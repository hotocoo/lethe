// cef_render_handler.cc - see cef_render_handler.h
//
// We install a CefV8Handler on every renderer's global object: when the
// browser process sends a "lethe:eval" message, the renderer runs the
// JavaScript via the V8 context, stringifies the result, and replies
// with "lethe:eval-result". This is the canonical CEF way to evaluate
// JS in the renderer; the same context as the page, no extra round trips.

#include "app/cef_render_handler.h"

#import <Foundation/Foundation.h>

#include <cstring>
#include <iostream>
#include <sstream>
#include <vector>

#include "include/cef_browser.h"
#include "include/cef_frame.h"
#include "include/cef_process_message.h"
#include "include/cef_v8.h"

namespace {

// Script plugins ("everything is a plugin"). The .js files and their enable
// state live in the same folders the WebKit shell's plugin loader manages:
//   ~/Library/Application Support/Lethe/plugins/*.js
//   ~/Library/Application Support/Lethe/preferences.json (disabledPlugins)
// The renderer scans them once per process (file reads stay allowed under
// the inherited Seatbelt profile) and runs each enabled, matching plugin at
// context creation - CEF's document-start equivalent - IIFE-wrapped so
// plugins cannot see each other's variables.
struct ScriptPlugin {
    std::string fileName;
    std::string code;
    std::string matchHost;  // suffix match; empty or "*" = all sites
};

bool parseDisabledSet(NSString* prefsPath, std::vector<std::string>* out) {
    NSError* err = nil;
    NSData* d = [NSData dataWithContentsOfFile:prefsPath options:0 error:&err];
    if (!d) return false;
    id json = [NSJSONSerialization JSONObjectWithData:d options:0 error:&err];
    if (![json isKindOfClass:[NSDictionary class]]) return false;
    id arr = ((NSDictionary*)json)[@"disabledPlugins"];
    if (![arr isKindOfClass:[NSArray class]]) return false;
    for (id v in (NSArray*)arr) {
        if ([v isKindOfClass:[NSString class]]) {
            out->push_back([(NSString*)v UTF8String] ?: "");
        }
    }
    return true;
}

std::vector<ScriptPlugin> scanScriptPlugins() {
    std::vector<ScriptPlugin> plugins;
    @autoreleasepool {
        NSString* root = [NSHomeDirectory()
            stringByAppendingPathComponent:@"Library/Application Support/Lethe"];
        NSString* dir = [root stringByAppendingPathComponent:@"plugins"];
        // Disabled set: script plugins are stored by file name.
        std::vector<std::string> disabled;
        parseDisabledSet([root stringByAppendingPathComponent:@"preferences.json"],
                         &disabled);
        NSFileManager* fm = [NSFileManager defaultManager];
        NSArray* files = [fm contentsOfDirectoryAtPath:dir error:nil];
        for (NSString* f in files) {
            if (![f hasSuffix:@".js"]) continue;
            NSString* path = [dir stringByAppendingPathComponent:f];
            NSString* src = [NSString stringWithContentsOfFile:path
                                                  encoding:NSUTF8StringEncoding
                                                     error:nil];
            if (!src.length) continue;
            // Header: // @match host (optional; everything else is
            // informational for the Plugins pane, which lists WebKit-side).
            ScriptPlugin p;
            p.fileName = [f UTF8String] ?: "";
            for (NSString* line in [src componentsSeparatedByString:@"\n"]) {
                NSString* t = [line stringByTrimmingCharactersInSet:
                    [NSCharacterSet whitespaceCharacterSet]];
                if ([t hasPrefix:@"// @match"]) {
                    NSString* m = [t substringFromIndex:8];
                    p.matchHost = [[m stringByTrimmingCharactersInSet:
                        [NSCharacterSet whitespaceCharacterSet]] UTF8String] ?: "";
                }
            }
            if (p.matchHost.empty()) p.matchHost = "*";
            bool on = true;
            for (const auto& d : disabled) {
                if (d == p.fileName) { on = false; break; }
            }
            if (on) p.code = [src UTF8String] ?: "";
            plugins.push_back(std::move(p));
        }
    }
    return plugins;
}

bool hostMatches(const std::string& match, const std::string& host) {
    if (match.empty() || match == "*") return true;
    if (host.empty()) return false;
    // Suffix match on dot boundaries, same semantics as the WebKit loader.
    if (host.size() >= match.size() &&
        host.compare(host.size() - match.size(), match.size(), match) == 0) {
        return host.size() == match.size() ||
               host[host.size() - match.size() - 1] == '.';
    }
    return false;
}

// Wrap a JS value into a CefV8Value. For the bench harness we only need
// string / number / bool / object-as-JSON, which covers every metrics
// expression used by tools/bench/bench.mjs.
CefRefPtr<CefV8Value> toV8(CefRefPtr<CefV8Value> v) { return v; }
std::string stringify(CefRefPtr<CefV8Value> v, int depth = 0) {
    if (depth > 8 || !v) return "null";
    if (v->IsString())  return v->GetStringValue().ToString();
    if (v->IsBool())    return v->GetBoolValue() ? "true" : "false";
    if (v->IsInt())     return std::to_string(v->GetIntValue());
    if (v->IsDouble())  { std::ostringstream o; o << v->GetDoubleValue(); return o.str(); }
    if (v->IsNull())    return "null";
    if (v->IsUndefined()) return "undefined";
    if (v->IsArray()) {
        std::ostringstream o; o << "[";
        int n = v->GetArrayLength();
        for (int i = 0; i < n; i++) {
            if (i) o << ",";
            o << stringify(v->GetValue(i), depth + 1);
        }
        o << "]";
        return o.str();
    }
    if (v->IsObject()) {
        std::ostringstream o; o << "{";
        std::vector<CefString> keys;
        v->GetKeys(keys);
        for (size_t i = 0; i < keys.size(); i++) {
            if (i) o << ",";
            o << "\"" << keys[i].ToString() << "\":";
            o << stringify(v->GetValue(keys[i]), depth + 1);
        }
        o << "}";
        return o.str();
    }
    return "null";
}

class LetheEvalHandler : public CefV8Handler {
 public:
    bool Execute(const CefString& name,
                 CefRefPtr<CefV8Value> /*object*/,
                 const CefV8ValueList& arguments,
                 CefRefPtr<CefV8Value>& retval,
                 CefString& exception) override {
        if (name == "__letheEval" && arguments.size() >= 1) {
            // Wrap as `(function(){ return <code>; })()` and evaluate.
            CefRefPtr<CefV8Context> ctx = CefV8Context::GetCurrentContext();
            if (!ctx) { exception = "no v8 context"; return true; }
            CefString code = arguments[0]->GetStringValue();
            CefRefPtr<CefV8Value> r;
            CefRefPtr<CefV8Exception> ex;
            bool ok = ctx->Eval(code, "<lethe-eval>", 0, r, ex);
            if (!ok) {
                exception = ex.get() ? ex->GetMessage().ToString()
                                     : "eval failed";
                retval = CefV8Value::CreateString("");
                return true;
            }
            retval = CefV8Value::CreateString(stringify(r));
            return true;
        }
        return false;
    }
    IMPLEMENT_REFCOUNTING(LetheEvalHandler);
};

CefRefPtr<LetheEvalHandler> g_handler;

}  // namespace

void LetheCefRenderHandler::OnContextCreated(CefRefPtr<CefBrowser> browser,
                                             CefRefPtr<CefFrame> frame,
                                             CefRefPtr<CefV8Context> context) {
    (void)browser; (void)frame;
    if (!context) return;
    if (!g_handler) g_handler = new LetheEvalHandler();
    context->Enter();
    CefRefPtr<CefV8Value> global = context->GetGlobal();
    CefRefPtr<CefV8Value> fn = CefV8Value::CreateFunction("__letheEval", g_handler);
    global->SetValue("__letheEval", fn, V8_PROPERTY_ATTRIBUTE_READONLY);
    context->Exit();
    // Script plugins: run at context creation (document start), main
    // frames only, IIFE-wrapped so plugins cannot see each other's vars.
    static const std::vector<ScriptPlugin> plugins = scanScriptPlugins();
    if (plugins.empty() || !frame || !frame->IsMain()) return;
    const std::string url = frame->GetURL().ToString();
    const std::string scheme = url.substr(0, url.find(':'));
    if (scheme != "http" && scheme != "https") return;
    size_t hostStart = url.find("://");
    hostStart = hostStart == std::string::npos ? 0 : hostStart + 3;
    size_t hostEnd = url.find('/', hostStart);
    if (hostEnd == std::string::npos) hostEnd = url.size();
    size_t port = url.find(':', hostStart);
    if (port != std::string::npos && port < hostEnd) hostEnd = port;
    const std::string host = url.substr(hostStart, hostEnd - hostStart);
    for (const auto& p : plugins) {
        if (!hostMatches(p.matchHost, host)) continue;
        context->Enter();
        CefRefPtr<CefV8Value> r;
        CefRefPtr<CefV8Exception> ex;
        context->Eval("(function(){\n" + p.code + "\n})();",
                      "<lethe-plugin:" + p.fileName + ">", 0, r, ex);
        context->Exit();
    }
}

void LetheCefRenderHandler::OnContextReleased(CefRefPtr<CefBrowser> browser,
                                              CefRefPtr<CefFrame> frame,
                                              CefRefPtr<CefV8Context> context) {
    (void)browser; (void)frame; (void)context;
}

bool LetheCefRenderHandler::OnProcessMessageReceived(
    CefRefPtr<CefBrowser> browser,
    CefRefPtr<CefFrame> frame,
    CefProcessId source_process,
    CefRefPtr<CefProcessMessage> message) {
    (void)browser; (void)source_process;
    if (!message) return false;
    const std::string& name = message->GetName();
    if (name != "lethe:eval") return false;
    CefRefPtr<CefListValue> args = message->GetArgumentList();
    if (!args || args->GetSize() < 2) return true;
    CefString code = args->GetString(0);
    CefString reqId = args->GetString(1);
    CefRefPtr<CefV8Context> ctx = frame ? frame->GetV8Context() : nullptr;
    std::cerr << "[render] lethe:eval reqId=" << reqId.ToString()
              << " ctx=" << (ctx ? "yes" : "NO") << std::endl;
    CefString result;
    if (ctx) {
        ctx->Enter();
        CefRefPtr<CefV8Value> r;
        CefRefPtr<CefV8Exception> ex;
        CefString wrapped = "(function(){try{return (" +
            code.ToString() + ");}catch(e){return {__letheError: e.message || String(e)};}})()";
        if (ctx->Eval(wrapped, "<lethe-eval>", 0, r, ex) && r) {
            result = stringify(r);
        } else {
            result = std::string("{\"__letheError\":\"") +
                     (ex ? ex->GetMessage().ToString() : "eval failed") + "\"}";
        }
        ctx->Exit();
    }
    CefRefPtr<CefProcessMessage> reply =
        CefProcessMessage::Create("lethe:eval-result");
    reply->GetArgumentList()->SetString(0, result);
    reply->GetArgumentList()->SetString(1, reqId);
    frame->SendProcessMessage(PID_BROWSER, reply);
    return true;
}
