// LethePluginLoader.mm - see LethePluginLoader.h

#import "ui/mac/LethePluginLoader.h"
#import "ui/mac/LethePreferences.h"

#include <sys/stat.h>
#include <unistd.h>

// Shared browser media scaler script. The plugin loader owns the shared
// WKUserContentController's remove/rebuild cycle, so it must restore this
// non-plugin script after clearing the old plugin scripts.
extern NSString* LetheMediaUpscalerScript(void);

NSString* const LethePluginsFolderChangedNotification =
    @"LethePluginsFolderChangedNotification";

@implementation LethePluginScript
@end

@implementation LethePluginLoader

+ (NSString*)pluginsFolder {
    NSString* root = [NSSearchPathForDirectoriesInDomains(
        NSApplicationSupportDirectory, NSUserDomainMask, YES).firstObject
        stringByAppendingPathComponent:@"Lethe"];
    NSString* folder = [root stringByAppendingPathComponent:@"plugins"];
    [[NSFileManager defaultManager] createDirectoryAtPath:folder
                              withIntermediateDirectories:YES
                                               attributes:nil error:nil];
    return folder;
}

+ (instancetype)shared {
    static LethePluginLoader* s; static dispatch_once_t once;
    dispatch_once(&once, ^{ s = [[LethePluginLoader alloc] init]; });
    return s;
}

// Manifest header: everything between ==LethePlugin== and ==/LethePlugin==
// in leading `//` comments. Unknown keys are ignored; missing keys fall
// back to the file name.
- (LethePluginScript*)parseFile:(NSString*)path {
    NSData* d = [NSData dataWithContentsOfFile:path];
    if (!d) return nil;
    NSString* src = [[NSString alloc] initWithData:d
                                          encoding:NSUTF8StringEncoding];
    if (!src.length) return nil;
    NSScanner* sc = [NSScanner scannerWithString:src];
    NSString* head = nil;
    if ([sc scanUpToString:@"==LethePlugin==" intoString:nil] &&
        [sc scanUpToString:@"==/LethePlugin==" intoString:&head]) {
        // head contains "==LethePlugin==\n// @name ...\n..."
    } else {
        return nil;  // no manifest at all: still a plugin, just unnamed
    }
    LethePluginScript* p = [LethePluginScript new];
    p.fileName = path.lastPathComponent;
    p.name = path.lastPathComponent.stringByDeletingPathExtension;
    p.pluginDescription = @"";
    p.matchHost = @"*";
    for (NSString* rawLine in [head componentsSeparatedByCharactersInSet:
                               [NSCharacterSet newlineCharacterSet]]) {
        NSString* line = rawLine;
        for (NSString* pre in @[@"//", @" ", @"\t"]) {
            line = [line stringByReplacingOccurrencesOfString:pre
                                                   withString:@""];
        }
        if (![line hasPrefix:@"@"] || [line containsString:@"=="]) continue;
        NSRange sep = [line rangeOfString:@" "];
        if (sep.location == NSNotFound) continue;
        NSString* key = [line substringToIndex:sep.location];
        NSString* val = [[line substringFromIndex:NSMaxRange(sep)]
            stringByTrimmingCharactersInSet:
                [NSCharacterSet whitespaceCharacterSet]];
        if ([key isEqualToString:@"@name"] && val.length) p.name = val;
        else if ([key isEqualToString:@"@description"]) p.pluginDescription = val;
        else if ([key isEqualToString:@"@match"] && val.length) p.matchHost = val;
    }
    return p;
}

- (NSArray<LethePluginScript*>*)scanPlugins {
    NSString* folder = [LethePluginLoader pluginsFolder];
    NSArray<NSString*>* files = [[NSFileManager defaultManager]
        contentsOfDirectoryAtPath:folder error:nil];
    NSMutableArray<LethePluginScript*>* out = [NSMutableArray array];
    NSMutableSet<NSString*>* disabled = [NSMutableSet setWithArray:
        [LethePreferences shared].disabledPlugins ?: @[]];
    for (NSString* f in [files sortedArrayUsingSelector:@selector(compare:)]) {
        if (![f.pathExtension isEqualToString:@"js"]) continue;
        NSString* path = [folder stringByAppendingPathComponent:f];

        // Script plugins execute with the full authority of the page's
        // JavaScript context. Treat the plugin directory as an integrity
        // boundary: never execute a symlink, a non-regular file, a file owned
        // by another account, or a file writable by group/others. Also cap
        // the manifest/script size so a malformed local file cannot force a
        // large allocation during startup.
        struct stat st;
        if (lstat(path.fileSystemRepresentation, &st) != 0 ||
            !S_ISREG(st.st_mode) || st.st_uid != getuid() ||
            (st.st_mode & (S_IWGRP | S_IWOTH)) != 0 ||
            st.st_size < 0 || static_cast<uint64_t>(st.st_size) > 1024u * 1024u) {
            continue;
        }

        LethePluginScript* p = [self parseFile:path];
        if (!p) continue;
        p.enabled = ![disabled containsObject:p.fileName];
        [out addObject:p];
    }
    return out;
}

- (void)installInto:(WKUserContentController*)ucc {
    // No other component adds user scripts, so removing all is exactly our
    // previous set. (WebKit has no per-script removal in this SDK.)
    [ucc removeAllUserScripts];
    WKUserScript* media = [[WKUserScript alloc]
        initWithSource:LetheMediaUpscalerScript()
          injectionTime:WKUserScriptInjectionTimeAtDocumentStart
       forMainFrameOnly:YES];
    [ucc addUserScript:media];
    for (LethePluginScript* p in [self scanPlugins]) {
        if (!p.enabled) continue;
        NSString* folder = [LethePluginLoader pluginsFolder];
        NSString* path = [folder stringByAppendingPathComponent:p.fileName];
        struct stat st;
        if (lstat(path.fileSystemRepresentation, &st) != 0 ||
            !S_ISREG(st.st_mode) || st.st_uid != getuid() ||
            (st.st_mode & (S_IWGRP | S_IWOTH)) != 0 ||
            st.st_size < 0 || static_cast<uint64_t>(st.st_size) > 1024u * 1024u) {
            continue;
        }
        NSData* d = [NSData dataWithContentsOfFile:path];
        if (!d) continue;
        // IIFE wrap: one plugin's top-level names never leak into another's
        // scope or the page's. document-start so plugins see every frame.
        // @match is enforced here (WKUserScript cannot filter by host):
        // a host-suffix check bails before any plugin code runs.
        NSMutableString* src = [NSMutableString stringWithString:@"(function(){\n"];
        if (![p.matchHost isEqualToString:@"*"] && p.matchHost.length) {
            static NSCharacterSet* kHostChars =
                [NSCharacterSet characterSetWithCharactersInString:
                    @"abcdefghijklmnopqrstuvwxyz0123456789.-"];
            NSString* host = [[[p.matchHost lowercaseString]
                componentsSeparatedByCharactersInSet:
                    [kHostChars invertedSet]]
                componentsJoinedByString:@""];
            [src appendFormat:
                @"var h=location.hostname;"
                @"if(!(h===\"%@\"||h.slice(-(%@+1))===\".%@\"))return;\n",
                host, @(host.length), host];
        }
        [src appendString:@"\n"];
        NSMutableData* wrapped = [NSMutableData dataWithData:
            [src dataUsingEncoding:NSUTF8StringEncoding]];
        [wrapped appendData:d];
        [wrapped appendData:
            [@"\n})();\n" dataUsingEncoding:NSUTF8StringEncoding]];
        WKUserScript* script = [[WKUserScript alloc]
            initWithSource:[[NSString alloc] initWithData:wrapped
                                                 encoding:NSUTF8StringEncoding]
             injectionTime:WKUserScriptInjectionTimeAtDocumentStart
           forMainFrameOnly:YES];
        [ucc addUserScript:script];
    }
}

@end
