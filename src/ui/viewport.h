#ifndef LETHE_UI_VIEWPORT_H
#define LETHE_UI_VIEWPORT_H

#include <gtk/gtk.h>
#include <string>
#include <functional>
#include "core/engine.h"
#include "renderer/html_view.h"

namespace lethe {

class Viewport {
public:
    Viewport(Engine* engine);
    ~Viewport();
    
    GtkWidget* create();
    void loadURL(const std::string& url);
    void stop();
    void reload();
    void showContent(const std::string& content, const std::string& mimeType = "text/html");
    void showError(const std::string& error);
    
    GtkWidget* getWidget() { return webView_; }

private:
    // GTK draw callbacks are C function pointers: the renderer lives at
    // namespace scope and reaches private state as a friend (viewport.cc).
    friend gboolean onViewportDraw(GtkWidget* widget, cairo_t* cr,
                                   gpointer data);

    Engine* engine_;
    GtkWidget* webView_;
    std::string currentUrl_;
    bool isLoading_;
    std::vector<lethe::HtmlBlock> blocks_;
    std::string errorText_;
};

} // namespace lethe

#endif // LETHE_UI_VIEWPORT_H
