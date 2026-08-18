#ifndef LETHE_UI_VIEWPORT_H
#define LETHE_UI_VIEWPORT_H

#include <gtk/gtk.h>
#include <string>
#include <functional>
#include "core/engine.h"

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
    bool onDraw(GtkWidget* widget, cairo_t* cr, gpointer data);
    
    Engine* engine_;
    GtkWidget* webView_;
    std::string currentUrl_;
    bool isLoading_;
};

} // namespace lethe

#endif // LETHE_UI_VIEWPORT_H
