#include "viewport.h"
#include <iostream>
#include <cstring>

namespace lethe {

Viewport::Viewport(Engine* engine) : engine_(engine), webView_(nullptr), 
                                     currentUrl_(""), isLoading_(false) {
}

Viewport::~Viewport() {
}

GtkWidget* Viewport::create() {
    // Create drawing area for web content
    webView_ = gtk_drawing_area_new();
    gtk_widget_set_hexpand(webView_, TRUE);
    gtk_widget_set_vexpand(webView_, TRUE);
    
    // Connect draw signal
    g_signal_connect(webView_, "draw", G_CALLBACK(onDraw), this);
    
    return webView_;
}

void Viewport::loadURL(const std::string& url) {
    if (!engine_ || !engine_->tabManager() || !engine_->httpClient()) return;
    
    currentUrl_ = url;
    isLoading_ = true;
    
    int activeTab = engine_->tabManager()->getActiveTab();
    engine_->tabManager()->navigate(activeTab, url);
    engine_->tabManager()->setTabLoading(activeTab, true);
    
    // Add to history
    engine_->history()->addEntry(url);
    
    // Send HTTP request
    HttpRequest req;
    req.url = url;
    req.method = HttpMethod::GET;
    
    HttpResponse resp = engine_->httpClient()->sendRequest(req);
    
    if (resp.success && resp.statusCode == 200) {
        std::string content(resp.body.begin(), resp.body.end());
        showContent(content, "text/html");
    } else {
        showError(resp.error.empty() ? "Failed to load page" : resp.error);
    }
    
    isLoading_ = false;
    engine_->tabManager()->setTabLoading(activeTab, false);
    
    // Redraw
    gtk_widget_queue_draw(webView_);
}

void Viewport::stop() {
    isLoading_ = false;
}

void Viewport::reload() {
    if (!currentUrl_.empty()) {
        loadURL(currentUrl_);
    }
}

void Viewport::showContent(const std::string& content, const std::string& mimeType) {
    // TODO: Parse and render HTML content
    // For now, just store and redraw
    gtk_widget_queue_draw(webView_);
}

void Viewport::showError(const std::string& error) {
    // TODO: Display error page
    std::cout << "[lethe] Error: " << error << std::endl;
    gtk_widget_queue_draw(webView_);
}

bool Viewport::onDraw(GtkWidget* widget, cairo_t* cr, gpointer data) {
    Viewport* self = static_cast<Viewport*>(data);
    
    // Clear background
    cairo_set_source_rgb(cr, 1.0, 1.0, 1.0);
    cairo_paint(cr);
    
    if (self->isLoading_) {
        // Show loading indicator
        cairo_set_source_rgb(cr, 0.0, 0.0, 0.0);
        cairo_select_font_face(cr, CAIRO_FONT_FAMILY_MONO, CAIRO_FONT_SLANT_NORMAL, CAIRO_FONT_WEIGHT_NORMAL);
        cairo_set_font_size(cr, 16);
        cairo_move_to(cr, 100, 100);
        cairo_show_text(cr, "Loading...");
        cairo_stroke(cr);
    } else if (!self->currentUrl_.empty()) {
        // Show URL for now (placeholder for actual content rendering)
        cairo_set_source_rgb(cr, 0.0, 0.0, 0.0);
        cairo_select_font_face(cr, CAIRO_FONT_FAMILY_MONO, CAIRO_FONT_SLANT_NORMAL, CAIRO_FONT_WEIGHT_NORMAL);
        cairo_set_font_size(cr, 12);
        cairo_move_to(cr, 10, 10);
        cairo_show_text(cr, "URL: ");
        cairo_show_text(cr, self->currentUrl_.c_str());
        cairo_stroke(cr);
        
        // TODO: Render actual web content here
        cairo_move_to(cr, 10, 30);
        cairo_show_text(cr, "Content rendering not yet implemented");
        cairo_stroke(cr);
    } else {
        // Show new tab page
        cairo_set_source_rgb(cr, 0.0, 0.0, 0.0);
        cairo_select_font_face(cr, CAIRO_FONT_FAMILY_SANS, CAIRO_FONT_SLANT_NORMAL, CAIRO_FONT_WEIGHT_BOLD);
        cairo_set_font_size(cr, 24);
        cairo_move_to(cr, 100, 100);
        cairo_show_text(cr, "Lethe Browser");
        cairo_stroke(cr);
        
        cairo_set_font_size(cr, 14);
        cairo_move_to(cr, 100, 130);
        cairo_show_text(cr, "Enter a URL to begin browsing");
        cairo_stroke(cr);
    }
    
    return TRUE;
}

} // namespace lethe
