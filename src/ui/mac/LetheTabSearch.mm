// LetheTabSearch.mm - panel that lists open tabs filtered by a search field.
#import "ui/mac/LetheTabSearch.h"
#import "ui/mac/LetheShell.h"
#import <AppKit/AppKit.h>

@interface LetheTabSearch () <NSTableViewDataSource, NSTableViewDelegate, NSSearchFieldDelegate>
@property (nonatomic) NSWindow* panel;
@property (nonatomic) NSSearchField* searchField;
@property (nonatomic) NSTableView* table;
@property (nonatomic) NSMutableArray<BrowserWindowController*>* matches;
@end

@implementation LetheTabSearch

+ (instancetype)shared {
    static LetheTabSearch* s; static dispatch_once_t once;
    dispatch_once(&once, ^{ s = [[LetheTabSearch alloc] init]; });
    return s;
}

- (void)show {
    if (!self.panel) [self buildPanel];
    [self refresh];
    [self.panel makeKeyAndOrderFront:nil];
    [self.searchField becomeFirstResponder];
}

- (void)buildPanel {
    NSWindow* win = [[NSWindow alloc] initWithContentRect:NSMakeRect(0, 0, 520, 360)
                                                styleMask:NSWindowStyleMaskTitled | NSWindowStyleMaskClosable | NSWindowStyleMaskResizable
                                                  backing:NSBackingStoreBuffered defer:NO];
    win.title = @"Search Tabs";
    self.panel = win;
    NSView* v = win.contentView;

    NSSearchField* sf = [[NSSearchField alloc] initWithFrame:NSMakeRect(0, 326, 520, 32)];
    sf.placeholderString = @"Filter open tabs by title or URL...";
    sf.delegate = self;
    sf.autoresizingMask = NSViewWidthSizable | NSViewMinYMargin;
    [v addSubview:sf];
    self.searchField = sf;

    NSScrollView* sv = [[NSScrollView alloc] initWithFrame:NSMakeRect(0, 0, 520, 326)];
    sv.hasVerticalScroller = YES;
    sv.autoresizingMask = NSViewWidthSizable | NSViewHeightSizable;
    NSTableView* tv = [[NSTableView alloc] initWithFrame:sv.bounds];
    tv.headerView = nil;
    NSTableColumn* col = [[NSTableColumn alloc] initWithIdentifier:@"t"];
    col.title = @"Tab";
    col.width = 504;
    col.resizingMask = NSTableColumnAutoresizingMask;
    [tv addTableColumn:col];
    tv.dataSource = self;
    tv.delegate = self;
    tv.target = self;
    tv.doubleAction = @selector(activateSelected:);
    tv.rowHeight = 36;
    [sv setDocumentView:tv];
    [v addSubview:sv];
    self.table = tv;

    [win center];
    [win setFrameAutosaveName:@"LetheTabSearch"];
}

- (void)refresh {
    NSString* q = self.searchField.stringValue.lowercaseString;
    self.matches = [NSMutableArray array];
    for (BrowserWindowController* c in [(LetheAppDelegate*)[NSApp delegate] controllers]) {
        NSString* url = c.webView.URL.absoluteString ?: @"";
        NSString* title = c.webView.title ?: @"";
        if (q.length == 0
            || [url.lowercaseString containsString:q]
            || [title.lowercaseString containsString:q]) {
            [self.matches addObject:c];
        }
    }
    [self.table reloadData];
    if (self.matches.count) [self.table selectRowIndexes:[NSIndexSet indexSetWithIndex:0] byExtendingSelection:NO];
}

- (void)controlTextDidChange:(NSNotification*)note {
    if (note.object == self.searchField) [self refresh];
}

- (void)activateSelected:(id)sender {
    NSInteger row = self.table.selectedRow;
    if (row < 0 || row >= (NSInteger)self.matches.count) return;
    BrowserWindowController* c = self.matches[row];
    [c.window makeKeyAndOrderFront:nil];
    [self.panel orderOut:nil];
}

// Return / Escape on the search field are handled by the
// NSSearchFieldDelegate (controlTextDidEndEditing fires on Return;
// cancelOperation: fires on Escape, which the BrowserWindowController
// delegate already implements on the address field). Return on the
// table itself activates the selection via doubleAction.

#pragma mark - NSTableViewDataSource

- (NSInteger)numberOfRowsInTableView:(NSTableView*)tv { return (NSInteger)self.matches.count; }

- (NSView*)tableView:(NSTableView*)tv viewForTableColumn:(NSTableColumn*)col row:(NSInteger)row {
    BrowserWindowController* c = self.matches[row];
    NSTableCellView* cell = [[NSTableCellView alloc] init];
    cell.frame = NSMakeRect(0, 0, 504, 36);
    NSTextField* t = [NSTextField labelWithString:c.webView.title.length ? c.webView.title : @"(untitled)"];
    t.font = [NSFont systemFontOfSize:13 weight:NSFontWeightSemibold];
    t.frame = NSMakeRect(8, 16, 488, 16);
    [cell addSubview:t];
    NSTextField* u = [NSTextField labelWithString:c.webView.URL.absoluteString ?: @""];
    u.font = [NSFont systemFontOfSize:11];
    u.textColor = [NSColor secondaryLabelColor];
    u.frame = NSMakeRect(8, 2, 488, 14);
    [cell addSubview:u];
    return cell;
}
@end
