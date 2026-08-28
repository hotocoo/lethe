// LetheDownloads.mm - downloads model + panel.
#import "ui/mac/LetheDownloads.h"

NSString* const LetheDownloadsDidChangeNotification = @"LetheDownloadsDidChangeNotification";

@implementation LetheDownloadItem
@end

@interface LetheDownloadsController () <NSTableViewDataSource, NSTableViewDelegate>
@property (nonatomic) NSWindow* panel;
@property (nonatomic) NSTableView* table;
@property (nonatomic) NSMutableArray<LetheDownloadItem*>* items;
@end

@implementation LetheDownloadsController

+ (instancetype)shared {
    static LetheDownloadsController* s; static dispatch_once_t once;
    dispatch_once(&once, ^{ s = [[LetheDownloadsController alloc] init]; });
    return s;
}

- (instancetype)init {
    if ((self = [super init])) {
        _items = [NSMutableArray array];
    }
    return self;
}

- (NSArray<LetheDownloadItem*>*)items { return [_items copy]; }

- (void)addItem:(LetheDownloadItem*)item {
    [_items insertObject:item atIndex:0];
    [self.table reloadData];
    [[NSNotificationCenter defaultCenter] postNotificationName:LetheDownloadsDidChangeNotification object:self];
}

- (void)updateItem:(LetheDownloadItem*)item {
    NSUInteger idx = [_items indexOfObject:item];
    if (idx != NSNotFound) {
        [self.table reloadDataForRowIndexes:[NSIndexSet indexSetWithIndex:idx]
                              columnIndexes:[NSIndexSet indexSetWithIndex:0]];
    }
    [[NSNotificationCenter defaultCenter] postNotificationName:LetheDownloadsDidChangeNotification object:self];
}

- (void)removeItem:(LetheDownloadItem*)item {
    [_items removeObject:item];
    [self.table reloadData];
    [[NSNotificationCenter defaultCenter] postNotificationName:LetheDownloadsDidChangeNotification object:self];
}

- (void)showPanel {
    if (self.panel) {
        [self.panel makeKeyAndOrderFront:nil];
        return;
    }
    NSWindow* win = [[NSWindow alloc] initWithContentRect:NSMakeRect(0, 0, 640, 360)
                                                styleMask:NSWindowStyleMaskTitled | NSWindowStyleMaskClosable | NSWindowStyleMaskMiniaturizable
                                                  backing:NSBackingStoreBuffered defer:NO];
    win.title = @"Downloads";
    self.panel = win;

    NSTableColumn* col = [[NSTableColumn alloc] initWithIdentifier:@"download"];
    col.title = @"File";
    col.width = 600;
    col.resizingMask = NSTableColumnAutoresizingMask;
    NSTableView* tv = [[NSTableView alloc] initWithFrame:win.contentView.bounds];
    tv.headerView = nil;
    [tv addTableColumn:col];
    tv.dataSource = self;
    tv.delegate = self;
    tv.rowHeight = 56;
    tv.target = self;
    tv.doubleAction = @selector(rowDoubleClicked:);
    tv.autoresizingMask = NSViewWidthSizable | NSViewHeightSizable;
    [tv setUsesAlternatingRowBackgroundColors:YES];
    [win.contentView addSubview:tv];
    self.table = tv;

    NSButton* reveal = [NSButton buttonWithTitle:@"Reveal in Finder"
                                       target:self action:@selector(revealSelected)];
    reveal.frame = NSMakeRect(20, 12, 140, 24);
    reveal.autoresizingMask = NSViewMinYMargin | NSViewMaxXMargin;
    [win.contentView addSubview:reveal];
    NSButton* clear = [NSButton buttonWithTitle:@"Clear finished"
                                     target:self action:@selector(clearFinished)];
    clear.frame = NSMakeRect(170, 12, 120, 24);
    clear.autoresizingMask = NSViewMinYMargin | NSViewMaxXMargin;
    [win.contentView addSubview:clear];

    [win center];
    [win makeKeyAndOrderFront:nil];
}

- (void)rowDoubleClicked:(id)sender { [self revealSelected]; }

- (void)revealSelected {
    NSInteger row = self.table.selectedRow;
    if (row < 0 || row >= (NSInteger)_items.count) return;
    LetheDownloadItem* it = _items[row];
    if (it.state == LetheDownloadStateFinished && it.destination) {
        [[NSWorkspace sharedWorkspace] activateFileViewerSelectingURLs:@[it.destination]];
    } else if (it.destination) {
        NSURL* parent = [it.destination URLByDeletingLastPathComponent];
        [[NSWorkspace sharedWorkspace] openURL:parent];
    }
}

- (void)clearFinished {
    NSMutableIndexSet* toRemove = [NSMutableIndexSet indexSet];
    for (NSUInteger i = 0; i < _items.count; i++) {
        if (_items[i].state == LetheDownloadStateFinished) [toRemove addIndex:i];
    }
    [_items removeObjectsAtIndexes:toRemove];
    [self.table reloadData];
}

#pragma mark - NSTableViewDataSource

- (NSInteger)numberOfRowsInTableView:(NSTableView*)tv { return (NSInteger)_items.count; }

- (NSView*)tableView:(NSTableView*)tv viewForTableColumn:(NSTableColumn*)col row:(NSInteger)row {
    LetheDownloadItem* it = _items[row];
    NSTableCellView* cell = [[NSTableCellView alloc] init];
    cell.frame = NSMakeRect(0, 0, col.width, 56);

    NSTextField* name = [NSTextField labelWithString:it.filename ?: @"(untitled)"];
    name.font = [NSFont systemFontOfSize:13 weight:NSFontWeightSemibold];
    name.frame = NSMakeRect(12, 32, col.width - 24, 18);
    [cell addSubview:name];

    NSString* status;
    if (it.state == LetheDownloadStateFinished) status = @"Done";
    else if (it.state == LetheDownloadStateFailed) status = it.errorMessage ?: @"Failed";
    else if (it.state == LetheDownloadStateCancelled) status = @"Cancelled";
    else if (it.bytesExpected > 0) {
        double pct = (double)it.bytesReceived / (double)it.bytesExpected * 100.0;
        status = [NSString stringWithFormat:@"%.0f%% - %@ / %@",
                  pct,
                  [NSByteCountFormatter stringFromByteCount:it.bytesReceived countStyle:NSByteCountFormatterCountStyleFile],
                  [NSByteCountFormatter stringFromByteCount:it.bytesExpected countStyle:NSByteCountFormatterCountStyleFile]];
    } else {
        status = [NSString stringWithFormat:@"%@ downloaded",
                  [NSByteCountFormatter stringFromByteCount:it.bytesReceived countStyle:NSByteCountFormatterCountStyleFile]];
    }
    NSTextField* st = [NSTextField labelWithString:status];
    st.font = [NSFont systemFontOfSize:11];
    st.textColor = [NSColor secondaryLabelColor];
    st.frame = NSMakeRect(12, 12, col.width - 24, 16);
    [cell addSubview:st];

    if (it.state == LetheDownloadStateRunning && it.bytesExpected > 0) {
        NSProgressIndicator* prog = [[NSProgressIndicator alloc] initWithFrame:NSMakeRect(12, 4, col.width - 24, 4)];
        prog.indeterminate = NO;
        prog.minValue = 0;
        prog.maxValue = 1;
        prog.doubleValue = (double)it.bytesReceived / (double)it.bytesExpected;
        [cell addSubview:prog];
    }
    return cell;
}
@end
