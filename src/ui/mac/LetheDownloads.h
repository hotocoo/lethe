// LetheDownloads.h - downloads model + panel window controller.
#import <Foundation/Foundation.h>
#import <AppKit/AppKit.h>

NS_ASSUME_NONNULL_BEGIN

typedef NS_ENUM(NSInteger, LetheDownloadState) {
    LetheDownloadStateRunning,
    LetheDownloadStateFinished,
    LetheDownloadStateFailed,
    LetheDownloadStateCancelled,
};

@interface LetheDownloadItem : NSObject
@property (nonatomic, copy) NSString* filename;
@property (nonatomic, copy) NSURL* destination;
@property (nonatomic, copy, nullable) NSString* sourceURL;
@property (nonatomic) int64_t bytesReceived;
@property (nonatomic) int64_t bytesExpected;   // -1 if unknown
@property (nonatomic) LetheDownloadState state;
@property (nonatomic, copy, nullable) NSString* errorMessage;
@end

extern NSString* const LetheDownloadsDidChangeNotification;

@interface LetheDownloadsController : NSObject
+ (instancetype)shared;
- (NSArray<LetheDownloadItem*>*)items;
- (void)addItem:(LetheDownloadItem*)item;
- (void)updateItem:(LetheDownloadItem*)item;
- (void)removeItem:(LetheDownloadItem*)item;
- (void)showPanel;
@end

NS_ASSUME_NONNULL_END
