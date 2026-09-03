#import <Foundation/Foundation.h>
#import <Metal/Metal.h>
#import <MetalFX/MetalFX.h>

#include "renderer/media_upscaler.h"

#include <cstring>

namespace {

id<MTLDevice> device() {
    static id<MTLDevice> d = MTLCreateSystemDefaultDevice();
    return d;
}

bool makeTexture(id<MTLDevice> d, NSUInteger width, NSUInteger height,
                 MTLTextureUsage usage, MTLStorageMode storageMode,
                 id<MTLTexture>* out) {
    MTLTextureDescriptor* desc = [MTLTextureDescriptor
        texture2DDescriptorWithPixelFormat:MTLPixelFormatRGBA8Unorm
                                      width:width height:height mipmapped:NO];
    desc.usage = usage;
    desc.storageMode = storageMode;
    *out = [d newTextureWithDescriptor:desc];
    return *out != nil;
}

} // namespace

extern "C" bool lethe_metalfx_available() {
    id<MTLDevice> d = device();
    return d != nil && [MTLFXSpatialScalerDescriptor supportsDevice:d];
}

extern "C" bool lethe_metalfx_upscale_rgba8(const uint8_t* src,
                                             size_t sw, size_t sh,
                                             uint8_t* dst,
                                             size_t dw, size_t dh) {
    if (!src || !dst || sw == 0 || sh == 0 || dw == 0 || dh == 0) return false;
    id<MTLDevice> d = device();
    if (!d || ![MTLFXSpatialScalerDescriptor supportsDevice:d]) return false;

    @autoreleasepool {
        MTLTextureUsage inputUsage = MTLTextureUsageShaderRead;
        MTLTextureUsage outputUsage = MTLTextureUsageShaderWrite | MTLTextureUsageShaderRead;
        id<MTLTexture> input = nil;
        id<MTLTexture> output = nil;
        // The CPU uploads the decoded RGBA frame through replaceRegion:, so
        // the input must be CPU-visible. MetalFX can sample it directly from
        // shared storage on Apple Silicon. Keep the scaler output private so
        // MetalFX can use the optimal GPU storage mode, then blit it to the
        // shared readback texture below.
        if (!makeTexture(d, sw, sh, inputUsage, MTLStorageModeShared, &input) ||
            !makeTexture(d, dw, dh, outputUsage, MTLStorageModePrivate, &output)) return false;

        [input replaceRegion:MTLRegionMake2D(0, 0, sw, sh)
                 mipmapLevel:0 withBytes:src bytesPerRow:sw * 4];

        MTLFXSpatialScalerDescriptor* desc = [MTLFXSpatialScalerDescriptor new];
        desc.inputWidth = sw;
        desc.inputHeight = sh;
        desc.outputWidth = dw;
        desc.outputHeight = dh;
        desc.colorTextureFormat = MTLPixelFormatRGBA8Unorm;
        desc.outputTextureFormat = MTLPixelFormatRGBA8Unorm;
        if ([desc respondsToSelector:@selector(colorProcessingMode)]) {
            desc.colorProcessingMode = MTLFXSpatialScalerColorProcessingModeLinear;
        }
        id<MTLFXSpatialScaler> scaler = [desc newSpatialScalerWithDevice:d];
        if (!scaler) return false;

        scaler.colorTexture = input;
        scaler.inputContentWidth = sw;
        scaler.inputContentHeight = sh;
        scaler.outputTexture = output;

        id<MTLCommandQueue> queue = [d newCommandQueue];
        id<MTLCommandBuffer> cb = [queue commandBuffer];
        [scaler encodeToCommandBuffer:cb];
        [cb commit];
        [cb waitUntilCompleted];
        if (cb.status != MTLCommandBufferStatusCompleted) return false;

        // Private output is copied through a temporary shared texture so the
        // C++ media API can consume a normal RGBA8 frame.
        MTLTextureDescriptor* readDesc = [MTLTextureDescriptor
            texture2DDescriptorWithPixelFormat:MTLPixelFormatRGBA8Unorm
                                          width:dw height:dh mipmapped:NO];
        readDesc.usage = MTLTextureUsageShaderRead;
        readDesc.storageMode = MTLStorageModeShared;
        id<MTLTexture> readable = [d newTextureWithDescriptor:readDesc];
        if (!readable) return false;
        id<MTLCommandBuffer> copyCB = [queue commandBuffer];
        id<MTLBlitCommandEncoder> blit = [copyCB blitCommandEncoder];
        [blit copyFromTexture:output toTexture:readable];
        [blit endEncoding];
        [copyCB commit];
        [copyCB waitUntilCompleted];
        if (copyCB.status != MTLCommandBufferStatusCompleted) return false;
        [readable getBytes:dst bytesPerRow:dw * 4
                  fromRegion:MTLRegionMake2D(0, 0, dw, dh) mipmapLevel:0];
        return true;
    }
}
