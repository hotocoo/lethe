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

// MetalFX resource creation is expensive enough to be visible when this
// path is used for video. Reuse the complete scaler pipeline for a stable
// source/output size instead of allocating textures, a queue and a scaler
// for every decoded frame. Keep the cache thread-local: the native renderer
// API can be called from more than one media worker, and sharing Metal
// resources without synchronization would introduce a data race while a
// mutex would serialize otherwise independent GPU work.
struct SpatialScalerCache {
    NSUInteger sw = 0;
    NSUInteger sh = 0;
    NSUInteger dw = 0;
    NSUInteger dh = 0;
    id<MTLTexture> input = nil;
    id<MTLTexture> output = nil;
    id<MTLTexture> readable = nil;
    id<MTLCommandQueue> queue = nil;
    id<MTLFXSpatialScaler> scaler = nil;
};

SpatialScalerCache& cache() {
    thread_local SpatialScalerCache c;
    return c;
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
        SpatialScalerCache& c = cache();
        if (c.sw != sw || c.sh != sh || c.dw != dw || c.dh != dh ||
            !c.input || !c.output || !c.readable || !c.queue || !c.scaler) {
            c = SpatialScalerCache{};

            // The CPU uploads the decoded RGBA frame through replaceRegion:,
            // so the input must be CPU-visible. Keep the scaler output private
            // for optimal GPU access, then blit it to the shared readback
            // texture required by the C++ RGBA API.
            if (!makeTexture(d, sw, sh, MTLTextureUsageShaderRead,
                             MTLStorageModeShared, &c.input) ||
                !makeTexture(d, dw, dh,
                             MTLTextureUsageShaderWrite | MTLTextureUsageShaderRead,
                             MTLStorageModePrivate, &c.output)) return false;

            MTLTextureDescriptor* readDesc = [MTLTextureDescriptor
                texture2DDescriptorWithPixelFormat:MTLPixelFormatRGBA8Unorm
                                              width:dw height:dh mipmapped:NO];
            readDesc.usage = MTLTextureUsageShaderRead;
            readDesc.storageMode = MTLStorageModeShared;
            c.readable = [d newTextureWithDescriptor:readDesc];
            c.queue = [d newCommandQueue];
            if (!c.readable || !c.queue) return false;

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
            c.scaler = [desc newSpatialScalerWithDevice:d];
            if (!c.scaler) return false;
            c.sw = sw; c.sh = sh; c.dw = dw; c.dh = dh;
            c.scaler.colorTexture = c.input;
            c.scaler.inputContentWidth = sw;
            c.scaler.inputContentHeight = sh;
            c.scaler.outputTexture = c.output;
        }

        [c.input replaceRegion:MTLRegionMake2D(0, 0, sw, sh)
                   mipmapLevel:0 withBytes:src bytesPerRow:sw * 4];

        // Keep the scaler and readback in one command buffer. The old path
        // submitted and waited twice per frame, forcing a second CPU/GPU
        // synchronization point. One submission preserves the synchronous
        // API contract while removing that avoidable round-trip.
        id<MTLCommandBuffer> cb = [c.queue commandBuffer];
        [c.scaler encodeToCommandBuffer:cb];
        id<MTLBlitCommandEncoder> blit = [cb blitCommandEncoder];
        [blit copyFromTexture:c.output toTexture:c.readable];
        [blit endEncoding];
        [cb commit];
        [cb waitUntilCompleted];
        if (cb.status != MTLCommandBufferStatusCompleted) return false;
        [c.readable getBytes:dst bytesPerRow:dw * 4
                  fromRegion:MTLRegionMake2D(0, 0, dw, dh) mipmapLevel:0];
        return true;
    }
}
