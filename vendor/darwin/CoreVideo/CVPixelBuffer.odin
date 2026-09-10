package CoreVideo

import NS "core:sys/darwin/Foundation"
import MTL "vendor:darwin/Metal"

PixelBufferRef :: distinct rawptr
MetalTextureCacheRef :: distinct rawptr
MetalTextureRef :: distinct rawptr
PixelFormatType_32BGRA :: 1111970369

foreign import CoreVideo "system:CoreVideo.framework"

@(link_prefix="CV")
foreign CoreVideo {
	PixelBufferCreate :: proc "c"(
		allocator: rawptr,
		width, height: NS.UInteger,
		pixel_format: u32,
		attributes: ^NS.Dictionary,
		pixel_buffer_out: ^PixelBufferRef,
	) -> Return ---
	BufferRelease :: proc "c"(buffer: rawptr) ---
	MetalTextureCacheCreate :: proc "c"(
		allocator: rawptr,
		cache_attributes: ^NS.Dictionary,
		metal_device: ^MTL.Device,
		texture_attributes: ^NS.Dictionary,
		cache_out: ^MetalTextureCacheRef,
	) -> Return ---
	MetalTextureCacheCreateTextureFromImage :: proc "c"(
		allocator: rawptr,
		texture_cache: MetalTextureCacheRef,
		source_image: PixelBufferRef,
		texture_attributes: ^NS.Dictionary,
		pixel_format: MTL.PixelFormat,
		width, height, plane_index: NS.UInteger,
		texture_out: ^MetalTextureRef,
	) -> Return ---
	MetalTextureGetTexture :: proc "c"(image: MetalTextureRef) -> ^MTL.Texture ---
	MetalTextureCacheFlush :: proc "c"(texture_cache: MetalTextureCacheRef, options: u64) ---

	@(link_name="kCVPixelBufferMetalCompatibilityKey") kCVPixelBufferMetalCompatibilityKey: ^NS.String
	@(link_name="kCVPixelBufferIOSurfacePropertiesKey") kCVPixelBufferIOSurfacePropertiesKey: ^NS.String
}
