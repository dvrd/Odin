import unittest

from import_darwinkit import Package, apply_alias_fixes


class PixelBufferAliasTests(unittest.TestCase):
	def test_avfoundation_pixel_buffers_use_corevideo_pointer_type(self):
		pkg = Package("AVFoundation", {"AVFoundation.odin": [
			"package darwin_AVFoundation",
			'import NS "core:sys/darwin/Foundation"',
			"CVPixelBufferRef :: struct {}",
			"CVImageBufferRef :: struct {}",
		]})

		apply_alias_fixes(pkg)

		lines = pkg.files["AVFoundation.odin"]
		self.assertIn('import CV "vendor:darwin/CoreVideo"', lines)
		self.assertIn("CVPixelBufferRef :: CV.PixelBufferRef", lines)
		self.assertIn("CVImageBufferRef :: struct {}", lines)
		self.assertNotIn("CVPixelBufferRef :: struct {}", lines)


if __name__ == "__main__":
	unittest.main()
