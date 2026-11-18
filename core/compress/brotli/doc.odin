/*
`Brotli` (RFC 7932) compression and decompression of data held in memory.

Example:
	package main

	import "core:bytes"
	import "core:compress/brotli"
	import "core:fmt"

	main :: proc() {
		INPUT := "Brotli packs repeated text such as Brotli packs repeated text well."

		packed: [dynamic]u8
		defer delete(packed)

		compress_err := brotli.compress(&packed, transmute([]u8)INPUT, .Default)

		if compress_err != nil {
			fmt.printf("\nCompress error: %v\n", compress_err)
			return
		}

		unpacked: [dynamic]u8
		defer delete(unpacked)

		decompress_err := brotli.decompress(&unpacked, packed[:], expected_output_size = len(INPUT))

		if decompress_err != nil {
			fmt.printf("\nDecompress error: %v\n", decompress_err)
			return
		}

		fmt.printf("Input: %v bytes, packed: %v bytes, unpacked: %v bytes\n", len(INPUT), len(packed), len(unpacked))
		assert(bytes.equal(unpacked[:], transmute([]u8)INPUT))
	}
*/
package compress_brotli

/*
	Copyright 2021 Jeroen van Rijn <nom@duclavier.com>.
	Made available under Odin's license.

	List of contributors:
		Jeroen van Rijn: Initial implementation.

	Brotli decoder and encoder. `brotli.decompress` decodes, `brotli.compress`
	encodes, and `brotli.Level` selects the speed/ratio trade-off of the encoder.
*/
