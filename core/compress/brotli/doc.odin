/*
`Brotli` (RFC 7932) compression and decompression of data held in memory.

Example:
	package main

	import "core:bytes"
	import "core:compress/brotli"
	import "core:fmt"

	main :: proc() {
		INPUT := "Brotli packs repeated text such as Brotli packs repeated text well."

		packed, encode_err := brotli.encode(transmute([]u8)INPUT, .Default)
		defer delete(packed)

		if encode_err != nil {
			fmt.printf("\nEncode error: %v\n", encode_err)
			return
		}

		buf: bytes.Buffer
		defer bytes.buffer_destroy(&buf)

		decode_err := brotli.load(packed, &buf, expected_output_size = len(INPUT))

		if decode_err != nil {
			fmt.printf("\nDecode error: %v\n", decode_err)
			return
		}

		fmt.printf("Input: %v bytes, packed: %v bytes, unpacked: %v bytes\n", len(INPUT), len(packed), len(buf.buf))
		assert(bytes.equal(buf.buf[:], transmute([]u8)INPUT))
	}
*/
package compress_brotli

/*
	Copyright 2021 Jeroen van Rijn <nom@duclavier.com>.
	Made available under Odin's license.

	List of contributors:
		Jeroen van Rijn: Initial implementation.

	Brotli decoder and encoder. `brotli.load` decodes, `brotli.encode` encodes,
	and `brotli.Level` selects the speed/ratio trade-off of the encoder.
*/
