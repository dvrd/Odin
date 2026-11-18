package test_core_compress

import "core:bytes"
import "core:compress/brotli"
import "core:testing"

// Real files from this repository: text and binary, from a few hundred bytes to 2 MiB.
Corpus_File :: struct {
	name: string,
	data: []u8,
	text: bool,
}

BROTLI_CORPUS := [?]Corpus_File {
	{name = "LICENSE", data = #load("../../../LICENSE"), text = true},
	{name = "tests/core/assets/XML/entities.html", data = #load("../assets/XML/entities.html"), text = true},
	{name = "tests/core/assets/I18N/nl_NL.po", data = #load("../assets/I18N/nl_NL.po"), text = true},
	{name = "tests/core/assets/I18N/mixed_context.mo", data = #load("../assets/I18N/mixed_context.mo"), text = false},
	{name = "core/unicode/tables.odin", data = #load("../../../core/unicode/tables.odin"), text = true},
	{name = "core/compress/brotli/dictionary.bin", data = #load("../../../core/compress/brotli/dictionary.bin"), text = false},
	{name = "tests/core/assets/UCD/UnicodeData.txt", data = #load("../assets/UCD/UnicodeData.txt"), text = true},
}

// Above this size Optimal is too slow for the test budget.
BROTLI_CORPUS_OPTIMAL_LIMIT :: 1 << 20

@(test)
brotli_corpus_round_trips_every_level :: proc(t: ^testing.T) {
	for file in BROTLI_CORPUS {
		for level in BROTLI_LEVELS {
			if level == .Optimal && len(file.data) > BROTLI_CORPUS_OPTIMAL_LIMIT {
				continue
			}

			packed, encode_error := brotli_encode(file.data, level)
			defer delete(packed)

			testing.expectf(t, encode_error == nil, "%s level %v: encode error %v", file.name, level, encode_error)

			plain, decode_error := brotli_decode(packed)
			defer delete(plain)

			testing.expectf(t, decode_error == nil, "%s level %v: decode error %v", file.name, level, decode_error)
			testing.expectf(t, bytes.equal(plain, file.data), "%s level %v did not round trip", file.name, level)

			if file.text && level >= .Default {
				testing.expectf(t, len(packed) < len(file.data), "%s level %v: %d bytes packed from %d", file.name, level, len(packed), len(file.data))
			}
		}
	}
}

@(test)
brotli_corpus_levels_stay_monotonic :: proc(t: ^testing.T) {
	data := BROTLI_CORPUS[len(BROTLI_CORPUS) - 1].data

	previous := max(int) / 2

	for level in BROTLI_LEVELS {
		if level == .Optimal {
			continue
		}

		packed, encode_error := brotli_encode(data, level)
		defer delete(packed)

		testing.expect_value(t, encode_error, nil)
		testing.expectf(t, len(packed) <= previous + previous / 50, "level %v grew to %d from %d", level, len(packed), previous)
		previous = len(packed)
	}
}
