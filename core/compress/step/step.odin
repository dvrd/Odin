/*
Step-driven decoding for callers that cannot block or allocate: an event loop
task that gets its input a packet at a time.

A decoder here is a fixed-size value. Each step is given an input slice and an
output slice, uses what it can of both within a work budget, and returns; it
keeps neither slice. `core:compress/deflate` and the other codecs of
`core:compress` pull their input through a blocking reader and are the simpler
choice when the whole input is already in memory.
*/
package compress_step

// A step retains no input or output slices. Bytes produced before Done are
// provisional: a later trailer or framing error can invalidate the stream.
Decode_Status :: enum { Need_Input, Need_Output, Progress, Done }
Decode_Error :: enum {
	None,
	Invalid_State,
	Invalid_Config,
	Overlapping_Buffers,
	Malformed,
	Truncated,
	Checksum_Mismatch,
	Size_Mismatch,
	Encoded_Limit,
	Decoded_Limit,
	Metadata_Limit,
	Member_Limit,
	Trailing_Data,
}
Decode_Result :: struct {
	consumed, produced, work: int,
	status: Decode_Status,
	err: Decode_Error,
}

// One work unit is a bounded parser action, symbol, output byte, or Huffman
// table construction phase (at most two tables of at most 288 symbols each).
// No step accepts an unbounded work budget.
DECODE_MAX_WORK :: 65536

// Empty slices never overlap. Neither buffer is retained by a decoder.
decode_buffers_overlap :: proc(input, output: []u8) -> bool {
	if len(input) == 0 || len(output) == 0 { return false }
	a, b := uintptr(raw_data(input)), uintptr(raw_data(output))
	if a <= b { return b-a < uintptr(len(input)) }
	return a-b < uintptr(len(output))
}
