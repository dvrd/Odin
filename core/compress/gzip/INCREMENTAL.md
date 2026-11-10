# Incremental gzip decoding

`decoder_init(&decoder)` selects encoded and decoded ceilings of 64 MiB, an
8192-byte header ceiling per member, and one member. Supply a `Config` to choose
explicit limits. An explicit zero decoded ceiling permits empty members. Header
ceilings must be 10 through 1048576 bytes; member ceilings must be 1 through 1024.
An explicit `Config{}` is invalid. Limits never come from the untrusted ISIZE.

The caller owns `Decoder`, including its fixed 32768-byte history and bounded
Huffman/parser storage. Allocate it through the caller's bounded allocator when
heap storage is needed. Initialization and stepping allocate nothing. There is
no destructor. Initialize again to reset either a completed or failed decoder;
do not copy or concurrently access an active decoder.

```
result := gzip.decoder_step(&decoder, input, output, final_input, work_limit)
```

`consumed` advances input; `produced` advances output. Both slices are borrowed
only for the call. Input and output may not overlap; overlap and invalid arguments
are rejected before state or output changes. The caller must also keep decoder
storage disjoint from both slices. `Need_Input` requests more encoded bytes,
`Need_Output` requests output capacity, and `Progress` yields at the work budget.
Continue from the unconsumed suffix, including when there was no byte progress.
The work budget must be 1 through 65536. `result.work` never exceeds it.

A work unit is one bounded parsing action, code bit, emitted byte, repeat-length
expansion (at most 138 entries), or Huffman-table construction phase. A phase
builds at most two existing tables, each with at most 288 symbols, 16 code lengths
and 512 fast entries. This is a deterministic operation bound, not elapsed time.
No operation scans a caller-sized slice without charging individual work units.
CRC updates process only bytes charged to these operations.

`final_input=true` means the supplied slice contains the complete remainder of
the encoded entity. It does not mean the end of a network packet. After a yield,
resubmit its remaining suffix with `final_input=true`. Once declared, final input
cannot be withdrawn. `Done` requires final input, complete member trailers and
validated CRC32 and ISIZE. Calling a completed decoder with empty final input is
idempotent; further data fails. Encoding errors are terminal and sticky until
initialization. Invalid call arguments do not poison an otherwise valid decoder.

Every encoded byte and every emitted decoded byte is checked against aggregate
ceilings before consumption/publication. Limits include all concatenated members
and gzip metadata. The header ceiling includes fixed header, XLEN, FEXTRA, FNAME,
FCOMMENT, their terminators and FHCRC. Optional metadata is skipped incrementally
without being stored. FHCRC is verified. Each new member gets fresh DEFLATE
history and payload CRC/ISIZE, while aggregate byte limits remain unchanged.
An empty next member remains valid when aggregate decoded credit is zero.

A valid next gzip magic after the member ceiling fails `Member_Limit`; other
trailing bytes fail `Trailing_Data`. Arbitrary zero padding is rejected. A
possible next member cut off inside its header fails `Truncated`. Gzip trailers
are consumed exactly: the raw engine does not prefetch trailer bytes.

Output remains provisional until `Done`: prior chunks can be invalidated by a
later checksum, truncation, framing or limit failure. On an error, discard output
from that call before publishing it. Previous caller-owned chunks remain valid
storage but do not certify a complete valid entity. A streaming HTTP consumer
must validate both HTTP entity EOF and decoder `Done` before declaring success.
HTTP content framing and gzip limits are separate responsibilities.

`core:compress/zlib` also exposes `Inflate_State`, `inflate_init` and
`inflate_step` with the same result/work/borrowing rules for raw DEFLATE. Its
`Done` reports the precise final-block boundary without requiring final input,
so an envelope decoder can process following trailer bytes. The raw caller owns
trailing-data policy. Existing buffered gzip/zlib functions are unchanged.
