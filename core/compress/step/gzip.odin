package compress_step

import "core:compress/deflate"
import "core:hash"

/*
Resumable gzip decoding on top of `Inflate_Decoder`, with the same stepping rules:
`consumed` advances the input, `produced` the output, both slices are borrowed for
the call only and may not overlap. `Need_Input` asks for more encoded bytes,
`Need_Output` for output room, `Progress` yields at the work budget; continue from
the unconsumed suffix in every case.

Every encoded byte and every decoded byte is checked against the aggregate ceilings
of the `Gzip_Decoder_Config` before it is consumed or published; the ceilings cover
all concatenated members and their metadata, and never come from the untrusted
ISIZE. Optional header fields are skipped without being stored, FHCRC is verified,
and each member gets a fresh history, CRC-32 and ISIZE check.

Output is provisional until `Done`: a later checksum, truncation, framing or limit
failure invalidates what earlier steps produced. `Done` needs `final_input` and the
complete, validated trailer of every member. A next gzip magic past the member
ceiling fails `Member_Limit`, any other trailing byte `Trailing_Data` (zero padding
included), and a next member cut off inside its header `Truncated`.
*/

GZIP_DECODER_HEADER_BYTES_MIN :: size_of(deflate.Gzip_Header)
GZIP_DECODER_HEADER_BYTES_MAX :: 1 << 20
GZIP_DECODER_MEMBERS_MAX      :: 1024

// All limits are explicit finite values. Encoded/decoded totals include all
// members. The header limit includes the fixed header, optional fields and FHCRC
// bytes of one member. Empty members remain valid with a zero decoded limit.
Gzip_Decoder_Config :: struct {
	max_encoded_bytes: u64,
	max_decoded_bytes: u64,
	max_header_bytes:  u32,
	max_members:       u32,
}

GZIP_DECODER_DEFAULT_CONFIG :: Gzip_Decoder_Config{
	max_encoded_bytes = 64 << 20,
	max_decoded_bytes = 64 << 20,
	max_header_bytes  = 8192,
	max_members       = 1,
}

Gzip_Decoder_Phase :: enum {
	Uninitialized,
	Header,
	Extra_Length,
	Extra,
	Name,
	Comment,
	Header_CRC,
	Payload,
	Trailer,
	Between,
	End,
	Failed,
}

// State has fixed size and owns no allocator or borrowed slices. Allocate it
// through the caller's bounded allocator; releasing that allocation needs no
// destructor. Initialize before use; reinitialize to start another stream.
Gzip_Decoder :: struct {
	config:          Gzip_Decoder_Config,
	phase:           Gzip_Decoder_Phase,
	error:           Decode_Error,
	encoded_bytes:   u64,
	decoded_bytes:   u64,
	members:         u32,
	final_declared:  bool,
	inflate:         Inflate_Decoder,
	header:          [size_of(deflate.Gzip_Header)]u8,
	trailer:         [size_of(deflate.Gzip_Trailer)]u8,
	index:           int,
	flags:           deflate.Gzip_Header_Flags,
	header_bytes:    u32,
	header_crc:      u32,
	payload_crc:     u32,
	member_size:     u32,
	extra_remaining: u32,
	field:           u32,
}

inflate_gzip_decoder_init :: proc(d: ^Gzip_Decoder, config := GZIP_DECODER_DEFAULT_CONFIG) -> Decode_Error {
	if d == nil {
		return .Invalid_State
	}

	if config.max_header_bytes < GZIP_DECODER_HEADER_BYTES_MIN || config.max_header_bytes > GZIP_DECODER_HEADER_BYTES_MAX {
		return .Invalid_Config
	}

	if config.max_members == 0 || config.max_members > GZIP_DECODER_MEMBERS_MAX {
		return .Invalid_Config
	}

	d^ = Gzip_Decoder{config = config, phase = .Header}

	return .None
}

// final_input declares the end of the complete encoded entity, not the end of
// this network packet. Keep it true when resubmitting unconsumed suffixes after
// Need_Output/Progress. Once declared it cannot be withdrawn. All decoding errors
// are sticky until init; invalid arguments and overlapping buffers do not mutate
// state/output. On an error, discard this call's provisional output.
inflate_gzip_decoder_step :: proc(d: ^Gzip_Decoder, input, output: []u8, final_input: bool, work_limit := 4096) -> (r: Decode_Result) {
	r.status = .Progress

	if d == nil || d.phase == .Uninitialized {
		r.err = .Invalid_State
		return
	}

	if work_limit <= 0 || work_limit > DECODE_MAX_WORK {
		r.err = .Invalid_Config
		return
	}

	if decode_buffers_overlap(input, output) {
		r.err = .Overlapping_Buffers
		return
	}

	if d.phase == .Failed {
		r.err = d.error
		return
	}

	if d.final_declared && !final_input {
		r.err = .Invalid_State
		return
	}

	if d.phase == .End {
		if len(input) != 0 {
			r.err = .Trailing_Data
			d.error = r.err
			d.phase = .Failed
		} else {
			r.status = .Done
		}

		return
	}

	d.final_declared = final_input

	for r.work < work_limit {
		if d.phase == .Payload {
			if inflate_gzip_decoder_payload(d, input, output, final_input, work_limit, &r) {
				continue
			}

			return
		}

		r.work += 1
		need_input := false

		#partial switch d.phase {
		case .Header:
			need_input = inflate_gzip_decoder_header(d, input, &r)
		case .Extra_Length:
			value, ok := inflate_gzip_decoder_byte(d, input, &r, true, true)

			if !ok {
				need_input = true
				break
			}

			d.field |= u32(value) << uint(d.index * 8)
			d.index += 1

			if d.index == 2 {
				d.extra_remaining = d.field
				d.phase = .Extra
			}
		case .Extra:
			if d.extra_remaining == 0 {
				inflate_gzip_decoder_next_field(d)
				break
			}

			_, ok := inflate_gzip_decoder_byte(d, input, &r, true, true)

			if !ok {
				need_input = true
				break
			}

			d.extra_remaining -= 1
		case .Name, .Comment:
			value, ok := inflate_gzip_decoder_byte(d, input, &r, true, true)

			if !ok {
				need_input = true
				break
			}

			if value == 0 {
				inflate_gzip_decoder_next_field(d)
			}
		case .Header_CRC:
			value, ok := inflate_gzip_decoder_byte(d, input, &r, true, false)

			if !ok {
				need_input = true
				break
			}

			d.field |= u32(value) << uint(d.index * 8)
			d.index += 1

			if d.index == 2 {
				if d.field != d.header_crc & 0xffff {
					r.err = .Checksum_Mismatch
					break
				}

				inflate_gzip_decoder_next_field(d)
			}
		case .Trailer:
			need_input = inflate_gzip_decoder_trailer(d, input, &r)
		case .Between:
			if r.consumed == len(input) {
				if final_input {
					d.phase = .End
					r.status = .Done
				} else {
					r.status = .Need_Input
				}

				return
			}

			d.phase = .Header
			d.index = 0
			d.header_bytes = 0
			d.header_crc = 0
		case:
			r.err = .Invalid_State
		}

		if r.err != .None {
			d.error = r.err
			d.phase = .Failed
			return
		}

		if need_input {
			if final_input {
				r.err = .Truncated
				d.error = r.err
				d.phase = .Failed
			} else {
				r.status = .Need_Input
			}

			return
		}
	}

	return
}

// Runs the raw decoder on the member's payload. Returns true when the payload
// ended and the step goes on with the trailer.
@(private)
inflate_gzip_decoder_payload :: proc(d: ^Gzip_Decoder, input, output: []u8, final_input: bool, work_limit: int, r: ^Decode_Result) -> (ended: bool) {
	p := inflate_decoder_step(&d.inflate, input[r.consumed:], output[r.produced:], final_input, work_limit - r.work)

	if p.produced > 0 {
		d.payload_crc = hash.crc32(output[r.produced:][:p.produced], d.payload_crc)
		d.member_size += u32(p.produced)
	}

	r.consumed += p.consumed
	r.produced += p.produced
	r.work += p.work
	d.encoded_bytes += u64(p.consumed)
	d.decoded_bytes += u64(p.produced)

	if p.err != .None {
		r.err = p.err
		d.error = r.err
		d.phase = .Failed
		return false
	}

	if p.status == .Done {
		d.phase = .Trailer
		d.index = 0
		return true
	}

	r.status = p.status

	return false
}

// Reads one byte of the fixed header. Returns true when it needs more input.
@(private)
inflate_gzip_decoder_header :: proc(d: ^Gzip_Decoder, input: []u8, r: ^Decode_Result) -> (need_input: bool) {
	value, ok := inflate_gzip_decoder_byte(d, input, r, true, true)

	if !ok {
		return true
	}

	d.header[d.index] = value
	d.index += 1

	// Anything but a gzip magic after a complete member is trailing data.
	not_gzip := Decode_Error.Trailing_Data if d.members != 0 else Decode_Error.Malformed

	if d.index == 1 && value != 0x1f {
		r.err = not_gzip
		return false
	}

	if d.index == 2 {
		if value != 0x8b {
			r.err = not_gzip
			return false
		}

		if d.members == d.config.max_members {
			r.err = .Member_Limit
			return false
		}
	}

	if d.index != len(d.header) {
		return false
	}

	header := (^deflate.Gzip_Header)(&d.header)^

	if header.compression_method != .DEFLATE || header.flags & {.reserved_1, .reserved_2, .reserved_3} != {} {
		r.err = .Malformed
		return false
	}

	d.flags = header.flags
	inflate_gzip_decoder_next_field(d)

	return false
}

// Reads one byte of the trailer and validates it once complete. Returns true when
// it needs more input.
@(private)
inflate_gzip_decoder_trailer :: proc(d: ^Gzip_Decoder, input: []u8, r: ^Decode_Result) -> (need_input: bool) {
	value, ok := inflate_gzip_decoder_byte(d, input, r, false, false)

	if !ok {
		return true
	}

	d.trailer[d.index] = value
	d.index += 1

	if d.index != len(d.trailer) {
		return false
	}

	trailer := (^deflate.Gzip_Trailer)(&d.trailer)^

	if u32(trailer.crc32) != d.payload_crc {
		r.err = .Checksum_Mismatch
		return false
	}

	if u32(trailer.size) != d.member_size {
		r.err = .Size_Mismatch
		return false
	}

	d.members += 1
	d.phase = .Between

	return false
}

// Moves on to the next optional header field the flags announce, or to the payload.
@(private)
inflate_gzip_decoder_next_field :: proc(d: ^Gzip_Decoder) {
	d.index = 0
	d.field = 0

	switch {
	case .extra in d.flags:
		d.flags -= {.extra}
		d.phase = .Extra_Length
	case .name in d.flags:
		d.flags -= {.name}
		d.phase = .Name
	case .comment in d.flags:
		d.flags -= {.comment}
		d.phase = .Comment
	case .header_crc in d.flags:
		d.flags -= {.header_crc}
		d.phase = .Header_CRC
	case:
		inflate_decoder_init(&d.inflate, d.config.max_encoded_bytes - d.encoded_bytes, d.config.max_decoded_bytes - d.decoded_bytes)
		d.payload_crc = 0
		d.member_size = 0
		d.phase = .Payload
	}
}

@(private)
inflate_gzip_decoder_byte :: proc(d: ^Gzip_Decoder, input: []u8, r: ^Decode_Result, header, crc: bool) -> (value: u8, ok: bool) {
	if r.consumed == len(input) {
		return 0, false
	}

	if d.encoded_bytes == d.config.max_encoded_bytes {
		r.err = .Encoded_Limit
		return 0, false
	}

	if header && d.header_bytes == d.config.max_header_bytes {
		r.err = .Metadata_Limit
		return 0, false
	}

	value = input[r.consumed]
	r.consumed += 1
	d.encoded_bytes += 1

	if header {
		d.header_bytes += 1
	}

	if crc {
		b := [1]u8{value}
		d.header_crc = hash.crc32(b[:], d.header_crc)
	}

	return value, true
}
