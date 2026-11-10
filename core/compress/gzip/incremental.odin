package compress_gzip

import "core:compress"
import "core:compress/zlib"
import "core:hash"

Config :: struct {
	max_encoded_bytes: u64,
	max_decoded_bytes: u64,
	max_header_bytes: u32,
	max_members: u32,
}

Decoder_Phase :: enum { Uninitialized, Header, Extra_Length, Extra, Name, Comment, Header_CRC, Payload, Trailer, Between, End, Failed }

// State has fixed size and owns no allocator or borrowed slices. Allocate it
// through the caller's bounded allocator; releasing that allocation needs no
// decoder destructor. Initialize before use; reinitialize to start another stream.
Decoder :: struct {
	config: Config,
	phase: Decoder_Phase,
	error: compress.Decode_Error,
	encoded_bytes, decoded_bytes: u64,
	members: u32,
	final_declared: bool,
	inflate: zlib.Inflate_State,
	fixed: [10]u8,
	trailer: [8]u8,
	index: int,
	flags: u8,
	header_bytes: u32,
	header_crc, payload_crc, member_size: u32,
	extra_remaining: u32,
	field: u32,
}

// All limits are explicit finite values. Encoded/decoded totals include all
// members. Header limit includes fixed header, optional fields and FHCRC bytes.
// Empty bodies/members remain valid with a zero decoded limit.
decoder_init :: proc(d: ^Decoder, config := Config{64 << 20, 64 << 20, 8192, 1}) -> compress.Decode_Error {
	if d == nil { return .Invalid_State }
	if config.max_header_bytes < 10 || config.max_header_bytes > 1 << 20 ||
		config.max_members == 0 || config.max_members > 1024 { return .Invalid_Config }
	d^ = Decoder{config = config, phase = .Header}
	return .None
}

@(private)
decoder_optional :: proc(d: ^Decoder) {
	d.index = 0; d.field = 0
	if d.flags & 4 != 0 { d.flags &~= 4; d.phase = .Extra_Length; return }
	if d.flags & 8 != 0 { d.flags &~= 8; d.phase = .Name; return }
	if d.flags & 16 != 0 { d.flags &~= 16; d.phase = .Comment; return }
	if d.flags & 2 != 0 { d.flags &~= 2; d.phase = .Header_CRC; return }
	_ = zlib.inflate_init(&d.inflate, d.config.max_encoded_bytes-d.encoded_bytes,
		d.config.max_decoded_bytes-d.decoded_bytes)
	d.payload_crc = 0; d.member_size = 0
	d.phase = .Payload
}

@(private)
decoder_byte :: proc(d: ^Decoder, input: []u8, r: ^compress.Decode_Result,
	header, crc: bool) -> (u8, bool) {
	if r.consumed == len(input) { return 0, false }
	if d.encoded_bytes == d.config.max_encoded_bytes { r.err = .Encoded_Limit; return 0, false }
	if header && d.header_bytes == d.config.max_header_bytes { r.err = .Metadata_Limit; return 0, false }
	v := input[r.consumed]
	r.consumed += 1; d.encoded_bytes += 1
	if header { d.header_bytes += 1 }
	if crc { b := [1]u8{v}; d.header_crc = hash.crc32(b[:], d.header_crc) }
	return v, true
}

// final_input declares the end of the complete encoded entity, not the end of
// this network packet. Keep it true when resubmitting unconsumed suffixes after
// Need_Output/Progress. Once declared it cannot be withdrawn. Done is returned
// only after final_input and complete validation of every member and trailer.
// Valid next members over the member cap fail Member_Limit; other trailing data
// fails Trailing_Data. Arbitrary padding is not accepted. A possible next member
// cut off inside its header fails Truncated. All decoding errors are sticky until
// init; invalid arguments and overlapping buffers do not mutate state/output.
// On an error, discard this call's provisional output before publishing chunks.
decoder_step :: proc(d: ^Decoder, input, output: []u8, final_input: bool,
	work_limit := 4096) -> (r: compress.Decode_Result) {
	r.status = .Progress
	if d == nil || d.phase == .Uninitialized { r.err = .Invalid_State; return }
	if work_limit <= 0 || work_limit > compress.DECODE_MAX_WORK { r.err = .Invalid_Config; return }
	if compress.decode_buffers_overlap(input, output) { r.err = .Overlapping_Buffers; return }
	if d.phase == .Failed { r.err = d.error; return }
	if d.final_declared && !final_input { r.err = .Invalid_State; return }
	if d.phase == .End {
		if len(input) != 0 {
			r.err = .Trailing_Data; d.error = r.err; d.phase = .Failed
		} else { r.status = .Done }
		return
	}
	d.final_declared = final_input
	for r.work < work_limit {
		if d.phase == .Payload {
			p := zlib.inflate_step(&d.inflate, input[r.consumed:], output[r.produced:],
				final_input, work_limit-r.work)
			if p.produced > 0 {
				d.payload_crc = hash.crc32(output[r.produced:r.produced+p.produced], d.payload_crc)
				d.member_size += u32(p.produced)
			}
			r.consumed += p.consumed; r.produced += p.produced; r.work += p.work
			d.encoded_bytes += u64(p.consumed); d.decoded_bytes += u64(p.produced)
			if p.err != .None { r.err = p.err; d.error = r.err; d.phase = .Failed; return }
			if p.status == .Done { d.phase = .Trailer; d.index = 0; continue }
			r.status = p.status
			return
		}
		r.work += 1
		need_input := false
		#partial switch d.phase {
		case .Header:
			v, ok := decoder_byte(d, input, &r, true, true)
			if !ok { need_input = true; break }
			d.fixed[d.index] = v; d.index += 1
			if d.index == 1 && v != 0x1f {
				r.err = .Trailing_Data if d.members != 0 else .Malformed; break
			}
			if d.index == 2 {
				if v != 0x8b { r.err = .Trailing_Data if d.members != 0 else .Malformed; break }
				if d.members == d.config.max_members { r.err = .Member_Limit; break }
			}
			if d.index != 10 { break }
			if d.fixed[2] != 8 || d.fixed[3] & 0xe0 != 0 { r.err = .Malformed; break }
			d.flags = d.fixed[3]
			decoder_optional(d)
		case .Extra_Length:
			v, ok := decoder_byte(d, input, &r, true, true)
			if !ok { need_input = true; break }
			d.field |= u32(v) << uint(d.index*8); d.index += 1
			if d.index == 2 { d.extra_remaining = d.field; d.phase = .Extra }
		case .Extra:
			if d.extra_remaining == 0 { decoder_optional(d); break }
			_, ok := decoder_byte(d, input, &r, true, true)
			if !ok { need_input = true; break }
			d.extra_remaining -= 1
		case .Name, .Comment:
			v, ok := decoder_byte(d, input, &r, true, true)
			if !ok { need_input = true; break }
			if v == 0 { decoder_optional(d) }
		case .Header_CRC:
			v, ok := decoder_byte(d, input, &r, true, false)
			if !ok { need_input = true; break }
			d.field |= u32(v) << uint(d.index*8); d.index += 1
			if d.index == 2 {
				if d.field != d.header_crc & 0xffff { r.err = .Checksum_Mismatch; break }
				decoder_optional(d)
			}
		case .Trailer:
			v, ok := decoder_byte(d, input, &r, false, false)
			if !ok { need_input = true; break }
			d.trailer[d.index] = v; d.index += 1
			if d.index != 8 { break }
			crc := u32(d.trailer[0]) | u32(d.trailer[1])<<8 | u32(d.trailer[2])<<16 | u32(d.trailer[3])<<24
			size := u32(d.trailer[4]) | u32(d.trailer[5])<<8 | u32(d.trailer[6])<<16 | u32(d.trailer[7])<<24
			if crc != d.payload_crc { r.err = .Checksum_Mismatch; break }
			if size != d.member_size { r.err = .Size_Mismatch; break }
			d.members += 1; d.phase = .Between
		case .Between:
			if r.consumed == len(input) {
				if final_input { d.phase = .End; r.status = .Done } else { r.status = .Need_Input }
				return
			}
			d.phase = .Header; d.index = 0; d.header_bytes = 0; d.header_crc = 0
		case: r.err = .Invalid_State
		}
		if r.err != .None { d.error = r.err; d.phase = .Failed; return }
		if need_input {
			if final_input { r.err = .Truncated; d.error = r.err; d.phase = .Failed } else { r.status = .Need_Input }
			return
		}
	}
	return
}
