package harness

@(private)
floor_log2 :: proc(v: u64) -> int {
	n := 0
	x := v
	for x > 1 {
		x >>= 1
		n += 1
	}
	return n
}

// RFC 9000 Appendix A.2. Truncation keeps the least significant nbytes.
pn_wire_length :: proc(full_pn: u64, has_largest_acked: bool, largest_acked: u64) -> (nbytes: int, truncated: u64, err: Error) {
	if full_pn >= u64(1) << 62 {
		return 0, 0, .Invalid_Input
	}
	unacked: u64
	if !has_largest_acked {
		unacked = full_pn + 1
	} else if full_pn <= largest_acked || largest_acked >= u64(1) << 62 {
		return 0, 0, .Invalid_Input
	} else {
		unacked = full_pn - largest_acked
	}
	min_bits := floor_log2(unacked) + 1
	nbytes = (min_bits + 7) / 8
	if nbytes < 1 {
		nbytes = 1
	}
	if nbytes > 4 {
		return 0, 0, .Invalid_Input
	}
	truncated = full_pn & ((u64(1) << uint(nbytes * 8)) - 1)
	return nbytes, truncated, .None
}

// RFC 9000 Appendix A.3. has_largest false means no packet has been processed
// (expected number 0). Time 0 and "no sample" are not overloaded onto one sentinel.
pn_decode :: proc(has_largest: bool, largest, truncated: u64, pn_nbits: int) -> (u64, bool) {
	if pn_nbits != 8 && pn_nbits != 16 && pn_nbits != 24 && pn_nbits != 32 {
		return 0, false
	}
	pn_win := u64(1) << uint(pn_nbits)
	if truncated >= pn_win {
		return 0, false
	}
	expected: u64
	if has_largest {
		if largest >= (u64(1) << 62) - 1 {
			return 0, false
		}
		expected = largest + 1
	}
	pn_hwin := pn_win / 2
	pn_mask := pn_win - 1
	candidate := (expected & ~pn_mask) | truncated
	limit := (u64(1) << 62) - pn_win
	if expected >= pn_hwin && candidate <= expected - pn_hwin && candidate < limit {
		candidate += pn_win
	} else if expected <= max(u64) - pn_hwin && candidate > expected + pn_hwin && candidate >= pn_win {
		candidate -= pn_win
	}
	if candidate >= u64(1) << 62 {
		return 0, false
	}
	return candidate, true
}
