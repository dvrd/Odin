package ecn
import "core:testing"

@(test)
receiver_counts_only_known_marks :: proc(t: ^testing.T) {
	c: Counts
	receive(&c, .ECT_0, true)
	receive(&c, .ECT_1, true)
	receive(&c, .CE, true)
	receive(&c, .CE, false)
	receive(&c, .Not_ECT, true)
	testing.expect_value(t, c, Counts{1, 1, 1})
}

@(test)
validated_ce_and_duplicate_ack :: proc(t: ^testing.T) {
	s: Sender
	init(&s, true)
	sent(&s, 2, .ECT_0)
	sent(&s, 2, .ECT_0)
	f := validate(&s, 2, 1, {ect0 = 2}, true, {ect0 = 1, ce = 1})
	testing.expect(t, f.accepted && f.congestion && s.state == .Capable)
	f = validate(&s, 2, 1, {}, true, {ce = 999})
	testing.expect(t, !f.disabled && !f.congestion && s.state == .Capable)
	sent(&s, 2, .ECT_0)
	f = validate(&s, 2, 2, {ect0 = 1}, true, {ect0 = 2, ce = 1})
	testing.expect(t, f.accepted && !f.congestion)
}

@(test)
bleach_remark_missing_and_invalid_counters_fall_back :: proc(t: ^testing.T) {
	for counts, i in ([]Counts{{}, {ect1 = 1}, {ect0 = 2}, {ce = 2}}) {
		s: Sender
		init(&s, true)
		sent(&s, 2, .ECT_0)
		f := validate(&s, 2, 1, {ect0 = 1}, i != 0, counts)
		testing.expect(t, f.disabled && mark(&s) == .Not_ECT)
	}
	s: Sender
	init(&s, true)
	sent(&s, 0, .ECT_0)
	testing.expect(t, validate(&s, 0, 1, {ect0 = 1}, true, {ect0 = 1}).accepted)
	sent(&s, 0, .ECT_0)
	testing.expect(t, validate(&s, 0, 2, {ect0 = 1}, true, {}).disabled)
}

@(test)
lost_ack_can_increase_feedback_more_than_newly_acked :: proc(t: ^testing.T) {
	s: Sender
	init(&s, true)
	for _ in 0 ..< 5 {sent(&s, 2, .ECT_0)}
	f := validate(&s, 2, 4, {ect0 = 1}, true, {ect0 = 5})
	testing.expect(t, f.accepted && !f.disabled)
	// Feedback is isolated by packet-number space.
	sent(&s, 0, .ECT_0)
	testing.expect(t, validate(&s, 0, 0, {ect0 = 1}, true, {ect0 = 1}).accepted)
	reset_path(&s)
	testing.expect_value(t, s.state, .Testing)
	timeout(&s)
	testing.expect_value(t, mark(&s), .Not_ECT)
}

@(test)
ect1_and_per_space_validation_do_not_cross_credit :: proc(t: ^testing.T) {
	s: Sender
	init(&s, true)
	sent(&s, 1, .ECT_1)
	testing.expect(t, validate(&s, 1, 0, {ect1 = 1}, true, {ce = 1}).congestion)
	sent(&s, 2, .ECT_0)
	testing.expect(t, validate(&s, 2, 0, {ect0 = 1}, true, {ce = 1}).congestion)
	sent(&s, 2, .ECT_0)
	testing.expect(t, validate(&s, 2, 1, {ect0 = 1}, true, {ect1 = 1, ce = 1}).disabled)
}

@(test)
unmarked_acks_do_not_establish_capability_and_disabled_is_inert :: proc(t: ^testing.T) {
	s: Sender
	init(&s, true)
	sent(&s, 2, .Not_ECT)
	testing.expect(t, !validate(&s, 2, 0, {}, false, {}).disabled && s.state == .Testing)
	timeout(&s)
	testing.expect(t, !validate(&s, 2, 1, {}, true, {}).accepted)
	init(&s, false)
	testing.expect_value(t, mark(&s), .Not_ECT)
	reset_path(&s)
	testing.expect_value(t, s.state, .Disabled)
}
