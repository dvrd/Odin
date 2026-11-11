# ECN accounting

This caller-serialized module implements QUIC ECN counter validation shared by
native packet owners. `Counts` holds cumulative ECT(0), ECT(1), and CE counts.
`receive` is called only for an authenticated, admitted, nonduplicate packet;
each packet in a coalesced datagram counts separately in its packet-number space.

A `Sender` starts in Testing when enabled. `mark` selects ECT(0), `sent` records
each packet's original mark, and `validate` receives the three peer counters and
the exact original marks of newly acknowledged packets. The owner must retain
those marks until acknowledgment/loss accounting permits retirement. Reordered
ACKs that do not advance the largest acknowledged packet cannot fail validation.
Counter increases may exceed newly acknowledged packets because ACKs can be lost;
total counters remain bounded by transmitted marks. Missing, bleached, regressing,
remarked, or excessive feedback changes the sender to Failed and subsequent
traffic uses Not-ECT. This fallback does not close the connection.

A validated new CE increase returns `Feedback.congestion`. The packet owner passes
that event with the acknowledged packet's send time to its congestion controller,
which limits the reduction to once per recovery epoch. `reset_path` restarts path
validation while retaining cumulative packet-space counter baselines. `timeout`
disables a still-unvalidated sender after the caller's three-PTO probe deadline.

Native socket support is additive in core:net: `udp_enable_ecn`,
`recv_udp_metadata`, and per-datagram `send_udp_ecn`. Darwin and Linux support
IPv4/IPv6 ancillary fields; unsupported platforms expose capability failure and
retain ordinary unmarked UDP. Missing/truncated ancillary data is explicit and
never fabricated as Not-ECT feedback. Per-datagram sends set DSCP to zero.

`interop/main.odin` with `interop/peer.py` exercises bidirectional traffic-class
metadata against an independent Python socket peer on IPv4 and IPv6. It is a
socket metadata test, not an independent QUIC implementation. Full encrypted
QUIC and HTTP3 cases live in the conn/sim and shared HTTP3 suites.

Protocol basis: RFC9000 sections13.4/19.3 and RFC9002 section7.1.
