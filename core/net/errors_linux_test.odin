#+build linux
package net

import "core:sys/linux"
import "core:testing"

// accept(2) on Linux returns an error that was pending on the connection being
// accepted, and says to treat these like EAGAIN: try again. They must not be
// Unknown, which a server cannot tell from a broken listener.
@(test)
accept_names_the_errors_that_mean_try_again :: proc(t: ^testing.T) {
	cases := [?]struct {
		errno:    linux.Errno,
		expected: Accept_Error,
	} {
		{.ENETDOWN, .Network_Unreachable},
		{.ENETUNREACH, .Network_Unreachable},
		{.EHOSTDOWN, .Network_Unreachable},
		{.EHOSTUNREACH, .Network_Unreachable},
		{.ENONET, .Network_Unreachable},
		{.EPROTO, .Aborted},
		{.ENOPROTOOPT, .Aborted},
		{.ETIMEDOUT, .Timeout},
		{.EOPNOTSUPP, .Unsupported_Socket},
		{.ECONNABORTED, .Aborted},
		{.EAGAIN, .Would_Block},
		{.EINTR, .Interrupted},
	}
	for c in cases {
		testing.expectf(t, _accept_error(c.errno) == c.expected, "%v: %v", c.errno, _accept_error(c.errno))
	}
}
