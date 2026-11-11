// Darwin-vs-Linux gate for the QUIC harness. Linux is unsupported: this process
// is not an independent peer, and a loopback of the harness model is not one.
package main

import "core:fmt"
import "core:net/quic/harness"
import "core:os"

main :: proc() {
	when ODIN_OS == .Linux {
		fmt.println("Linux independent QUIC peer is unsupported")
	} else when ODIN_OS == .Darwin {
		fmt.println("Linux peer unsupported; Darwin-vs-Linux comparison skipped")
	} else {
		fmt.println("Linux peer unsupported; comparison skipped")
	}
	compared, harness_ok := harness.darwin_vs_linux_gate()
	if !harness_ok {
		os.exit(1)
	}
	if compared {
		os.exit(2)
	}
}
