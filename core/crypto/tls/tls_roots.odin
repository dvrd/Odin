package tls

import "base:runtime"

/*
Trust roots behind the package's `Error`.
*/

// root_pool_parse adds the certificates of a PEM bundle to the pool.
@(require_results)
root_pool_parse :: proc(pool: ^Root_Pool, data: []u8, allocator := context.allocator) -> Error {
	return root_error(engine_root_pool_parse(pool, data, allocator))
}

// root_pool_load_file adds the certificates of a PEM file to the pool.
@(require_results)
root_pool_load_file :: proc(pool: ^Root_Pool, path: string) -> Error {
	return root_error(engine_root_pool_load_file(pool, path))
}

// root_pool_load_system adds the trust roots of the operating system to the pool.
@(require_results)
root_pool_load_system :: proc(pool: ^Root_Pool) -> Error {
	return root_error(engine_root_pool_load_system(pool))
}

@(private, require_results)
root_error :: proc(failure: Root_Error) -> Error {
	switch failure.kind {
	case .None:
		return nil
	case .Invalid_State:
		return General_Error.Invalid_State
	case .Allocation_Failed:
		if failure.allocation == .None {
			return runtime.Allocator_Error.Out_Of_Memory
		}
		return failure.allocation
	case .Bundle_Oversized, .Certificate_Limit:
		return General_Error.Limit_Exceeded
	case .Read_Failed, .Invalid_PEM, .Invalid_Certificate, .No_Certificates:
		return General_Error.Invalid_Trust_Roots
	}
	return General_Error.Invalid_Trust_Roots
}
