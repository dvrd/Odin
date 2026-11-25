package tls

import "core:net"
import "core:testing"

// Every failure the engine can name reaches the caller as an error, and no
// failure reaches it as nil: a mapping that forgot a case would report success.
@(test)
error_mappings_report_every_failure_and_only_failures :: proc(t: ^testing.T) {
	check :: proc(t: ^testing.T, none: bool, err: Error, name: string, loc := #caller_location) {
		testing.expectf(t, none == (err == nil), "%s maps to %v", name, err, loc = loc)
	}

	for kind in Client_Error {
		check(t, kind == .None, client_error(kind), "Client_Error")
	}
	for kind in Handshake_Error_Kind {
		check(t, kind == .None, handshake_error({kind = kind}), "Handshake_Error")
	}
	for kind in IO_Error_Kind {
		check(t, kind == .None, io_error({kind = kind}), "IO_Error")
	}
	for kind in Server_Handshake_Error {
		check(t, kind == .None, server_handshake_error(kind), "Server_Handshake_Error")
	}
	for kind in Server_Ticket_Error {
		check(t, kind == .None, ticket_error(kind), "Server_Ticket_Error")
	}
	for kind in Anti_Replay_Error {
		check(t, kind == .None, anti_replay_error(kind), "Anti_Replay_Error")
	}
	for kind in Server_Async_Init_Error {
		check(t, kind == .None, server_async_init_error(kind), "Server_Async_Init_Error")
	}
	for kind in Server_Async_Failure_Kind {
		check(t, kind == .None, server_async_failure_error({kind = kind}), "Server_Async_Failure")
	}
	for kind in Root_Error_Kind {
		check(t, kind == .None, root_error({kind = kind}), "Root_Error")
	}
	for kind in Quic_Secret_Kind {
		check(t, kind == .None, quic_secret_error({kind = kind}), "Quic_Secret_Error")
	}
	for kind in Key_Schedule_Error {
		check(t, kind == .None, key_schedule_error(kind), "Key_Schedule_Error")
	}
	for kind in Finished_Error {
		check(t, kind == .None, finished_error(kind), "Finished_Error")
	}
	for kind in Client_Hello_Error {
		check(t, kind == .None, client_hello_encode_error(kind), "Client_Hello_Error")
	}
	for kind in Client_Hello_Send_Error_Kind {
		check(t, kind == .None, client_hello_send_error({kind = kind}), "Client_Hello_Send_Error")
	}
	for kind in Authentication_Error_Kind {
		check(t, kind == .None, authentication_error({kind = kind}), "Authentication_Error")
	}
	for kind in Record_Protection_Error {
		check(t, kind == .None, record_protection_error(kind), "Record_Protection_Error")
	}
	for kind in Server_Hello_Error {
		check(t, kind == .None, socket_server_hello_decode_error(kind), "Server_Hello_Error")
	}
}

// The values a caller is most likely to branch on.
@(test)
error_mappings_name_the_conditions_callers_branch_on :: proc(t: ^testing.T) {
	testing.expect_value(t, io_error({kind = .EOF}), Error(Protocol_Error.Close_Notify))
	testing.expect_value(t, client_error(.Missing_Trust_Roots), Error(General_Error.Invalid_Trust_Roots))
	testing.expect_value(t, client_error(.Invalid_Server_Name), Error(General_Error.Invalid_SNI_Hostname))
	testing.expect_value(t, server_handshake_error(.No_Application_Protocol), Error(Protocol_Error.No_Application_Protocol))
	testing.expect_value(t, server_handshake_error(.Limit), Error(General_Error.Limit_Exceeded))
	testing.expect_value(t, anti_replay_error(.Replayed), Error(General_Error.Early_Data_Rejected))
	testing.expect_value(t, handshake_error({kind = .Unsupported_Extension}), Error(Protocol_Error.Unsupported_Extension))
	testing.expect_value(t, transport_error(net.TCP_Recv_Error.Timeout), Error(net.TCP_Recv_Error.Timeout))
	testing.expect_value(t, transport_error(net.Connection_Error.Cancelled), Error(General_Error.Cancelled))
}
