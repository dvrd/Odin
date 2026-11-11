package conn

remaining_stream_records :: proc(c:^Connection)->int {
 if c==nil||!c.initialized{return 0}
 buffers,model:=0,0
 for b in c.bufs {if !b.used {buffers+=1}}
 for s in c.model.streams {if !s.active {model+=1}}
 return min(buffers,model)
}
// Admission is read-only. Closed IDs retain metadata to reject stale duplicates.
stream_admission :: proc(c:^Connection,id:u64)->Error {
 if e:=usable(c);e!=.None{return e}
 if id>=u64(1)<<62{return .Invalid}
 if find_buf(c,id)!=nil{return .None}
 if !our_stream(c,id){return .Invalid}
 _,limit:=send_limits(c,id)
 if id/4>=limit{return .Flow_Control}
 if remaining_stream_records(c)<=0{return .Capacity}
 return .None
}
close_with_application_error :: proc(c:^Connection,code:u64)->Error {
 if e:=usable(c);e!=.None{return e};if code>=u64(1)<<62||!c.hs.have_one_rtt||!c.hs.one_rtt_write.initialized{return .Invalid}
 c.close_application=true;c.close_error=code;c.want_close=true;return .None
}

// Read-only terminal deadline query for event loops that poll at/after expiry.
drain_complete :: proc(c:^Connection,now:i64)->bool {
 return c!=nil&&c.initialized&&(c.phase==.Closed||c.phase==.Failed||c.phase==.Draining&&now>=c.draining_until)
}
