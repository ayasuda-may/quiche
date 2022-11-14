#[cfg(feature = "wt-ffi")]
use std::ptr;
use crate::*;

#[no_mangle]
pub extern fn quiche_h3_webtransport_conn_new_with_transport(
    quic_conn: &mut Connection,
) -> *mut h3::webtransport::ServerSession {

    match h3::webtransport::ServerSession::with_transport(
	quic_conn,
    ) {
	Ok(v) => {
	    Box::into_raw(Box::new(v))
	},
	Err(e) => {
	    error!("failed to init webtransport: {}", e);
	    std::ptr::null_mut()
	}
    }
}
