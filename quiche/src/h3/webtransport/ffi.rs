#[cfg(feature = "wts")]
#[no_mangle]
pub extern fn quiche_h3_webtransport_conn_new_with_transport(
    quic_conn: &mut Connection,
) -> *mut h3::Connection {

    if !quic_conn.dgram_enabled() {
	return Err(Error::InvalidConfig("dgram_enabled"));
    }

    let mut config = h3::Config::new().unwrap();
    config.set_enable_webtransport(true);

    match h3::Connection::with_transport(quic_conn, &config) {
        Ok(v) => {
	    Box::into_raw(
		Box::new(
		    h3::webtransport::ServerSession::new(v)))

	},
	Err(_) => ptr::null_mut(),
    }
}
