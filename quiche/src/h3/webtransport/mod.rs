//!
//! WebTransport over HTTP/3 session management implementation.
//!
//! This module provides both server-side and client-side
//! WebTransport session management API.
//!
//! ## Connection setup
//!
//! Same as quiche::h3 module, WebTransport session
//! requires a QUIC transport-layer connection, see
//! [Connection setup] for a full description of the setup process.
//!
//! To use HTTP/3, the QUIC connection must be configured with a suitable
//! Application Layer Protocol Negotiation (ALPN) Protocol ID:
//!
//! ```
//! let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION)?;
//! config.set_application_protos(quiche::h3::APPLICATION_PROTOCOL)?;
//! # Ok::<(), quiche::Error>(())
//! ```
//!
//! The QUIC handshake is driven by [sending] and [receiving] QUIC packets.
//!
//! Once the handshake has completed, the first step in establishing an HTTP/3
//! connection and WebTransport session is creating its configuration object:
//!
//! WebTransport over HTTP/3 client and server connections are both created using the
//! [`with_transport()`] function, the role is inferred from the type of QUIC
//! connection:
//!
//! To create a client session, do the following
//!
//! ```no_run
//! # let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION).unwrap();
//! # let scid = quiche::ConnectionId::from_ref(&[0xba; 16]);
//! # let addr = "127.0.0.1:1234".parse().unwrap();
//! # let mut conn = quiche::connect(Some("quic.tech"), &scid, addr, &mut config)?;
//! let client_session = quiche::h3::webtransport::ClientSession::with_transport(&mut conn)?;
//! # Ok::<(), quiche::h3::webtransport::Error>(())
//! ```
//!
//! An example of creating a server session might look like this
//!
//! ```no_run
//! # let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION).unwrap();
//! # let scid = quiche::ConnectionId::from_ref(&[0xba; 16]);
//! # let from = "127.0.0.1:1234".parse().unwrap();
//! # let mut conn = quiche::accept(&scid, None, from, &mut config).unwrap();
//! let server_session = quiche::h3::webtransport::ServerSession::with_transport(&mut conn)?;
//! # Ok::<(), quiche::h3::webtransport::Error>(())
//! ```
//!
//! ## Client sends a CONNECT request
//!
//! To initiate a session, the client executes the [`send_connect_request()`] function.
//! Within this function, it sends a HEADERS frame,
//! adding the header values required by the WebTransport protocol,
//! in the manner of HTTP/3.
//!
//! ```no_run
//! # let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION).unwrap();
//! # let scid = quiche::ConnectionId::from_ref(&[0xba; 16]);
//! # let addr = "127.0.0.1:1234".parse().unwrap();
//! # let mut conn = quiche::connect(Some("quic.tech"), &scid, addr, &mut config)?;
//! let mut client_session = quiche::h3::webtransport::ClientSession::with_transport(&mut conn)?;
//! // After received peer's SETTINGS frame,
//! client_session.send_connect_request(&mut conn, b"authority.quic.tech:1234", b"/path", b"origin.quic.tech", None);
//! # Ok::<(), quiche::h3::webtransport::Error>(())
//! ```
//! ## Handling WebTransport events
//!
//! ### Server side
//!
//! After [receiving] QUIC packets, HTTP/3 data is processed using the
//! connection's [`poll()`] method. On success, this returns an [`Event`] object
//! and an ID corresponding to the stream where the `Event` originated.
//!
//! The management of WebTransport's session_id is managed inside ServerSession, so you don't have to worry about it.
//!
//! ```no_run
//! # let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION).unwrap();
//! # let scid = quiche::ConnectionId::from_ref(&[0xba; 16]);
//! # let from = "127.0.0.1:1234".parse().unwrap();
//! # let mut conn = quiche::accept(&scid, None, from, &mut config).unwrap();
//! let mut server_session = quiche::h3::webtransport::ServerSession::with_transport(&mut conn)?;
//!
//! // Before executing the poll, pass the packet received from the UDP socket
//! // in your application and the sender's address to the `recv` function of quiche::Connection.
//!
//! // let (packet, addr) = received_packet_from_udp_socket();
//! // conn.recv(packet, quiche::RecvInfo{ from: addr });
//!
//! // The `poll` can pull out the events that occurred according to the data passed here.
//! loop {
//!     match server_session.poll(&mut conn) {
//!         Ok(quiche::h3::webtransport::ServerEvent::ConnectRequest(req)) => {
//!             // you can handle request with
//!             // req.authority()
//!             // req.path()
//!             // and you can validate this request with req.origin()
//!             if req.origin() == "origin.quic.tech" {
//!                 server_session.accept_connect_request(&mut conn, None);
//!             } else {
//!                 server_session.reject_connect_request(&mut conn, 403, None);
//!             }
//!         },
//!
//!         Ok(quiche::h3::webtransport::ServerEvent::StreamData(stream_id)) => {
//!             let mut buf = vec![0; 10000];
//!             while let Ok(len) = server_session.recv_stream_data(&mut conn, stream_id, &mut buf) {
//!                 let stream_data = &buf[0..len];
//!                 // handle stream_data
//!
//!                 if (stream_id & 0x2) == 0 {
//!                     // bidirectional stream
//!                     // you can send data through this stream.
//!                     server_session.send_stream_data(&mut conn, stream_id, stream_data);
//!                 } else {
//!                     // you cannot send data through client-initiated-unidirectional-stream.
//!                     // so, open new server-initiated-unidirectional-stream, and send data
//!                     // through it.
//!                     let new_stream_id = server_session.open_stream(&mut conn, false).unwrap();
//!                     server_session.send_stream_data(&mut conn, new_stream_id, stream_data);
//!                 }
//!             }
//!         },
//!
//!         Ok(quiche::h3::webtransport::ServerEvent::StreamFinished(stream_id)) => {
//!             // A WebTransport stream finished, handle it.
//!         },
//!
//!         Ok(quiche::h3::webtransport::ServerEvent::Datagram) => {
//!             let mut buf = vec![0; 1500];
//!             while let Ok((in_session, offset, total)) = server_session.recv_dgram(&mut conn, &mut buf) {
//!                 if in_session {
//!                     let dgram = &buf[offset..total];
//!                     // handle this dgram
//!
//!                     // for instance, you can write echo-server like following
//!                     server_session.send_dgram(&mut conn, dgram);
//!                 } else {
//!                     // this dgram is not related to current WebTransport session. ignore.
//!                 }
//!             }
//!         },
//!
//!         Ok(quiche::h3::webtransport::ServerEvent::SessionReset(e)) => {
//!             // Peer reset session stream, handle it.
//!         },
//!
//!         Ok(quiche::h3::webtransport::ServerEvent::SessionFinished) => {
//!             // Peer finish session stream, handle it.
//!         },
//!
//!         Ok(quiche::h3::webtransport::ServerEvent::SessionGoAway) => {
//!              // Peer signalled it is going away, handle it.
//!         },
//!
//!         Ok(quiche::h3::webtransport::ServerEvent::Other(stream_id, event)) => {
//              // Original h3::Event which is not related to WebTransport.
//!         },
//!
//!         Err(quiche::h3::webtransport::Error::Done) => {
//!             break;
//!         },
//!
//!         Err(e) => {
//!             break;
//!         },
//!     }
//! }
//!
//! // After calling the send-related functions of ServerSession,
//! // the send method of quiche::Connection must be called.
//! // This allows you to extract the QUIC packets that should be sent
//! // through the UDP socket.
//! // You need to write a process to pass this through to the UDP socket.
//! let mut buf = vec![0; 1500];
//! loop {
//!     match conn.send(&mut buf) {
//!         Ok((len, send_info)) => {
//!             let packet = &buf[0..len];
//!             // send this packet to peer through UDP socket.
//!         },
//!         Err(quiche::Error::Done) => break,
//!         Err(e) => break,
//!     }
//! }
//!
//! //
//! # Ok::<(), quiche::h3::webtransport::Error>(())
//! ```
//!
//! ### Client side
//!
//! ```no_run
//! # let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION).unwrap();
//! # let scid = quiche::ConnectionId::from_ref(&[0xba; 16]);
//! # let addr = "127.0.0.1:1234".parse().unwrap();
//! # let mut conn = quiche::connect(Some("quic.tech"), &scid, addr, &mut config)?;
//! let mut client_session = quiche::h3::webtransport::ClientSession::with_transport(&mut conn)?;
//!
//! // Before executing the poll, pass the packet received from the UDP socket
//! // in your application and the sender's address to the `recv` function of quiche::Connection.
//!
//! // let (packet, addr) = received_packet_from_udp_socket();
//! // conn.recv(packet, quiche::RecvInfo{ from: addr });
//!
//! // The `poll` can pull out the events that occurred according to the data passed here.
//!
//! loop {
//!     match client_session.poll(&mut conn) {
//!         Ok(quiche::h3::webtransport::ClientEvent::PeerReady) => {
//!             // This event is issued when a SETTINGS frame from the server is received and
//!             // it detects that WebTransport is enabled.
//!             client_session.send_connect_request(&mut conn,
//!                 b"authority.quic.tech:1234",
//!                 b"/path",
//!                 b"origin.quic.tech",
//!                 None);
//!         },
//!         Ok(quiche::h3::webtransport::ClientEvent::Connected) => {
//!             // receive response from server for CONNECT request,
//!             // and it indicates server accepted it.
//!             // you can start to send any data through Stream or send Datagram
//!         },
//!         Ok(quiche::h3::webtransport::ClientEvent::Rejected(code)) => {
//!             // receive response from server for CONNECT request,
//!             // and it indicates server rejected it.
//!             // you may want to close session.
//!         },
//!         Ok(quiche::h3::webtransport::ClientEvent::StreamData(stream_id)) => {
//!             let mut buf = vec![0; 10000];
//!             while let Ok(len) = client_session.recv_stream_data(&mut conn, stream_id, &mut buf) {
//!                 let stream_data = &buf[0..len];
//!                 //handle_stream_data(stream_data);
//!             }
//!
//!         },
//!         Ok(quiche::h3::webtransport::ClientEvent::Datagram) => {
//!             let mut buf = vec![0; 1500];
//!             while let Ok((in_session, offset, total)) = client_session.recv_dgram(&mut conn, &mut buf) {
//!                 if in_session {
//!                     let dgram = &buf[offset..total];
//!                     // handle_dgram(dgram);
//!                 } else {
//!                     // this dgram is not related to current WebTransport session. ignore.
//!                 }
//!             }
//!         },
//!         Ok(quiche::h3::webtransport::ClientEvent::StreamFinished(stream_id)) => {
//!             // A WebTrnasport stream finished, handle it.
//!         },
//!         Ok(quiche::h3::webtransport::ClientEvent::SessionFinished) => {
//!             // Peer finish session stream, handle it.
//!         },
//!         Ok(quiche::h3::webtransport::ClientEvent::SessionReset(e)) => {
//!             // Peer reset session stream, handle it.
//!         },
//!         Ok(quiche::h3::webtransport::ClientEvent::SessionGoAway) => {
//!              // Peer signalled it is going away, handle it.
//!         },
//!         Ok(quiche::h3::webtransport::ClientEvent::Other(stream_id, event)) => {
//              // Original h3::Event which is not related to WebTransport.
//!         },
//!         Err(quiche::h3::webtransport::Error::Done) => break,
//!         Err(e) => break,
//!     }
//! }
//!
//! let mut data_to_be_sent = vec![1; 500];
//!
//! let bidi_stream_id = client_session.open_stream(&mut conn, true)?;
//! client_session.send_stream_data(&mut conn, bidi_stream_id, &data_to_be_sent)?;
//!
//! let uni_stream_id = client_session.open_stream(&mut conn, false)?;
//! client_session.send_stream_data(&mut conn, uni_stream_id, &data_to_be_sent)?;
//!
//! client_session.send_dgram(&mut conn, &data_to_be_sent)?;
//!
//! // After calling the send-related functions of ClientSession,
//! // the send method of quiche::Connection must be called.
//! // This allows you to extract the QUIC packets that should be sent
//! // through the UDP socket.
//! // You need to write a process to pass this through to the UDP socket.
//! let mut buf = vec![0; 1500];
//! loop {
//!     match conn.send(&mut buf) {
//!         Ok((len, send_info)) => {
//!             let packet = &buf[0..len];
//!             // send this packet to peer through UDP socket.
//!         },
//!         Err(quiche::Error::Done) => break,
//!         Err(e) => break,
//!     }
//! }
//! # Ok::<(), quiche::h3::webtransport::Error>(())
//! ```
//!
use crate::h3::{self, Header, NameValue};
use crate::stream::is_bidi;
use crate::Connection;
use std::collections::HashMap;
use std::str;

const HTTP_STATUS_BAD_REQUEST: u32 = 400;
const HTTP_STATUS_TOO_MANY_REQUESTS: u32 = 429;

/// If you want to reject the CONNECT request and then disconnect QUIC, use this code as the reason.
pub const QUIC_CLOSE_REASON_REQUEST_REJECTED: u64 = 0x10B;

/// An WebTransport error.
#[derive(Clone, Debug, PartialEq)]
pub enum Error {
    /// There is no error or no work todo
    Done,

    /// Invalid state of session.
    InvalidState,

    /// An argument of method is wrong.
    InvalidArg(&'static str),

    /// Invalid QUIC tarnsport configuration found.
    InvalidConfig(&'static str),

    /// The specified stream doesn't exist.
    StreamNotFound,

    /// The direction or initiater of the specified stream does not match.
    InvalidStream,

    /// Error originated from the transport layer.
    TransportError(crate::Error),

    /// Unexpected data received from peer.
    UnexpectedMessage,

    /// Error originated from the HTTP3 layer.
    HTTPError(h3::Error),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        None
    }
}

impl std::convert::From<h3::Error> for Error {
    fn from(err: h3::Error) -> Self {
        match err {
            h3::Error::Done => Error::Done,
            h3::Error::TransportError(e) => Error::TransportError(e),
            _ => Error::HTTPError(err),
        }
    }
}

impl std::convert::From<crate::Error> for Error {
    fn from(err: crate::Error) -> Self {
        match err {
            crate::Error::Done => Error::Done,
            _ => Error::TransportError(err),
        }
    }
}

/// An error on CONNECT request to establish WebTransport session.
#[derive(Clone, Debug, PartialEq)]
enum ConnectRequestError {
    /// A parameter not found.
    MissingParam(&'static str),
    /// A parameter' type or format is wrong.
    InvalidParam(&'static str, Vec<u8>),
    /// A parameter doesn't match to expected one.
    ParamMismatch(&'static str, &'static str, Vec<u8>),
}

/// The main header values that were included in the HTTP request to initiate WebTransport
#[derive(Clone, Debug, PartialEq)]
pub struct ConnectRequest {
    authority: String,
    path: String,
    origin: String,
}

impl ConnectRequest {
    /// Create a new connect-request
    pub fn new(authority: String, path: String, origin: String) -> Self {
        Self {
            authority,
            path,
            origin,
        }
    }

    /// accessor to the ':authority' header value
    pub fn authority(&self) -> &str {
        &self.authority
    }

    /// accessor to the ':path' header value
    pub fn path(&self) -> &str {
        &self.path
    }

    /// accessor to the 'origin' header value
    pub fn origin(&self) -> &str {
        &self.origin
    }
}

/// An WebTransport server session event.
#[derive(Clone, Debug, PartialEq)]
pub enum ServerEvent {
    /// HTTP headers requesting WebTransport start were received.
    ConnectRequest(ConnectRequest),

    /// WebTransport stream payload was received
    StreamData(u64),

    /// WebTransport stream was closed.
    StreamFinished(u64),

    /// DATAGRAM was received
    Datagram,

    /// WebTransport session-control-stream was closed.
    SessionFinished,

    /// WebTransport session-control-stream was reset.
    SessionReset(u64),

    /// GOAWAY was received on WebTransport session-control-stream.
    SessionGoAway,

    /// Bypassed events related to HTTP other than WebTransport
    Other(u64, h3::Event),
}

/// An WebTransport client session event.
#[derive(Clone, Debug, PartialEq)]
pub enum ClientEvent {
    /// QUIC handshake is completed, and server's SETTINGS indicates server can accept
    /// WebTransport.
    PeerReady,

    /// response for CONNECT request was received with OK status.
    Connected,

    /// response for CONNECT request was received with not OK status.
    Rejected(i32),

    /// WebTransport stream payload was received
    StreamData(u64),

    /// WebTransport stream was closed.
    StreamFinished(u64),

    /// DATAGRAM was received
    Datagram,

    /// WebTransport session-control-stream was closed.
    SessionFinished,

    /// WebTransport session-control-stream was reset.
    SessionReset(u64),

    /// GOAWAY was received on WebTransport session-control-stream.
    SessionGoAway,

    /// Events related to HTTP other than WebTransport
    Other(u64, h3::Event),
}

/// A specialized [`Result`] type for quiche WebTransport operations.
///
/// This type is used throughout quiche's WebTransport public API for any operation
/// that can produce an error.
///
/// [`Result`]: https://doc.rust-lang.org/std/result/enum.Result.html
pub type Result<T> = std::result::Result<T, Error>;

/// Information about WebTransport stream.
struct StreamInfo {
    stream_id: u64,
    local: bool,
}

impl StreamInfo {
    /// Create a new stream info
    pub fn new(stream_id: u64, local: bool) -> Self {
        Self { stream_id, local }
    }

    /// Returns true if the stream is bidirectional.
    pub fn is_bidi(&self) -> bool {
        is_bidi(self.stream_id)
    }

    /// Returns true if the stream was created locally.
    pub fn is_local(&self) -> bool {
        self.local
    }
}

fn find_request(
    list: &[h3::Header],
) -> std::result::Result<ConnectRequest, ConnectRequestError> {
    match is_webtransport_request(list) {
        Ok(()) => {
            let mut headers = list.iter();

            let authority = find_string_param(&mut headers, ":authority")?;
            let path = find_string_param(&mut headers, ":path")?;
            let origin = find_string_param(&mut headers, "origin")?;

            Ok(ConnectRequest::new(authority, path, origin))
        },

        Err(e) => Err(e),
    }
}

fn find_string_param(
    headers: &mut std::slice::Iter<h3::Header>, param: &'static str,
) -> std::result::Result<String, ConnectRequestError> {
    if let Some(header) = headers.find(|h| h.name() == param.as_bytes()) {
        if let Ok(param_str) = String::from_utf8(header.value().to_vec()) {
            Ok(param_str)
        } else {
            Err(ConnectRequestError::InvalidParam(
                param,
                header.value().to_vec(),
            ))
        }
    } else {
        Err(ConnectRequestError::MissingParam(param))
    }
}

fn find_integer_param(
    headers: &mut std::vec::IntoIter<h3::Header>, param: &'static str,
) -> std::result::Result<i32, ConnectRequestError> {
    if let Some(header) = headers.find(|h| h.name() == param.as_bytes()) {
        if let Ok(param_str) = String::from_utf8(header.value().to_vec()) {
            let param_int = param_str.parse::<i32>().map_err(|_| {
                ConnectRequestError::InvalidParam(param, header.value().to_vec())
            })?;
            Ok(param_int)
        } else {
            Err(ConnectRequestError::InvalidParam(
                param,
                header.value().to_vec(),
            ))
        }
    } else {
        Err(ConnectRequestError::MissingParam(param))
    }
}

fn validate_param(
    headers: &mut std::slice::Iter<h3::Header>, param: &'static str,
    expected: &'static str,
) -> std::result::Result<(), ConnectRequestError> {
    if let Some(method) = headers.find(|h| h.name() == param.as_bytes()) {
        if method.value() != expected.as_bytes() {
            Err(ConnectRequestError::ParamMismatch(
                param,
                expected,
                method.value().to_vec(),
            ))
        } else {
            Ok(())
        }
    } else {
        Err(ConnectRequestError::MissingParam(param))
    }
}

fn is_webtransport_request(
    list: &[h3::Header],
) -> std::result::Result<(), ConnectRequestError> {
    let mut headers = list.iter();
    validate_param(&mut headers, ":method", "CONNECT")?;
    validate_param(&mut headers, ":protocol", "webtransport")?;
    Ok(())
}

#[derive(Clone, Debug, PartialEq)]
enum ServerState {
    Init,
    Requested(u64),
    Connected(u64),
    Finished,
}

/// Represents an individual WebTransport session on the server side
pub struct ServerSession {
    h3_conn: h3::Connection,
    streams: HashMap<u64, StreamInfo>,
    state: ServerState,
}

impl ServerSession {
    fn new(h3_conn: h3::Connection) -> Self {
        Self {
            h3_conn,
            state: ServerState::Init,
            streams: HashMap::new(),
        }
    }

    /// Returns true if this session has accepted the CONNECT request.
    pub fn is_connected(&self) -> bool {
        matches!(self.state, ServerState::Connected(_))
    }

    /// Create a new WebTransport session using the provided QUIC connection.
    ///
    /// This includes the HTTP/3 handshake.
    ///
    /// On success the new session is returned.
    ///
    /// The [`StreamLimit`] error is returned when the HTTP/3 control stream
    /// cannot be created.
    /// The [`InvalidConfig`] error is returned when the 'dgram_enabled' option is not set as
    /// enabled.
    pub fn with_transport(conn: &mut Connection) -> Result<Self> {
        if !conn.dgram_enabled() {
            return Err(Error::InvalidConfig("dgram_enabled"));
        }
        let mut config = h3::Config::new().unwrap();
        config.set_enable_webtransport(true);
        let h3_conn = match h3::Connection::with_transport(conn, &config) {
            Ok(v) => v,
            Err(e) => return Err(e.into()),
        };
        Ok(Self::new(h3_conn))
    }

    /// Reads stream payload data into the provided buffer.
    ///
    /// Applications should call this method whenever the [`poll()`] method
    /// returns a [`StreamData`] event.
    ///
    /// On success the amount of bytes read is returned, or [`Done`] if there
    /// is no data to read.
    ///
    /// [`poll()`]: struct.ServerSession.html#method.poll
    /// [`StreamData`]: enum.ServerEvent.html#variant.StreamData
    /// [`Done`]: enum.Error.html#variant.Done
    pub fn recv_stream_data(
        &mut self, conn: &mut Connection, stream_id: u64, out: &mut [u8],
    ) -> Result<usize> {
        self.h3_conn
            .recv_webtransport_stream_data(conn, stream_id, out)
            .map_err(|e| e.into())
    }

    /// Reads a DATAGRAM into the provided buffer.
    ///
    /// Applications should call this method whenever the [`poll()`] method
    /// returns a [`Datagram`] event.
    ///
    /// If successful, data is packed into the slice passed
    /// as the argument and a tuple containing three values is returned.
    ///
    /// The first is a flag indicating whether this DATAGRAM is tied to the current session.
    /// The second is an offset value that points to where in the packed data the DATAGRAM payload starts.
    /// The third is a position that indicates the end of the payload.
    ///
    /// [`Done`] is returned if there is no data to read.
    ///
    /// [`BufferTooShort`] is returned if the provided buffer is too small for
    /// the data.
    ///
    /// [`poll()`]: struct.ServerSession.html#method.poll
    /// [`Datagram`]: enum.ServerEvent.html#variant.Datagram
    /// [`Done`]: enum.Error.html#variant.Done
    /// [`BufferTooShort`]: ../h3/enum.Error.html#variant.BufferTooShort
    pub fn recv_dgram(
        &mut self, conn: &mut Connection, buf: &mut [u8],
    ) -> Result<(bool, usize, usize)> {
        match self.h3_conn.recv_dgram(conn, buf) {
            Ok((len, quarter_session_id, session_id_len)) => match self.state {
                ServerState::Connected(sid) => {
                    let session_id = quarter_session_id * 4;
                    if sid == session_id {
                        Ok((true, session_id_len, len))
                    } else {
                        info!("The session_id included in Datagram frame doesn't match to current WebTransport session.");
                        Ok((false, session_id_len, len))
                    }
                },
                _ => Err(Error::InvalidState),
            },
            Err(e) => Err(e.into()),
        }
    }

    /// Processes WebTransport event received from the peer.
    ///
    /// On success it returns an [`Event`] and an ID, or [`Done`] when there are
    /// no events to report.
    ///
    /// Note that all events are edge-triggered, meaning that once reported they
    /// will not be reported again by calling this method again, until the event
    /// is re-armed.
    pub fn poll(&mut self, conn: &mut Connection) -> Result<ServerEvent> {
        match self.h3_conn.poll(conn) {
            Ok((stream_id, h3::Event::Headers { list, has_body: _ })) => {
                match find_request(&list) {
                    Ok(wt_req) => {
                        if self.state == ServerState::Init {
                            self.state = ServerState::Requested(stream_id);
                            Ok(ServerEvent::ConnectRequest(wt_req))
                        } else {
                            info!("A New WebTransport request is received while current state is not idle: {:?}", self.state);
                            let _ = self.reject_internal(
                                conn,
                                stream_id,
                                HTTP_STATUS_TOO_MANY_REQUESTS,
                                None,
                            );
                            Err(Error::UnexpectedMessage)
                        }
                    },
                    Err(e) => {
                        info!(
                            "This is a bad request to connect WebTransport: {:?}",
                            e
                        );
                        let _ = self.reject_internal(
                            conn,
                            stream_id,
                            HTTP_STATUS_BAD_REQUEST,
                            None,
                        );
                        Err(Error::UnexpectedMessage)
                    },
                }
            },

	    /// priority update available in 0.14.0
	    /// optional event implementation for webtransport
	    /// TBC A. Yasuda
	    Ok((_, PriorityUpdate)) => todo!(),
	    
            Ok((stream_id, h3::Event::WebTransportStreamData(session_id))) => {
                match self.state {
                    ServerState::Connected(sid) => {
                        if sid == session_id {
                            self.streams.entry(stream_id).or_insert_with(|| {
                                StreamInfo::new(stream_id, false)
                            });
                            Ok(ServerEvent::StreamData(stream_id))
                        } else {
                            info!("A WebTransport stream data received, but session_id does't match: {}", session_id);
                            Ok(ServerEvent::Other(
                                stream_id,
                                h3::Event::WebTransportStreamData(session_id),
                            ))
                        }
                    },
                    _ => Ok(ServerEvent::Other(
                        stream_id,
                        h3::Event::WebTransportStreamData(session_id),
                    )),
                }
            },

            Ok((stream_id, h3::Event::Data)) => {
                Ok(ServerEvent::Other(stream_id, h3::Event::Data))
            },

            Ok((stream_id, h3::Event::Finished)) => {
                if self.streams.contains_key(&stream_id) {
                    Ok(ServerEvent::StreamFinished(stream_id))
                } else {
                    match self.state {
                        ServerState::Requested(sid)
                        | ServerState::Connected(sid) => {
                            if sid == stream_id {
                                Ok(ServerEvent::SessionFinished)
                            } else {
                                info!("A stream 'finished' event received, but stream_id is unknown: {}", stream_id);
                                Ok(ServerEvent::Other(
                                    stream_id,
                                    h3::Event::Finished,
                                ))
                            }
                        },
                        _ => {
                            Ok(ServerEvent::Other(stream_id, h3::Event::Finished))
                        },
                    }
                }
            },

            Ok((stream_id, h3::Event::Reset(e))) => match self.state {
                ServerState::Requested(sid) | ServerState::Connected(sid) => {
                    if sid == stream_id {
                        Ok(ServerEvent::SessionReset(e))
                    } else {
                        info!("A stream 'reset' event received, but stream_id is unknown: {}", stream_id);
                        Ok(ServerEvent::Other(stream_id, h3::Event::Reset(e)))
                    }
                },
                _ => Ok(ServerEvent::Other(stream_id, h3::Event::Reset(e))),
            },

            Ok((session_id, h3::Event::Datagram)) => match self.state {
                ServerState::Connected(sid) => {
                    if sid == session_id {
                        Ok(ServerEvent::Datagram)
                    } else {
                        info!("A stream 'datagram' event received, but session_id is unknown: {}", session_id);
                        Ok(ServerEvent::Other(session_id, h3::Event::Datagram))
                    }
                },
                _ => Ok(ServerEvent::Other(session_id, h3::Event::Datagram)),
            },

            Ok((stream_id, h3::Event::GoAway)) => match self.state {
                ServerState::Requested(sid) | ServerState::Connected(sid) => {
                    if sid == stream_id {
                        Ok(ServerEvent::SessionGoAway)
                    } else {
                        info!("A stream 'goaway' event received, but stream_id is unknown: {}", stream_id);
                        Ok(ServerEvent::Other(stream_id, h3::Event::GoAway))
                    }
                },
                _ => Ok(ServerEvent::Other(stream_id, h3::Event::GoAway)),
            },

            Err(h3::Error::Done) => Err(Error::Done),

            Err(e) => Err(e.into()),
        }
    }

    /// Accepts clients' connect-request.
    /// After receiving a [`ConnectRequest`] from the client through [`poll()`],
    /// if you have verified its content and consider it valid,
    /// you execute this function to establish a WebTransport session.
    /// It sends a response to the client with a status code of 200.
    ///
    /// If there is any additional information you wish to add to the header, pass it in a HashMap.
    ///
    /// If this function is called without having received a [`ConnectRequest`] from the client,
    /// [`InvalidState`] will be returned.
    pub fn accept_connect_request(
        &mut self, conn: &mut Connection, extra_headers: Option<&[Header]>,
    ) -> Result<()> {
        match self.state {
            ServerState::Requested(session_id) => {
                let mut list = vec![
                    Header::new(b":status", b"200"),
                    Header::new(b"sec-webtransport-http3-draft", b"draft02"),
                ];
                if let Some(extra_headers) = extra_headers {
                    list.append(&mut extra_headers.to_vec());
                }
                let _ =
                    self.h3_conn.send_response(conn, session_id, &list, false)?;
                self.state = ServerState::Connected(session_id);
                Ok(())
            },
            _ => Err(Error::InvalidState),
        }
    }

    /// Reject client's connect-request.
    ///
    /// Call this function when you receive a [`ConnectRequest`] from a client through [`poll()`],
    /// verify its contents, and consider it invalid.
    /// The argument should be a status code in the 400 range.
    /// If there is any additional information you wish to add to the header, pass it in a HashMap.
    ///
    /// If this function is called without having received a [`ConnectRequest`] from the client,
    /// [`InvalidState`] will be returned.
    pub fn reject_connect_request(
        &mut self, conn: &mut Connection, code: u32,
        extra_headers: Option<&[Header]>,
    ) -> Result<()> {
        match self.state {
            ServerState::Requested(session_id) => {
                self.reject_internal(conn, session_id, code, extra_headers)?;
                Ok(())
            },
            _ => Err(Error::InvalidState),
        }
    }

    fn reject_internal(
        &mut self, conn: &mut Connection, stream_id: u64, code: u32,
        extra_headers: Option<&[Header]>,
    ) -> Result<()> {
        if code < 400 {
            return Err(Error::InvalidArg("code"));
        }
        let code = format!("{}", code).into_bytes();
        let mut list = vec![
            Header::new(b":status", &code),
            Header::new(b"sec-webtransport-http3-draft", b"draft02"),
        ];
        if let Some(extra_headers) = extra_headers {
            list.append(&mut extra_headers.to_vec());
        }
        if let Err(e) = self.h3_conn.send_response(conn, stream_id, &list, true) {
            warn!("Failed to send WebTransport reject response: {}", e);
        }
        self.state = ServerState::Finished;
        Ok(())
    }

    /// Open a server-initiated WebTransport stream.
    ///
    /// The parameters are the raw QUIC connection and a flag indicating
    /// whether the stream is bidirectional or not.
    /// This function should call after receiving a [`ConnectRequest``] from
    /// the client and accepting it with [`accept_connect_request()`].
    /// Otherwise, an [`InvalidState`] error will be returned.
    ///
    /// If successful, the ID of the stream representing new WebTransport Stream is returned.
    pub fn open_stream(
        &mut self, conn: &mut Connection, is_bidi: bool,
    ) -> Result<u64> {
        match self.state {
            ServerState::Connected(session_id) => {
                match self
                    .h3_conn
                    .open_webtransport_stream(conn, session_id, is_bidi)
                {
                    Ok(stream_id) => {
                        let stream = StreamInfo::new(stream_id, true);
                        self.streams.insert(stream_id, stream);
                        Ok(stream_id)
                    },

                    Err(e) => Err(e.into()),
                }
            },
            _ => Err(Error::InvalidState),
        }
    }

    /// Sends data through a WebTransport stream.
    ///
    /// Pass the ID of the corresponding stream and the byte sequence to be sent as arguments.
    /// If this method is called before the WebTransport session is
    /// established, an [`InvalidState`] will be returned.
    /// If you specify an unidirectional stream opened by the peer,
    /// [`InvalidStream`] will be returned.
    /// [`StreamNotFound`] is returned if the stream with the specified ID does not exist.
    ///
    /// Specify the ID of the bidirectional stream opened by the peer,
    /// or specify the ID of the stream you opened with [`open_stream()`].
    ///
    /// If successful, a number is returned representing the amount of data that could be sent.
    pub fn send_stream_data(
        &mut self, conn: &mut Connection, stream_id: u64, data: &[u8], fin: bool,
    ) -> Result<usize> {
        match self.state {
            ServerState::Connected(_session_id) => {
                match self.streams.get(&stream_id) {
                    Some(stream) => {
                        if !stream.is_bidi() && !stream.is_local() {
                            Err(Error::InvalidStream)
                        } else {

			    //let len = usize::MIN;//data.len();
			    //while len
                            let written =
                                conn.stream_send(stream_id, data, fin)?;
                            //let _w =
                            //    conn.stream_send(stream_id, b"", false)?;
                                //conn.stream_send(stream_id, data, true)?;
                            Ok(written)
                        }
                    },
                    None => Err(Error::StreamNotFound),
                }
            },
            _ => Err(Error::InvalidState),
        }
    }

    /// Send DATAGRAM.
    ///
    /// You can pass a sequence of bytes that you want to send,
    /// and it will be converted to the appropriate frame and sent.
    /// Call this function after the WebTransport session has been established.
    /// Otherwise, [`InvalidState`] will be returned.
    pub fn send_dgram(
        &mut self, conn: &mut Connection, data: &[u8],
    ) -> Result<()> {
        match self.state {
            ServerState::Connected(session_id) => {
                let quarter_session_id = session_id / 4;
                self.h3_conn.send_dgram(conn, quarter_session_id, data)?;
                Ok(())
            },
            _ => Err(Error::InvalidState),
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
enum ClientState {
    Init,
    PeerReady,
    Requesting(u64),
    Connected(u64),
}

/// Represents a WebTransport session on the client side
pub struct ClientSession {
    h3_conn: h3::Connection,
    streams: HashMap<u64, StreamInfo>,
    state: ClientState,
}

impl ClientSession {
    fn new(h3_conn: h3::Connection) -> Self {
        Self {
            h3_conn,
            streams: HashMap::new(),
            state: ClientState::Init,
        }
    }

    /// Returns true if this session got response for CONNECT request with OK status
    pub fn is_connected(&self) -> bool {
        matches!(self.state, ClientState::Connected(_))
    }

    /// Create a new WebTransport client using the provided QUIC connection.
    ///
    /// This includes the HTTP/3 handshake.
    ///
    /// On success the new session is returned.
    ///
    /// The [`StreamLimit`] error is returned when the HTTP/3 control stream
    /// cannot be created.
    pub fn with_transport(conn: &mut Connection) -> Result<Self> {
        if !conn.dgram_enabled() {
            return Err(Error::InvalidConfig("dgram_enabled"));
        }
        let mut config = h3::Config::new().unwrap();
        config.set_enable_webtransport(true);
        let h3_conn = match h3::Connection::with_transport(conn, &config) {
            Ok(v) => v,
            Err(e) => return Err(e.into()),
        };
        Ok(Self::new(h3_conn))
    }

    /// Sends a CONNECT request to the server to initiate a WebTransport session.
    ///
    /// The authority and path components in the URL are passed as arguments.
    /// The server information of the calling URL is also passed as the origin argument.
    /// Additional information can be passed as a HashMap to be included in the header.
    /// It is called immediately after initialization. Otherwise, [`InvalidState`] is returned.
    pub fn send_connect_request(
        &mut self, conn: &mut Connection, authority: &[u8], path: &[u8],
        origin: &[u8], extra_headers: Option<&[Header]>,
    ) -> Result<u64> {
        if self.state != ClientState::PeerReady {
            return Err(Error::InvalidState);
        }
        let mut req = vec![
            Header::new(b":method", b"CONNECT"),
            Header::new(b":scheme", b"https"),
            Header::new(b":protocol", b"webtransport"),
            Header::new(b"sec-webtransport-http3-draft02", b"1"),
            Header::new(b":authority", authority),
            Header::new(b":path", path),
            Header::new(b"origin", origin),
        ];
        if let Some(extra_headers) = extra_headers {
            req.append(&mut extra_headers.to_vec());
        }
        let stream_id = self.h3_conn.send_request(conn, &req, false)?;
        self.state = ClientState::Requesting(stream_id);

        Ok(stream_id)
    }

    /// Processes WebTransport event received from the peer.
    ///
    /// On success it returns an [`Event`] and an ID, or [`Done`] when there are
    /// no events to report.
    ///
    /// Note that all events are edge-triggered, meaning that once reported they
    /// will not be reported again by calling this method again, until the event
    /// is re-armed.
    pub fn poll(&mut self, conn: &mut Connection) -> Result<ClientEvent> {
        if self.state == ClientState::Init
            && self.h3_conn.webtransport_enabled_by_peer()
        {
            self.state = ClientState::PeerReady;
            return Ok(ClientEvent::PeerReady);
        }

        match self.h3_conn.poll(conn) {
            Ok((stream_id, h3::Event::Headers { list, has_body })) => {
                match self.state {
                    ClientState::Requesting(sid) => {
                        if sid == stream_id {
                            let mut headers = list.into_iter();
                            match find_integer_param(&mut headers, ":status") {
                                Ok(code) => {
                                    if (200..300).contains(&code) {
                                        self.state =
                                            ClientState::Connected(stream_id);
                                        Ok(ClientEvent::Connected)
                                    } else {
                                        Ok(ClientEvent::Rejected(code))
                                    }
                                },
                                Err(_e) => {
                                    debug!("header requires proper :status");
                                    Err(Error::UnexpectedMessage)
                                },
                            }
                        } else {
                            debug!("Headers event received with unknown stream_id: {}", stream_id);
                            Ok(ClientEvent::Other(
                                stream_id,
                                h3::Event::Headers { list, has_body },
                            ))
                        }
                    },
                    _ => {
                        debug!("Headers event received with stream_id: {}, while not requesting it.", stream_id);
                        Ok(ClientEvent::Other(
                            stream_id,
                            h3::Event::Headers { list, has_body },
                        ))
                    },
                }
            },

            Ok((stream_id, h3::Event::WebTransportStreamData(session_id))) => {
                match self.state {
                    ClientState::Connected(sid) => {
                        if sid == session_id {
                            self.streams.entry(stream_id).or_insert_with(|| {
                                StreamInfo::new(stream_id, false)
                            });
                            Ok(ClientEvent::StreamData(stream_id))
                        } else {
                            info!("A WebTransport stream data received, but session_id does't match: {}", session_id);
                            Ok(ClientEvent::Other(
                                stream_id,
                                h3::Event::WebTransportStreamData(session_id),
                            ))
                        }
                    },
                    _ => Ok(ClientEvent::Other(
                        stream_id,
                        h3::Event::WebTransportStreamData(session_id),
                    )),
                }
            },

            Ok((stream_id, h3::Event::Data)) => {
                Ok(ClientEvent::Other(stream_id, h3::Event::Data))
            },

            Ok((stream_id, h3::Event::Finished)) => {
                if self.streams.contains_key(&stream_id) {
                    Ok(ClientEvent::StreamFinished(stream_id))
                } else {
                    match self.state {
                        ClientState::Requesting(sid)
                        | ClientState::Connected(sid) => {
                            if sid == stream_id {
                                Ok(ClientEvent::SessionFinished)
                            } else {
                                info!("A stream 'finished' event received, but stream_id is unknown: {}", stream_id);
                                Ok(ClientEvent::Other(
                                    stream_id,
                                    h3::Event::Finished,
                                ))
                            }
                        },
                        _ => {
                            Ok(ClientEvent::Other(stream_id, h3::Event::Finished))
                        },
                    }
                }
            },

            Ok((stream_id, h3::Event::Reset(e))) => match self.state {
                ClientState::Requesting(sid) | ClientState::Connected(sid) => {
                    if sid == stream_id {
                        Ok(ClientEvent::SessionReset(e))
                    } else {
                        info!("A stream 'reset' event received, but stream_id is unknown: {}", stream_id);
                        Ok(ClientEvent::Other(stream_id, h3::Event::Reset(e)))
                    }
                },
                _ => Ok(ClientEvent::Other(stream_id, h3::Event::Reset(e))),
            },

            Ok((session_id, h3::Event::Datagram)) => match self.state {
                ClientState::Connected(sid) => {
                    if sid == session_id {
                        Ok(ClientEvent::Datagram)
                    } else {
                        info!("A stream 'datagram' event received, but session_id is unknown: {}", session_id);
                        Ok(ClientEvent::Other(session_id, h3::Event::Datagram))
                    }
                },
                _ => Ok(ClientEvent::Other(session_id, h3::Event::Datagram)),
            },

            Ok((stream_id, h3::Event::GoAway)) => match self.state {
                ClientState::Requesting(sid) | ClientState::Connected(sid) => {
                    if sid == stream_id {
                        Ok(ClientEvent::SessionGoAway)
                    } else {
                        info!("A stream 'goaway' event received, but stream_id is unknown: {}", stream_id);
                        Ok(ClientEvent::Other(stream_id, h3::Event::GoAway))
                    }
                },
                _ => Ok(ClientEvent::Other(stream_id, h3::Event::GoAway)),
            },

	    /// priority update available in 0.14.0
	    /// optional event implementation for webtransport
	    /// client request
	    /// TBC A. Yasuda
	    Ok((_, PriorityUpdate)) => todo!(),
	    
            Err(h3::Error::Done) => Err(Error::Done),

            Err(e) => Err(e.into()),
        }
    }

    /// Open a client-initiated WebTransport stream.
    ///
    /// The parameters are the raw QUIC connection and a flag indicating
    /// whether the stream is bidirectional or not.
    /// This function should call after receiving a [`ConnectRequest``] from
    /// the client and accepting it with [`accept_connect_request()`].
    /// Otherwise, an [`InvalidState`] error will be returned.
    ///
    /// If successful, the ID of the stream representing new WebTransport Stream is returned.
    pub fn open_stream(
        &mut self, conn: &mut Connection, is_bidi: bool,
    ) -> Result<u64> {
        match self.state {
            ClientState::Connected(session_id) => {
                match self
                    .h3_conn
                    .open_webtransport_stream(conn, session_id, is_bidi)
                {
                    Ok(stream_id) => {
                        let stream = StreamInfo::new(stream_id, true);
                        self.streams.insert(stream_id, stream);
                        Ok(stream_id)
                    },

                    Err(e) => Err(e.into()),
                }
            },
            _ => Err(Error::InvalidState),
        }
    }

    /// Sends data through a WebTransport stream.
    ///
    /// Pass the ID of the corresponding stream and the byte sequence to be sent as arguments.
    /// If this method is called before the WebTransport session is
    /// established, an [`InvalidState`] will be returned.
    /// If you specify an unidirectional stream opened by the peer,
    /// [`InvalidStream`] will be returned.
    /// [`StreamNotFound`] is returned if the stream with the specified ID does not exist.
    ///
    /// Specify the ID of the bidirectional stream opened by the peer,
    /// or specify the ID of the stream you opened with [`open_stream()`].
    ///
    /// If successful, a number is returned representing the amount of data that could be sent.
    pub fn send_stream_data(
        &mut self, conn: &mut Connection, stream_id: u64, data: &[u8], fin: bool,
    ) -> Result<usize> {
        match self.state {
            ClientState::Connected(_session_id) => {
                match self.streams.get_mut(&stream_id) {
                    Some(stream) => {
                        if !stream.is_bidi() && !stream.is_local() {
                            Err(Error::InvalidStream)
                        } else {
                            let written =
                                conn.stream_send(stream_id, data, fin)?;
                            Ok(written)
                        }
                    },
                    None => Err(Error::StreamNotFound),
                }
            },
            _ => Err(Error::InvalidState),
        }
    }

    /// Reads stream payload data into the provided buffer.
    ///
    /// Applications should call this method whenever the [`poll()`] method
    /// returns a [`StreamData`] event.
    ///
    /// On success the amount of bytes read is returned, or [`Done`] if there
    /// is no data to read.
    ///
    /// [`poll()`]: struct.ClientSession.html#method.poll
    /// [`StreamData`]: enum.ClientEvent.html#variant.StreamData
    /// [`Done`]: enum.Error.html#variant.Done
    pub fn recv_stream_data(
        &mut self, conn: &mut Connection, stream_id: u64, out: &mut [u8],
    ) -> Result<usize> {
        self.h3_conn
            .recv_webtransport_stream_data(conn, stream_id, out)
            .map_err(|e| e.into())
    }

    /// Reads a DATAGRAM into the provided buffer.
    ///
    /// Applications should call this method whenever the [`poll()`] method
    /// returns a [`Datagram`] event.
    ///
    /// If successful, data is packed into the slice passed
    /// as the argument and a tuple containing three values is returned.
    ///
    /// The first is a flag indicating whether this DATAGRAM is tied to the current session.
    /// The second is an offset value that points to where in the packed data the DATAGRAM payload starts.
    /// The third is a position that indicates the end of the payload.
    ///
    /// [`Done`] is returned if there is no data to read.
    ///
    /// [`BufferTooShort`] is returned if the provided buffer is too small for
    /// the data.
    ///
    /// [`poll()`]: struct.ClientSession.html#method.poll
    /// [`Datagram`]: enum.ClientEvent.html#variant.Datagram
    /// [`Done`]: enum.Error.html#variant.Done
    /// [`BufferTooShort`]: ../h3/enum.Error.html#variant.BufferTooShort
    pub fn recv_dgram(
        &mut self, conn: &mut Connection, buf: &mut [u8],
    ) -> Result<(bool, usize, usize)> {
        match self.h3_conn.recv_dgram(conn, buf) {
            Ok((len, quarter_session_id, session_id_len)) => match self.state {
                ClientState::Connected(sid) => {
                    let session_id = quarter_session_id * 4;
                    if sid == session_id {
                        Ok((true, session_id_len, len))
                    } else {
                        info!("The session_id included in Datagram frame doesn't match to current WebTransport session.");
                        Ok((false, session_id_len, len))
                    }
                },
                _ => Err(Error::InvalidState),
            },
            Err(e) => Err(e.into()),
        }
    }

    /// Send DATAGRAM.
    ///
    /// You can pass a sequence of bytes that you want to send,
    /// and it will be converted to the appropriate frame and sent.
    /// Call this function after the WebTransport session has been established.
    /// Otherwise, [`InvalidState`] will be returned.
    pub fn send_dgram(
        &mut self, conn: &mut Connection, data: &[u8],
    ) -> Result<()> {
        match self.state {
            ClientState::Connected(session_id) => {
                let quarter_session_id = session_id / 4;
                self.h3_conn.send_dgram(conn, quarter_session_id, data)?;
                Ok(())
            },
            _ => Err(Error::InvalidState),
        }
    }
}

#[doc(hidden)]
pub mod testing {
    use super::*;
    use crate::testing;

    pub struct Session {
        pub pipe: testing::Pipe,
        pub client: ClientSession,
        pub server: ServerSession,
    }

    impl Session {
        pub fn default() -> Result<Session> {
            let mut config = crate::Config::new(crate::PROTOCOL_VERSION)?;
            config.load_cert_chain_from_pem_file("examples/cert.crt")?;
            config.load_priv_key_from_pem_file("examples/cert.key")?;
            //config.set_application_protos(b"\x02h3")?;
            config.set_application_protos(&[b"\x02h3"])?;
            config.set_initial_max_data(1500);
            config.set_initial_max_stream_data_bidi_local(150);
            config.set_initial_max_stream_data_bidi_remote(150);
            config.set_initial_max_stream_data_uni(150);
            config.set_initial_max_streams_bidi(5);
            config.set_initial_max_streams_uni(5);
            config.verify_peer(false);
            config.enable_dgram(true, 3, 3);
            config.set_ack_delay_exponent(8);

            let mut h3_config = crate::h3::Config::new()?;
            h3_config.set_enable_webtransport(true);
            Session::with_configs(&mut config, &h3_config)
        }

        pub fn with_configs(
            config: &mut crate::Config, h3_config: &crate::h3::Config,
        ) -> Result<Session> {
            let pipe = testing::Pipe::with_config(config)?;
            let client_dgram = pipe.client.dgram_enabled();
            let server_dgram = pipe.server.dgram_enabled();
            let client_conn =
                crate::h3::Connection::new(h3_config, false, client_dgram)?;
            let server_conn =
                crate::h3::Connection::new(h3_config, true, server_dgram)?;
            Ok(Session {
                pipe,
                client: ClientSession::new(client_conn),
                server: ServerSession::new(server_conn),
            })
        }

        pub fn handshake(&mut self) -> Result<()> {
            self.pipe.handshake()?;

            // Client streams.
            self.client.h3_conn.send_settings(&mut self.pipe.client)?;
            self.pipe.advance().ok();

            self.client
                .h3_conn
                .open_qpack_encoder_stream(&mut self.pipe.client)?;
            self.pipe.advance().ok();

            self.client
                .h3_conn
                .open_qpack_decoder_stream(&mut self.pipe.client)?;
            self.pipe.advance().ok();

            if self.pipe.client.grease {
                self.client
                    .h3_conn
                    .open_grease_stream(&mut self.pipe.client)?;
            }

            self.pipe.advance().ok();

            // Server streams.
            self.server.h3_conn.send_settings(&mut self.pipe.server)?;
            self.pipe.advance().ok();

            self.server
                .h3_conn
                .open_qpack_encoder_stream(&mut self.pipe.server)?;
            self.pipe.advance().ok();

            self.server
                .h3_conn
                .open_qpack_decoder_stream(&mut self.pipe.server)?;
            self.pipe.advance().ok();

            if self.pipe.server.grease {
                self.server
                    .h3_conn
                    .open_grease_stream(&mut self.pipe.server)?;
            }

            self.advance().ok();

            while self.client.poll(&mut self.pipe.client).is_ok() {
                // Do nothing.
            }

            while self.server.poll(&mut self.pipe.server).is_ok() {
                // Do nothing.
            }

            Ok(())
        }

        /// Advances the session pipe over the buffer.
        pub fn advance(&mut self) -> crate::Result<()> {
            self.pipe.advance()
        }

        /// Polls the client for events.
        pub fn poll_client(&mut self) -> Result<ClientEvent> {
            self.client.poll(&mut self.pipe.client)
        }

        /// Polls the server for events.
        pub fn poll_server(&mut self) -> Result<ServerEvent> {
            self.server.poll(&mut self.pipe.server)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::testing::*;
    use super::*;

    fn complete_webtransport_handshake() -> testing::Session {
        let mut s = Session::default().unwrap();
        s.handshake().unwrap();

        // To make sure that server supports WebTransport,
        // wait server's SETTING frame including enable_webtransport flag.
        assert_eq!(s.poll_client(), Ok(ClientEvent::PeerReady));
        assert_eq!(s.poll_client(), Err(Error::Done));

        let _ = s
            .client
            .send_connect_request(
                &mut s.pipe.client,
                b"authority.quic.tech:1234",
                b"/path",
                b"origin.quic.tech",
                None,
            )
            .unwrap();

        s.advance().ok();

        let req = ConnectRequest::new(
            "authority.quic.tech:1234".to_string(),
            "/path".to_string(),
            "origin.quic.tech".to_string(),
        );

        assert_eq!(s.poll_server(), Ok(ServerEvent::ConnectRequest(req)));
        assert_eq!(s.poll_server(), Err(Error::Done));

        s.server
            .accept_connect_request(&mut s.pipe.server, None)
            .ok();

        s.advance().ok();

        assert_eq!(s.poll_client(), Ok(ClientEvent::Connected));
        assert_eq!(s.poll_client(), Err(Error::Done));

        s
    }

    #[test]
    fn accept_connect_request() {
        complete_webtransport_handshake();
    }

    #[test]
    fn reject_connect_request() {
        let mut s = Session::default().unwrap();
        s.handshake().unwrap();

        // To make sure that server supports WebTransport,
        // wait server's SETTING frame including enable_webtransport flag.
        assert_eq!(s.poll_client(), Ok(ClientEvent::PeerReady));
        assert_eq!(s.poll_client(), Err(Error::Done));

        let _session_id = s
            .client
            .send_connect_request(
                &mut s.pipe.client,
                b"authority.quic.tech:1234",
                b"/path",
                b"origin.quic.tech",
                None,
            )
            .unwrap();

        s.advance().ok();

        let req = ConnectRequest::new(
            "authority.quic.tech:1234".to_string(),
            "/path".to_string(),
            "origin.quic.tech".to_string(),
        );

        assert_eq!(s.poll_server(), Ok(ServerEvent::ConnectRequest(req)));
        assert_eq!(s.poll_server(), Err(Error::Done));

        s.server
            .reject_connect_request(&mut s.pipe.server, 401, None)
            .ok();

        s.advance().ok();

        assert_eq!(s.poll_client(), Ok(ClientEvent::Rejected(401)));
        assert_eq!(s.poll_client(), Ok(ClientEvent::SessionFinished));
        assert_eq!(s.poll_client(), Err(Error::Done));
    }

    #[test]
    fn unidirectional_stream() {
        let mut s = complete_webtransport_handshake();

        let initial_client_uni_stream = 18;

        // client open uni-directional stream
        assert_eq!(
            s.client.open_stream(&mut s.pipe.client, false),
            Ok(initial_client_uni_stream)
        );
        // and send data through the stream
        let data_to_be_sent = b"Hello, WebTransport";

        s.client
            .send_stream_data(
                &mut s.pipe.client,
                initial_client_uni_stream,
                data_to_be_sent,
		true,
            )
            .ok();

        s.advance().ok();

        assert_eq!(
            s.poll_server(),
            Ok(ServerEvent::StreamData(initial_client_uni_stream))
        );

        let mut buf = vec![0; 1000];
        assert_eq!(
            s.server.recv_stream_data(
                &mut s.pipe.server,
                initial_client_uni_stream,
                &mut buf
            ),
            Ok(19)
        );
        assert_eq!(data_to_be_sent, &buf[0..19]);

        assert_eq!(s.poll_server(), Err(Error::Done));

        // server cant send data through client-initiated uni-stream.
        assert_eq!(
            s.server.send_stream_data(
                &mut s.pipe.server,
                initial_client_uni_stream,
                data_to_be_sent,
		true,
            ),
            Err(Error::InvalidStream)
        );

        let initial_server_uni_stream = 19;

        assert_eq!(
            s.server.open_stream(&mut s.pipe.server, false),
            Ok(initial_server_uni_stream)
        );

        s.server
            .send_stream_data(
                &mut s.pipe.server,
                initial_server_uni_stream,
                data_to_be_sent,
		true,
            )
            .ok();

        s.advance().ok();

        assert_eq!(
            s.poll_client(),
            Ok(ClientEvent::StreamData(initial_server_uni_stream))
        );

        assert_eq!(
            s.client.recv_stream_data(
                &mut s.pipe.client,
                initial_server_uni_stream,
                &mut buf
            ),
            Ok(19)
        );

        assert_eq!(data_to_be_sent, &buf[0..19]);

        assert_eq!(s.poll_client(), Err(Error::Done));

        // client cant send data through server-initiated uni-stream.
        assert_eq!(
            s.client.send_stream_data(
                &mut s.pipe.client,
                initial_server_uni_stream,
                data_to_be_sent,
		true,
            ),
            Err(Error::InvalidStream)
        );
    }

    #[test]
    fn client_initiated_bidirectional_stream() {
        let mut s = complete_webtransport_handshake();

        let initial_client_bidi_stream = 4;

        // client open uni-directional stream
        assert_eq!(
            s.client.open_stream(&mut s.pipe.client, true),
            Ok(initial_client_bidi_stream)
        );

        let data_to_be_sent = b"Hello, WebTransport from client";

        s.client
            .send_stream_data(
                &mut s.pipe.client,
                initial_client_bidi_stream,
                data_to_be_sent,
		true,
            )
            .ok();

        s.advance().ok();

        assert_eq!(
            s.poll_server(),
            Ok(ServerEvent::StreamData(initial_client_bidi_stream))
        );

        let mut buf = vec![0; 1000];
        assert_eq!(
            s.server.recv_stream_data(
                &mut s.pipe.server,
                initial_client_bidi_stream,
                &mut buf
            ),
            Ok(31)
        );
        assert_eq!(data_to_be_sent, &buf[0..31]);

        assert_eq!(s.poll_server(), Err(Error::Done));

        let data_to_be_sent = b"Hello, WebTransport from server";

        // server can send data through client-initiated bidi-stream.
        s.server
            .send_stream_data(
                &mut s.pipe.server,
                initial_client_bidi_stream,
                data_to_be_sent,
		true,
            )
            .ok();

        s.advance().ok();

        assert_eq!(
            s.poll_client(),
            Ok(ClientEvent::StreamData(initial_client_bidi_stream))
        );

        assert_eq!(
            s.client.recv_stream_data(
                &mut s.pipe.client,
                initial_client_bidi_stream,
                &mut buf
            ),
            Ok(31)
        );

        assert_eq!(data_to_be_sent, &buf[0..31]);

        assert_eq!(s.poll_client(), Err(Error::Done));
    }

    #[test]
    fn server_initiated_bidirectional_stream() {
        let mut s = complete_webtransport_handshake();

        let initial_server_bidi_stream = 1;

        // client open uni-directional stream
        assert_eq!(
            s.server.open_stream(&mut s.pipe.server, true),
            Ok(initial_server_bidi_stream)
        );

        let data_to_be_sent = b"Hello, WebTransport from server";

        s.server
            .send_stream_data(
                &mut s.pipe.server,
                initial_server_bidi_stream,
                data_to_be_sent,
		true,
            )
            .ok();

        s.advance().ok();

        assert_eq!(
            s.poll_client(),
            Ok(ClientEvent::StreamData(initial_server_bidi_stream))
        );

        let mut buf = vec![0; 1000];
        assert_eq!(
            s.client.recv_stream_data(
                &mut s.pipe.client,
                initial_server_bidi_stream,
                &mut buf
            ),
            Ok(31)
        );
        assert_eq!(data_to_be_sent, &buf[0..31]);

        assert_eq!(s.poll_client(), Err(Error::Done));

        let data_to_be_sent = b"Hello, WebTransport from client";

        // server can send data through client-initiated bidi-stream.
        s.client
            .send_stream_data(
                &mut s.pipe.client,
                initial_server_bidi_stream,
                data_to_be_sent,
		true,
            )
            .ok();

        s.advance().ok();

        assert_eq!(
            s.poll_server(),
            Ok(ServerEvent::StreamData(initial_server_bidi_stream))
        );

        assert_eq!(
            s.server.recv_stream_data(
                &mut s.pipe.server,
                initial_server_bidi_stream,
                &mut buf
            ),
            Ok(31)
        );

        assert_eq!(data_to_be_sent, &buf[0..31]);

        assert_eq!(s.poll_server(), Err(Error::Done));
    }

    #[test]
    fn datagram() {
        let mut s = complete_webtransport_handshake();

        let data_to_be_sent = b"Hello, WebTransport from client";

        s.client
            .send_dgram(&mut s.pipe.client, data_to_be_sent)
            .ok();

        s.advance().ok();

        assert_eq!(s.poll_server(), Ok(ServerEvent::Datagram));

        let mut buf = vec![0; 1500];

        assert_eq!(
            s.server.recv_dgram(&mut s.pipe.server, &mut buf),
            Ok((true, 1, 32))
        );

        assert_eq!(data_to_be_sent, &buf[1..32]);

        assert_eq!(s.poll_server(), Err(Error::Done));

        let data_to_be_sent = b"Hello, WebTransport from server";

        s.server
            .send_dgram(&mut s.pipe.server, data_to_be_sent)
            .ok();

        s.advance().ok();

        assert_eq!(s.poll_client(), Ok(ClientEvent::Datagram));

        assert_eq!(
            s.client.recv_dgram(&mut s.pipe.client, &mut buf),
            Ok((true, 1, 32))
        );

        assert_eq!(data_to_be_sent, &buf[1..32]);

        assert_eq!(s.poll_client(), Err(Error::Done));
    }
}

pub mod ffi;
