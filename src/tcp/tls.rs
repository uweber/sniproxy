use std::{
    io::{BufWriter, Write},
    net::{SocketAddr, TcpStream},
    sync::Arc,
    time::Duration,
};

use anyhow::{bail, Result};
use log::debug;

use crate::{
    config::{self, Config},
    context, http, proxy_protocol,
    reader::ReaderBuf,
    tls::{self, Tls},
};

fn extract_ip_string(addr: SocketAddr) -> String {
    match addr {
        SocketAddr::V6(v6) => {
            if let Some(ipv4) = v6.ip().to_ipv4() {
                ipv4.to_string()
            } else {
                v6.ip().to_string()
            }
        }
        SocketAddr::V4(v4) => v4.ip().to_string(),
    }
}

/// Handle TCP/TLS connections.
pub(crate) async fn handle_stream(config: Arc<Config>, stream: TcpStream) -> Result<()> {
    let mut rb = ReaderBuf::with_capacity(tls::RECORD_MAX_LEN, stream);

    // Start by checking we got a valid TLS message, and if true parse it.
    let tls = match Tls::from(&mut rb) {
        Ok(tls) => tls,
        Err(e) => {
            // If this looks like an HTTP request, try to redirect it.
            // Luckily http::is_http needs 5 bytes in the buffer and the
            // minimal TLS parsing reads 5 bytes.
            if http::is_http(&rb) {
                return http::try_redirect(&config, &context::peer_addr()?, &mut rb);
            }

            tls::alert(rb.get_mut(), tls::AlertDescription::InternalError)?;
            bail!("Could not parse TLS message: {e}");
        }
    };

    // Retrieve the SNI hostname.
    let local_ip = &extract_ip_string(context::local_addr()?);

    let hostname = match tls.hostname() {
        Some(name) => {
            debug!("Found SNI {name} in TLS handshake");
            name
        }
        None => {
            debug!("No SNI found in TLS handshake, using IP address {local_ip}");
            local_ip
        }
    };
    context::set_hostname(hostname)?;

    let peer = &context::peer_addr()?;
    let backend = config
        .get_backend(hostname, peer, tls.is_challenge())
        .or_else(|e| match e.downcast() {
            Ok(e) => match e {
                config::Error::HostnameNotFound => {
                    tls::alert(rb.get_mut(), tls::AlertDescription::UnrecognizedName)?;
                    bail!("No route found for '{hostname}'")
                }
                config::Error::NoBackend => {
                    tls::alert(rb.get_mut(), tls::AlertDescription::AccessDenied)?;
                    bail!("No backend defined for '{hostname}'")
                }
                config::Error::AccessDenied => {
                    tls::alert(rb.get_mut(), tls::AlertDescription::AccessDenied)?;
                    bail!("Request from {peer} for '{hostname}' was denied by ACLs")
                }
            },
            Err(e) => bail!(e),
        })?;
    debug!(
        "Using backend {:?} (is alpn challenge? {})",
        backend.to_socket_addr(),
        tls.is_challenge(),
    );

    // Connect to the backend.
    let conn = match TcpStream::connect_timeout(&backend.to_socket_addr()?, Duration::from_secs(3))
    {
        Ok(conn) => conn,
        Err(e) => {
            tls::alert(rb.get_mut(), tls::AlertDescription::InternalError)?;
            bail!("Could not connect to backend '{}': {e}", &backend.address);
        }
    };

    // Use a buffered writer to avoid small writes until we start forwarding the
    // data.
    let mut bw = BufWriter::new(conn);

    // Send an HAProxy protocol header if needed.
    if let Some(version) = backend.proxy_protocol {
        proxy_protocol::write_header(&mut bw, version, &context::local_addr()?, peer)?;
    }

    // Replay the handshake.
    bw.write_all(rb.buf())?;

    // We can now flush the buffered writer and stop using it to avoid adding
    // buffering in the middle of the connection.
    let mut conn = bw.into_inner()?;

    // Do not use read & write timeouts for proxying.
    if let Err(e) = conn.set_read_timeout(None) {
        tls::alert(&mut conn, tls::AlertDescription::InternalError)?;
        bail!("Could not unset the read timeout on TCP stream: {e}");
    }
    if let Err(e) = conn.set_write_timeout(None) {
        tls::alert(&mut conn, tls::AlertDescription::InternalError)?;
        bail!("Could not unset the write timeout on TCP stream: {e}");
    }

    super::tcp::proxy(rb.into_inner(), conn).await?;
    Ok(())
}
