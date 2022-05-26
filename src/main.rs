use std::sync::Arc;

use rustls::{self};
use structopt::StructOpt;
use tokio::{self};

static ALPN: &[u8] = b"h3";

#[derive(StructOpt, Debug)]
#[structopt(name = "server")]
struct Opt {
    #[structopt()]
    pub uri: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_span_events(tracing_subscriber::fmt::format::FmtSpan::FULL)
        .with_writer(std::io::stderr)
        .init();

    let opt = Opt::from_args();

    let dest = opt.uri.parse::<http::Uri>()?;

    if dest.scheme() != Some(&http::uri::Scheme::HTTPS) {
        Err("destination scheme must be 'https'")?;
    }

    let auth = dest
        .authority()
        .ok_or("destination must have a host")?
        .clone();

    let port = auth.port_u16().unwrap_or(443);

    // dns me! // TODO: iter
    let addr = tokio::net::lookup_host((auth.host(), port))
        .await?
        .next()
        .ok_or("dns found no addresses")?;

    eprintln!("DNS Lookup for {:?}: {:?}", dest, addr);

    let tls_config_builder = rustls::ClientConfig::builder()
        .with_safe_default_cipher_suites()
        .with_safe_default_kx_groups()
        .with_protocol_versions(&[&rustls::version::TLS13])?;
    let mut tls_config = {
        let mut roots = rustls::RootCertStore::empty();
        match rustls_native_certs::load_native_certs() {
            Ok(certs) => {
                for cert in certs {
                    if let Err(e) = roots.add(&rustls::Certificate(cert.0)) {
                        eprintln!("failed to parse trust anchor: {}", e);
                    }
                }
            }
            Err(e) => {
                eprintln!("coundn't load any default trust roots: {}", e);
            }
        }
        tls_config_builder
            .with_root_certificates(roots)
            .with_no_client_auth()
    };
    tls_config.enable_early_data = true;
    tls_config.alpn_protocols = vec![ALPN.into()];
    let client_config = quinn::ClientConfig::new(Arc::new(tls_config));

    let mut client_endpoint = h3_quinn::quinn::Endpoint::client("[::]:0".parse().unwrap())?;
    client_endpoint.set_default_client_config(client_config);
    let quinn_conn = h3_quinn::Connection::new(client_endpoint.connect(addr, auth.host())?.await?);

    eprintln!("QUIC connected ...");

    Ok(())
}