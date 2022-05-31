use std::{net::SocketAddr, path::PathBuf, sync::Arc};

use bytes::{Bytes, BytesMut};
use futures::StreamExt;
use http::{Request, StatusCode};
use rustls::{Certificate, PrivateKey};
use structopt::StructOpt;
use tokio::{fs::File, io::AsyncReadExt};
use tracing::{debug, error, info, trace_span, warn};

use h3::{quic::BidiStream, server::RequestStream};

#[derive(StructOpt, Debug)]
#[structopt(name = "server")]
struct Opt {
    #[structopt(
        name = "dir",
        short,
        long,
        help = "Root directory of the files to serve. \
                If omitted, server will respond OK."
    )]
    pub root: Option<PathBuf>,

    #[structopt(
        short,
        long,
        default_value = "[::1]:4433",
        help = "What address:port to listen for new connections"
    )]
    pub listen: SocketAddr,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_span_events(tracing_subscriber::fmt::format::FmtSpan::FULL)
        .with_writer(std::io::stderr)
        .init();
    
    let opt = Opt::from_args();

    let root = if let Some(root) = opt.root {
        if !root.is_dir() {
            return Err(format!("{}: is not a readable directory", root.display()).into());
        } else {
            info!("serving {}", root.display());
            Arc::new(Some(root))
        }
    } else {
        Arc::new(None)
    };

    let crypto = load_crypto("cert.der".into(), "client.key".into()).await?;
    let server_config = h3_quinn::quinn::ServerConfig::with_crypto(Arc::new(crypto));
    let (endpoint, mut incoming) = h3_quinn::quinn::Endpoint::server(server_config, opt.listen)?;

    info!("Listening on {}", opt.listen);

    while let Some(new_conn) = incoming.next().await {
        trace_span!("New connection being attempted");

        let root = root.clone();
        tokio::spawn(async move {
            match new_conn.await {
                Ok(conn) => {
                    debug!("New connection now established");

                    let mut h3_conn = h3::server::Connection::new(h3_quinn::Connection::new(conn))
                        .await
                        .unwrap();
                    
                    while let Some((req, stream)) = h3_conn.accept().await.unwrap() {
                        let root = root.clone();
                        debug!("New request: {:#?}", req);

                        tokio::spawn(async {
                            if let Err(e) = handle_request(req, stream, root).await {
                                error!("request failed: {}", e);
                            }
                        });
                    }
                }
                Err(err) => {
                    warn!("accepting connection failed: {:?}", err);
                }
            }
        });
    }

    endpoint.wait_idle().await;

    Ok(())
}

async fn handle_request<T>(
    req: Request<()>,
    mut stream: RequestStream<T, Bytes>,
    serve_root: Arc<Option<PathBuf>>,
) -> Result<(), Box<dyn std::error::Error>>
where
    T: BidiStream<Bytes>,
{
    let (status, to_serve) = match serve_root.as_deref() {
        None => (StatusCode::OK, None),
        Some(_) if req.uri().path().contains("..") => (StatusCode::NOT_FOUND, None),
        
    }
}

static ALPN: &[u8] = b"h3";

async fn load_crypto(cert_path: PathBuf, key_path: PathBuf) -> Result<rustls::ServerConfig, Box<dyn std::error::Error>> {
    let mut cert_v = Vec::new();
    let mut key_v = Vec::new();

    let mut cert_f = File::open(cert_path).await?;
    let mut key_f = File::open(key_path).await?;

    cert_f.read_to_end(&mut cert_v).await?;
    key_f.read_to_end(&mut key_v).await?;
    let (cert, key) = (Certificate(cert_v), PrivateKey(key_v));

    let mut crypto = rustls::ServerConfig::builder()
        .with_safe_default_cipher_suites()
        .with_safe_default_kx_groups()
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)?;
    
    crypto.max_early_data_size = u32::MAX;
    crypto.alpn_protocols = vec![ALPN.into()];
        Ok(crypto)
}