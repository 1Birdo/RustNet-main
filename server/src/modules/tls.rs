// TLS encryption support for secure CnC communications
use tokio::net::TcpStream;
use tokio_rustls::{TlsAcceptor, rustls, server::TlsStream};
use std::sync::Arc;
use std::path::Path;
use super::error::{CncError, Result};

/// Load TLS certificate and private key from PEM files
#[allow(dead_code)]
pub async fn load_tls_config(cert_path: &str, key_path: &str) -> Result<Arc<rustls::ServerConfig>> {
    // Read certificate file
    let cert_bytes = tokio::fs::read(cert_path).await
        .map_err(|e| CncError::ConfigError(format!("Failed to read certificate: {}", e)))?;
    
    // Read private key file
    let key_bytes = tokio::fs::read(key_path).await
        .map_err(|e| CncError::ConfigError(format!("Failed to read private key: {}", e)))?;
    
    // Parse certificates
    let certs = rustls_pemfile::certs(&mut &cert_bytes[..])
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|e| CncError::ConfigError(format!("Failed to parse certificate: {}", e)))?;
    
    // Parse private key
    let key = rustls_pemfile::private_key(&mut &key_bytes[..])
        .map_err(|e| CncError::ConfigError(format!("Failed to parse private key: {}", e)))?
        .ok_or_else(|| CncError::ConfigError("No private key found in file".to_string()))?;
    
    // Create server config
    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| CncError::ConfigError(format!("Failed to create TLS config: {}", e)))?;
    
    Ok(Arc::new(config))
}

/// Create a TLS acceptor from server config
#[allow(dead_code)]
pub fn create_tls_acceptor(config: Arc<rustls::ServerConfig>) -> TlsAcceptor {
    TlsAcceptor::from(config)
}

/// Accept a TLS connection
#[allow(dead_code)]
pub async fn accept_tls_connection(
    acceptor: &TlsAcceptor,
    stream: TcpStream,
) -> Result<TlsStream<TcpStream>> {
    acceptor.accept(stream).await
        .map_err(|e| CncError::ConfigError(format!("TLS handshake failed: {}", e)))
}

/// Generate self-signed certificate for testing/development
/// For production, use proper CA-signed certificates
pub fn generate_self_signed_cert() -> Result<(Vec<u8>, Vec<u8>)> {
    use rcgen::{CertificateParams, KeyPair};
    use time::OffsetDateTime;
    
    let mut params = CertificateParams::default();
    params.not_before = OffsetDateTime::now_utc();
    params.not_after = OffsetDateTime::now_utc() + time::Duration::days(365);
    params.distinguished_name.push(
        rcgen::DnType::CommonName,
        "RustNet CnC Server"
    );
    params.subject_alt_names = vec![
        rcgen::SanType::DnsName("localhost".to_string()),
        rcgen::SanType::IpAddress(std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1))),
    ];
    
    let key_pair = KeyPair::generate(&rcgen::PKCS_ECDSA_P256_SHA256)
        .map_err(|e| CncError::ConfigError(format!("Failed to generate key pair: {}", e)))?;
    
    params.key_pair = Some(key_pair);
    
    let cert = rcgen::Certificate::from_params(params)
        .map_err(|e| CncError::ConfigError(format!("Failed to generate certificate: {}", e)))?;
    
    let cert_pem = cert.serialize_pem()
        .map_err(|e| CncError::ConfigError(format!("Failed to serialize certificate: {}", e)))?
        .into_bytes();
    let key_pem = cert.serialize_private_key_pem().into_bytes();
    
    Ok((cert_pem, key_pem))
}

/// Save certificate and key to files
#[allow(dead_code)]
pub async fn save_certificate(
    cert_pem: &[u8],
    key_pem: &[u8],
    cert_path: &str,
    key_path: &str,
) -> Result<()> {
    tokio::fs::write(cert_path, cert_pem).await
        .map_err(|e| CncError::ConfigError(format!("Failed to write certificate: {}", e)))?;
    
    tokio::fs::write(key_path, key_pem).await
        .map_err(|e| CncError::ConfigError(format!("Failed to write key: {}", e)))?;
    
    Ok(())
}

/// Setup TLS for the server - generates or loads certificates
#[allow(dead_code)]
pub async fn setup_tls(cert_path: &str, key_path: &str, strict_mode: bool) -> Result<TlsAcceptor> {
    // Check if certificate files exist
    if !Path::new(cert_path).exists() || !Path::new(key_path).exists() {
        if strict_mode {
            return Err(CncError::ConfigError(
                format!("TLS certificates not found at {} / {}. Strict mode is enabled, refusing to generate self-signed certs.", cert_path, key_path)
            ));
        }

        tracing::warn!("TLS certificates not found, generating self-signed certificate...");
        tracing::warn!("⚠️  For production use, replace with CA-signed certificates!");
        
        let (cert_pem, key_pem) = generate_self_signed_cert()?;
        save_certificate(&cert_pem, &key_pem, cert_path, key_path).await?;
        
        tracing::info!("✓ Self-signed certificate generated at {}", cert_path);
    }
    
    let config = load_tls_config(cert_path, key_path).await?;
    Ok(create_tls_acceptor(config))
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_generate_self_signed_cert() {
        let result = generate_self_signed_cert();
        assert!(result.is_ok());
        
        if let Ok((cert_pem, key_pem)) = result {
            assert!(!cert_pem.is_empty());
            assert!(!key_pem.is_empty());
        }
    }
}
