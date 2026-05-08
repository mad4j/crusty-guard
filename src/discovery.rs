use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

use crate::CliError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveryReport {
    pub target: String,
    pub scanned_ports: Vec<u16>,
    pub services: Vec<DiscoveredService>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveredService {
    pub port: u16,
    pub protocol: &'static str,
    pub service_name: Option<&'static str>,
}

pub fn discover(host: &str, ports: &[u16], timeout_ms: u64) -> Result<DiscoveryReport, CliError> {
    let timeout = Duration::from_millis(timeout_ms);
    let mut services = Vec::new();

    for port in ports {
        let address = format!("{host}:{port}")
            .to_socket_addrs()
            .map_err(|error| CliError::new(format!("failed to resolve {host}:{port}: {error}")))?
            .next()
            .ok_or_else(|| CliError::new(format!("failed to resolve {host}:{port}")))?;

        if TcpStream::connect_timeout(&address, timeout).is_ok() {
            services.push(DiscoveredService {
                port: *port,
                protocol: "tcp",
                service_name: known_service_name(*port),
            });
        }
    }

    Ok(DiscoveryReport {
        target: host.to_string(),
        scanned_ports: ports.to_vec(),
        services,
    })
}

fn known_service_name(port: u16) -> Option<&'static str> {
    match port {
        79 => Some("finger"),
        22 => Some("ssh"),
        80 => Some("http"),
        443 => Some("https"),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use std::net::TcpListener;

    use super::discover;

    #[test]
    fn discover_reports_open_tcp_port() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();

        let report = discover("127.0.0.1", &[port], 200).unwrap();

        assert_eq!(report.target, "127.0.0.1");
        assert_eq!(report.scanned_ports, vec![port]);
        assert_eq!(report.services.len(), 1);
        assert_eq!(report.services[0].port, port);
        assert_eq!(report.services[0].protocol, "tcp");
    }
}
