use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, ToSocketAddrs};

/// RFC 1918 / RFC 4193 / RFC 6890 internal IP ranges.
const INTERNAL_IPV4_RANGES: &[(Ipv4Addr, u32)] = &[
    (Ipv4Addr::new(10, 0, 0, 0), 8),
    (Ipv4Addr::new(172, 16, 0, 0), 12),
    (Ipv4Addr::new(192, 168, 0, 0), 16),
    (Ipv4Addr::new(127, 0, 0, 0), 8),
];

/// Check if a URI uses an insecure protocol.
pub fn is_insecure_uri(uri: &str) -> bool {
    uri.starts_with("git://") || uri.starts_with("http://")
}

/// Check if a source URI points to an internal/private host.
pub fn is_internal_source(uri: &str) -> bool {
    match extract_host(uri) {
        Some(h) => is_internal_host(&h),
        None => false,
    }
}

/// Check if an IPv4 address is in a CIDR range.
fn ipv4_in_cidr(addr: Ipv4Addr, network: Ipv4Addr, prefix_len: u32) -> bool {
    let addr_bits = u32::from(addr);
    let net_bits = u32::from(network);
    let mask = if prefix_len == 0 {
        0
    } else {
        !0u32 << (32 - prefix_len)
    };
    (addr_bits & mask) == (net_bits & mask)
}

/// Check if an IP address is internal/private.
fn is_internal_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => INTERNAL_IPV4_RANGES
            .iter()
            .any(|(net, prefix)| ipv4_in_cidr(v4, *net, *prefix)),
        IpAddr::V6(v6) => {
            // ::1 (loopback)
            v6 == Ipv6Addr::LOCALHOST
                // fc00::/7 (unique local)
                || (v6.octets()[0] & 0xfe) == 0xfc
        }
    }
}

/// Extract the hostname from a URI string.
fn extract_host(uri: &str) -> Option<String> {
    // Handle git:// , http:// , https://
    let after_scheme = uri.split("://").nth(1)?;
    let host_port = after_scheme.split('/').next()?;
    let host = host_port.split(':').next()?;
    // Strip user@ prefix
    let host = if let Some(at_pos) = host.rfind('@') {
        &host[at_pos + 1..]
    } else {
        host
    };
    if host.is_empty() {
        None
    } else {
        Some(host.to_string())
    }
}

/// Check if a hostname resolves to only internal IPs.
fn is_internal_host(host: &str) -> bool {
    // Try parsing as IP address first
    if let Ok(ip) = host.parse::<IpAddr>() {
        return is_internal_ip(ip);
    }

    // Try DNS resolution
    let sock_addr = format!("{}:0", host);
    match sock_addr.to_socket_addrs() {
        Ok(addrs) => {
            let addrs: Vec<_> = addrs.collect();
            !addrs.is_empty() && addrs.iter().all(|a| is_internal_ip(a.ip()))
        }
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ========== URI Security ==========

    #[test]
    fn git_protocol_is_insecure() {
        assert!(is_insecure_uri("git://github.com/foo/bar.git"));
    }

    #[test]
    fn http_is_insecure() {
        assert!(is_insecure_uri("http://rubygems.org/"));
    }

    #[test]
    fn https_is_secure() {
        assert!(!is_insecure_uri("https://rubygems.org/"));
    }

    #[test]
    fn ssh_is_secure() {
        assert!(!is_insecure_uri("git@github.com:foo/bar.git"));
    }

    // ========== Host Extraction ==========

    #[test]
    fn extract_host_from_git_uri() {
        assert_eq!(
            extract_host("git://github.com/rails/jquery-rails.git"),
            Some("github.com".to_string())
        );
    }

    #[test]
    fn extract_host_from_http_uri() {
        assert_eq!(
            extract_host("http://rubygems.org/"),
            Some("rubygems.org".to_string())
        );
    }

    #[test]
    fn extract_host_with_port() {
        assert_eq!(
            extract_host("http://gems.example.com:8080/"),
            Some("gems.example.com".to_string())
        );
    }

    #[test]
    fn extract_host_with_user() {
        assert_eq!(
            extract_host("http://user@gems.example.com/"),
            Some("gems.example.com".to_string())
        );
    }

    // ========== Internal IP Detection ==========

    #[test]
    fn localhost_is_internal() {
        assert!(is_internal_ip("127.0.0.1".parse().unwrap()));
        assert!(is_internal_ip("127.0.0.42".parse().unwrap()));
    }

    #[test]
    fn rfc1918_10_is_internal() {
        assert!(is_internal_ip("10.0.0.1".parse().unwrap()));
        assert!(is_internal_ip("10.255.255.255".parse().unwrap()));
    }

    #[test]
    fn rfc1918_172_is_internal() {
        assert!(is_internal_ip("172.16.0.1".parse().unwrap()));
        assert!(is_internal_ip("172.31.255.255".parse().unwrap()));
    }

    #[test]
    fn rfc1918_192_is_internal() {
        assert!(is_internal_ip("192.168.0.1".parse().unwrap()));
        assert!(is_internal_ip("192.168.255.255".parse().unwrap()));
    }

    #[test]
    fn public_ip_is_not_internal() {
        assert!(!is_internal_ip("8.8.8.8".parse().unwrap()));
        assert!(!is_internal_ip("1.1.1.1".parse().unwrap()));
    }

    #[test]
    fn ipv6_loopback_is_internal() {
        assert!(is_internal_ip("::1".parse().unwrap()));
    }

    #[test]
    fn ipv6_unique_local_is_internal() {
        assert!(is_internal_ip("fc00::1".parse().unwrap()));
        assert!(is_internal_ip("fd12:3456:789a::1".parse().unwrap()));
    }

    // ========== Internal Source Detection ==========

    #[test]
    fn internal_http_source() {
        assert!(is_internal_source("http://192.168.1.1/gems/"));
        assert!(is_internal_source("http://10.0.0.1:8080/"));
        assert!(is_internal_source("http://127.0.0.1/"));
    }

    #[test]
    fn external_http_source() {
        assert!(!is_internal_source("http://rubygems.org/"));
    }

    #[test]
    fn localhost_name_is_internal() {
        assert!(is_internal_source("http://localhost/"));
    }

    // ========== extract_host edge cases ==========

    #[test]
    fn extract_host_no_scheme() {
        assert_eq!(extract_host("not-a-url"), None);
    }

    #[test]
    fn extract_host_empty_host() {
        assert_eq!(extract_host("http:///path"), None);
    }

    // ========== ipv4_in_cidr edge cases ==========

    #[test]
    fn ipv4_in_cidr_prefix_zero_matches_any() {
        assert!(ipv4_in_cidr(
            Ipv4Addr::new(8, 8, 8, 8),
            Ipv4Addr::new(0, 0, 0, 0),
            0
        ));
        assert!(ipv4_in_cidr(
            Ipv4Addr::new(192, 168, 1, 1),
            Ipv4Addr::new(0, 0, 0, 0),
            0
        ));
    }

    #[test]
    fn ipv4_in_cidr_prefix_32_exact_match() {
        assert!(ipv4_in_cidr(
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(10, 0, 0, 1),
            32
        ));
        assert!(!ipv4_in_cidr(
            Ipv4Addr::new(10, 0, 0, 2),
            Ipv4Addr::new(10, 0, 0, 1),
            32
        ));
    }
}
