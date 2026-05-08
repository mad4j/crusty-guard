use crate::checks::{CheckResult, VulnerabilityCheck};
use crate::discovery::DiscoveryReport;

pub struct Cve19990524;

impl VulnerabilityCheck for Cve19990524 {
    fn run(&self, report: &DiscoveryReport) -> CheckResult {
        let evidence: Vec<String> = report
            .services
            .iter()
            .filter(|service| service.port == 79 || service.service_name == Some("finger"))
            .map(|service| match service.service_name {
                Some(name) => format!("{} / {} ({name})", service.port, service.protocol),
                None => format!("{} / {}", service.port, service.protocol),
            })
            .collect();

        let detected = !evidence.is_empty();
        let details = if detected {
            "Finger service is reachable. CVE-1999-0524 applies when the finger daemon is exposed to untrusted networks.".to_string()
        } else {
            "Finger service was not discovered on the scanned target.".to_string()
        };

        CheckResult {
            id: "CVE-1999-0524",
            title: "Finger service exposure",
            severity: "medium",
            detected,
            details,
            evidence,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::checks::VulnerabilityCheck;
    use crate::discovery::{DiscoveredService, DiscoveryReport};

    use super::Cve19990524;

    #[test]
    fn flags_when_finger_service_is_discovered() {
        let report = DiscoveryReport {
            target: "example.org".to_string(),
            scanned_ports: vec![79],
            services: vec![DiscoveredService {
                port: 79,
                protocol: "tcp",
                service_name: Some("finger"),
            }],
        };

        let result = Cve19990524.run(&report);

        assert!(result.detected);
        assert_eq!(result.id, "CVE-1999-0524");
        assert_eq!(result.evidence, vec!["79 / tcp (finger)".to_string()]);
    }

    #[test]
    fn does_not_flag_when_finger_service_is_absent() {
        let report = DiscoveryReport {
            target: "example.org".to_string(),
            scanned_ports: vec![22],
            services: vec![DiscoveredService {
                port: 22,
                protocol: "tcp",
                service_name: Some("ssh"),
            }],
        };

        let result = Cve19990524.run(&report);

        assert!(!result.detected);
        assert!(result.evidence.is_empty());
    }
}
