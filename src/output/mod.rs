use std::fmt::Write;

use crate::OutputFormat;
use crate::checks::CheckResult;
use crate::discovery::DiscoveryReport;

pub fn render(report: &DiscoveryReport, results: &[CheckResult], format: OutputFormat) -> String {
    match format {
        OutputFormat::Text => render_text(report, results),
        OutputFormat::Json => render_json(report, results),
    }
}

fn render_text(report: &DiscoveryReport, results: &[CheckResult]) -> String {
    let mut output = String::new();
    let _ = writeln!(output, "Target: {}", report.target);
    let _ = writeln!(
        output,
        "Scanned ports: {}",
        join_ports(&report.scanned_ports)
    );
    let _ = writeln!(output, "Discovered services:");

    if report.services.is_empty() {
        let _ = writeln!(output, "- none");
    } else {
        for service in &report.services {
            let _ = writeln!(
                output,
                "- {}/{}{}",
                service.port,
                service.protocol,
                service
                    .service_name
                    .map(|name| format!(" ({name})"))
                    .unwrap_or_default()
            );
        }
    }

    let _ = writeln!(output, "Checks:");
    for result in results {
        let status = if result.detected {
            "VULNERABLE"
        } else {
            "not detected"
        };
        let _ = writeln!(output, "- {} [{}]: {}", result.id, result.severity, status);
        let _ = writeln!(output, "  {}", result.details);
        if !result.evidence.is_empty() {
            let _ = writeln!(output, "  Evidence: {}", result.evidence.join(", "));
        }
    }

    output
}

fn render_json(report: &DiscoveryReport, results: &[CheckResult]) -> String {
    let services = report
        .services
        .iter()
        .map(|service| {
            format!(
                "{{\"port\":{},\"protocol\":\"{}\",\"service\":{}}}",
                service.port,
                json_escape(service.protocol),
                service
                    .service_name
                    .map(|name| format!("\"{}\"", json_escape(name)))
                    .unwrap_or_else(|| "null".to_string())
            )
        })
        .collect::<Vec<_>>()
        .join(",");

    let findings = results
        .iter()
        .map(|result| {
            let evidence = result
                .evidence
                .iter()
                .map(|item| format!("\"{}\"", json_escape(item)))
                .collect::<Vec<_>>()
                .join(",");

            format!(
                concat!(
                    "{{",
                    "\"id\":\"{}\"",
                    ",\"title\":\"{}\"",
                    ",\"severity\":\"{}\"",
                    ",\"detected\":{}",
                    ",\"details\":\"{}\"",
                    ",\"evidence\":[{}]",
                    "}}"
                ),
                json_escape(result.id),
                json_escape(result.title),
                json_escape(result.severity),
                result.detected,
                json_escape(&result.details),
                evidence,
            )
        })
        .collect::<Vec<_>>()
        .join(",");

    format!(
        concat!(
            "{{",
            "\"target\":\"{}\"",
            ",\"scanned_ports\":[{}]",
            ",\"services\":[{}]",
            ",\"findings\":[{}]",
            "}}"
        ),
        json_escape(&report.target),
        report
            .scanned_ports
            .iter()
            .map(u16::to_string)
            .collect::<Vec<_>>()
            .join(","),
        services,
        findings,
    )
}

fn join_ports(ports: &[u16]) -> String {
    ports
        .iter()
        .map(u16::to_string)
        .collect::<Vec<_>>()
        .join(",")
}

fn json_escape(value: &str) -> String {
    let mut escaped = String::new();

    for character in value.chars() {
        match character {
            '\\' => escaped.push_str("\\\\"),
            '"' => escaped.push_str("\\\""),
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            other => escaped.push(other),
        }
    }

    escaped
}

#[cfg(test)]
mod tests {
    use crate::OutputFormat;
    use crate::checks::CheckResult;
    use crate::discovery::{DiscoveredService, DiscoveryReport};

    use super::render;

    #[test]
    fn render_supports_text_output() {
        let report = DiscoveryReport {
            target: "localhost".to_string(),
            scanned_ports: vec![79],
            services: vec![DiscoveredService {
                port: 79,
                protocol: "tcp",
                service_name: Some("finger"),
            }],
        };
        let results = vec![CheckResult {
            id: "CVE-1999-0524",
            title: "Finger service exposure",
            severity: "medium",
            detected: true,
            details: "detected".to_string(),
            evidence: vec!["79 / tcp (finger)".to_string()],
        }];

        let rendered = render(&report, &results, OutputFormat::Text);

        assert!(rendered.contains("Target: localhost"));
        assert!(rendered.contains("CVE-1999-0524 [medium]: VULNERABLE"));
    }

    #[test]
    fn render_supports_json_output() {
        let report = DiscoveryReport {
            target: "localhost".to_string(),
            scanned_ports: vec![79],
            services: vec![],
        };
        let results = vec![CheckResult {
            id: "CVE-1999-0524",
            title: "Finger service exposure",
            severity: "medium",
            detected: false,
            details: "not detected".to_string(),
            evidence: vec![],
        }];

        let rendered = render(&report, &results, OutputFormat::Json);

        assert!(rendered.starts_with('{'));
        assert!(rendered.contains("\"target\":\"localhost\""));
        assert!(rendered.contains("\"detected\":false"));
    }
}
