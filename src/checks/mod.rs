mod cve_1999_0524;

use crate::discovery::DiscoveryReport;

pub use cve_1999_0524::Cve19990524;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckResult {
    pub id: &'static str,
    pub title: &'static str,
    pub severity: &'static str,
    pub detected: bool,
    pub details: String,
    pub evidence: Vec<String>,
}

pub trait VulnerabilityCheck {
    fn run(&self, report: &DiscoveryReport) -> CheckResult;
}

pub fn run_all(report: &DiscoveryReport) -> Vec<CheckResult> {
    let checks: [&dyn VulnerabilityCheck; 1] = [&Cve19990524];
    checks.into_iter().map(|check| check.run(report)).collect()
}
