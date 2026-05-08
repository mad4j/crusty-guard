pub mod checks;
pub mod discovery;
pub mod output;

use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputFormat {
    Text,
    Json,
}

impl OutputFormat {
    fn parse(value: &str) -> Result<Self, CliError> {
        match value {
            "text" => Ok(Self::Text),
            "json" => Ok(Self::Json),
            _ => Err(CliError::new(format!(
                "unsupported output format '{value}'. Use 'text' or 'json'."
            ))),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanOptions {
    pub host: String,
    pub ports: Vec<u16>,
    pub output: OutputFormat,
    pub timeout_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CliError {
    message: String,
}

impl CliError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for CliError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for CliError {}

pub fn run<I, S>(args: I) -> Result<String, CliError>
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    let args = args.into_iter().map(Into::into).collect::<Vec<String>>();

    if args.iter().any(|arg| arg == "--help" || arg == "-h") {
        return Ok(help_text().to_string());
    }

    let options = parse_args(args)?;
    let discovery_report = discovery::discover(&options.host, &options.ports, options.timeout_ms)?;
    let check_results = checks::run_all(&discovery_report);

    Ok(output::render(
        &discovery_report,
        &check_results,
        options.output,
    ))
}

pub fn parse_args<I, S>(args: I) -> Result<ScanOptions, CliError>
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    let mut values = args.into_iter().map(Into::into);
    let _program_name = values.next();

    let mut host = None;
    let mut ports = vec![79];
    let mut output = OutputFormat::Text;
    let mut timeout_ms = 500;

    while let Some(arg) = values.next() {
        match arg.as_str() {
            "--host" => {
                let value = values
                    .next()
                    .ok_or_else(|| CliError::new("missing value for --host"))?;
                host = Some(value);
            }
            "--ports" => {
                let value = values
                    .next()
                    .ok_or_else(|| CliError::new("missing value for --ports"))?;
                ports = parse_ports(&value)?;
            }
            "--format" => {
                let value = values
                    .next()
                    .ok_or_else(|| CliError::new("missing value for --format"))?;
                output = OutputFormat::parse(&value)?;
            }
            "--timeout-ms" => {
                let value = values
                    .next()
                    .ok_or_else(|| CliError::new("missing value for --timeout-ms"))?;
                timeout_ms = value.parse::<u64>().map_err(|_| {
                    CliError::new(format!("invalid timeout '{value}'. Expected milliseconds."))
                })?;
            }
            "--help" | "-h" => return Err(CliError::new(help_text())),
            other => {
                return Err(CliError::new(format!(
                    "unknown argument '{other}'.\n\n{}",
                    help_text()
                )));
            }
        }
    }

    let host = host.ok_or_else(|| {
        CliError::new(format!(
            "missing required --host argument\n\n{}",
            help_text()
        ))
    })?;

    Ok(ScanOptions {
        host,
        ports,
        output,
        timeout_ms,
    })
}

fn parse_ports(value: &str) -> Result<Vec<u16>, CliError> {
    let mut ports = Vec::new();

    for segment in value.split(',') {
        let trimmed = segment.trim();
        if trimmed.is_empty() {
            continue;
        }

        let port = trimmed.parse::<u16>().map_err(|_| {
            CliError::new(format!(
                "invalid port '{trimmed}'. Ports must be between 0 and 65535."
            ))
        })?;
        ports.push(port);
    }

    if ports.is_empty() {
        return Err(CliError::new(
            "no ports supplied. Use a comma-separated list such as '79,443'.",
        ));
    }

    Ok(ports)
}

pub fn help_text() -> &'static str {
    "crusty-guard - modular Rust CLI for vulnerability checks\n\nUSAGE:\n    crusty-guard --host <HOST> [--ports <PORTS>] [--format <text|json>] [--timeout-ms <MS>]\n\nOPTIONS:\n    --host <HOST>         Hostname or IP address to scan\n    --ports <PORTS>       Comma-separated TCP port list to scan (default: 79)\n    --format <FORMAT>     Output format: text or json (default: text)\n    --timeout-ms <MS>     TCP connect timeout in milliseconds (default: 500)\n    -h, --help            Show this help message"
}

#[cfg(test)]
mod tests {
    use super::{OutputFormat, ScanOptions, parse_args};

    #[test]
    fn parse_args_uses_defaults() {
        let parsed = parse_args(["crusty-guard", "--host", "127.0.0.1"]).unwrap();

        assert_eq!(
            parsed,
            ScanOptions {
                host: "127.0.0.1".to_string(),
                ports: vec![79],
                output: OutputFormat::Text,
                timeout_ms: 500,
            }
        );
    }

    #[test]
    fn parse_args_supports_multiple_ports_and_json() {
        let parsed = parse_args([
            "crusty-guard",
            "--host",
            "localhost",
            "--ports",
            "79,443",
            "--format",
            "json",
            "--timeout-ms",
            "250",
        ])
        .unwrap();

        assert_eq!(parsed.host, "localhost");
        assert_eq!(parsed.ports, vec![79, 443]);
        assert_eq!(parsed.output, OutputFormat::Json);
        assert_eq!(parsed.timeout_ms, 250);
    }

    #[test]
    fn run_returns_help_text() {
        let output = super::run(["crusty-guard", "--help"]).unwrap();

        assert!(output.contains("USAGE:"));
        assert!(output.contains("--format <text|json>"));
    }
}
