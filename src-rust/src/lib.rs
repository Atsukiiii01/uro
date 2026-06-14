use pyo3::prelude::*;
use regex::Regex;
use std::collections::HashSet;

#[pyfunction]
fn analyze_js(content: &str) -> PyResult<(Vec<String>, Vec<(String, String)>)> {
    let mut paths = HashSet::new();
    let mut secrets = Vec::new();

    // Regex for deep API paths and endpoints
    let path_re = Regex::new(r#"['"](/(?:api|v1|v2|internal|graphql|admin)[/a-zA-Z0-9_.-]+)['"]"#).unwrap();
    for cap in path_re.captures_iter(content) {
        if let Some(mat) = cap.get(1) {
            paths.insert(mat.as_str().to_string());
        }
    }

    // Regex for JWTs
    let jwt_re = Regex::new(r#"ey[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*"#).unwrap();
    for cap in jwt_re.captures_iter(content) {
        if let Some(mat) = cap.get(0) {
            secrets.push(("JWT".to_string(), mat.as_str().to_string()));
        }
    }

    // Regex for AWS Keys
    let aws_re = Regex::new(r#"(?i)(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}"#).unwrap();
    for cap in aws_re.captures_iter(content) {
        if let Some(mat) = cap.get(0) {
            secrets.push(("AWS_KEY".to_string(), mat.as_str().to_string()));
        }
    }

    // Regex for High Entropy Tokens (Generic)
    let token_re = Regex::new(r#"(?i)(?:token|api_key|secret|auth|access)[-_a-z0-9]*\s*[:=]\s*['"]([a-zA-Z0-9-_]{24,})['"]"#).unwrap();
    for cap in token_re.captures_iter(content) {
        if let Some(mat) = cap.get(1) {
            secrets.push(("HIGH_ENTROPY_TOKEN".to_string(), mat.as_str().to_string()));
        }
    }

    Ok((paths.into_iter().collect(), secrets))
}

#[pymodule]
fn utsu_rust_core(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(analyze_js, m)?)?;
    Ok(())
}