use pyo3::prelude::*;
use regex::Regex;

#[pyfunction]
fn extract_security_intel(js_content: &str) -> PyResult<(Vec<String>, Vec<(String, String)>)> {
    let path_regex = Regex::new(r#"(?:"|')(/[a-zA-Z0-9_\-\.\?=&/]+)(?:"|')"#).unwrap();
    
    // Hardened Regex hunting for exact structural signatures, not just loose keywords
    let jwt_regex = Regex::new(r#"ey[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}"#).unwrap();
    // Hardened AWS Regex: Strictly uppercase, exactly 20 characters, locked by word boundaries
    let aws_regex = Regex::new(r#"\b(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}\b"#).unwrap();
    let high_entropy_token = Regex::new(r#"(?i)(?:api_key|secret|token|authorization)["\s]*:[\s]*["']([a-zA-Z0-9\-_]{32,})["']"#).unwrap();

    let mut endpoints = Vec::new();
    let mut secrets = Vec::new();

    for cap in path_regex.captures_iter(js_content) {
        if let Some(mat) = cap.get(1) {
            let path = mat.as_str().to_string();
            if path.contains('/') && path.len() > 2 {
                endpoints.push(path);
            }
        }
    }

    // Capture JWTs
    for mat in jwt_regex.find_iter(js_content) {
        secrets.push(("JWT".to_string(), mat.as_str().to_string()));
    }

    // Capture AWS Keys
    for mat in aws_regex.find_iter(js_content) {
        secrets.push(("AWS_KEY".to_string(), mat.as_str().to_string()));
    }

    // Capture 32+ character High Entropy API Keys
    for cap in high_entropy_token.captures_iter(js_content) {
        if let Some(mat) = cap.get(1) {
            secrets.push(("HIGH_ENTROPY_TOKEN".to_string(), mat.as_str().to_string()));
        }
    }

    endpoints.sort();
    endpoints.dedup();

    Ok((endpoints, secrets))
}

#[pymodule]
fn uro_rust_core(_py: Python, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(extract_security_intel, m)?)?;
    Ok(())
}