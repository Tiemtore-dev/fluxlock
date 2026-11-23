//! Exact browser-origin policy; never use substring, suffix or confusable matching.
pub fn canonical(value: &str) -> Result<String, String> {
    if value.len() > 4096 || value.chars().any(|c| c.is_control()) || value.contains('\\') {
        return Err("URL refusée".into());
    }
    let url = url::Url::parse(value).map_err(|_| "URL invalide")?;
    if url.scheme() != "https" || !url.username().is_empty() || url.password().is_some() {
        return Err("Une origine HTTPS sans identifiants est requise".into());
    }
    let host = url.host_str().ok_or("Hôte absent")?;
    if !host.is_ascii() || host.ends_with('.') || host.is_empty() {
        return Err("Hôte non canonique".into());
    }
    Ok(url.origin().ascii_serialization())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn exact_origins_reject_homographs_aliases_ports_and_ambiguous_urls() {
        assert_eq!(
            canonical("https://PAYPAL.COM:443/login").unwrap(),
            "https://paypal.com"
        );
        for wrong in [
            "https://paypal.com.evil.test",
            "https://www.paypal.com",
            "https://paypal.com:8443",
            "https://pаypal.com",
        ] {
            assert_ne!(
                canonical(wrong).unwrap(),
                canonical("https://paypal.com").unwrap()
            );
        }
        assert_eq!(
            canonical("https://bücher.de").unwrap(),
            "https://xn--bcher-kva.de"
        );
        assert_ne!(
            canonical("https://faß.de").unwrap(),
            canonical("https://fass.de").unwrap()
        );
        for wrong in [
            "http://paypal.com",
            "https://user@paypal.com",
            "https://paypal.com.",
            "https://paypal.com\\@evil.test",
            "data:text/html,x",
        ] {
            assert!(canonical(wrong).is_err());
        }
    }
}
