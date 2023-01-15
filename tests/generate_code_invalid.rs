#[cfg(test)]
mod tests {
    use mc_auth::AuthFlow;

    #[test]
    #[should_panic]
    fn generate_code_invalid() {
        let mut auth = AuthFlow::new("invalid");
        let data = auth.request_code().unwrap();
        assert_eq!(data.verification_uri, "");
    }
}
