#[cfg(test)]
mod tests {
    use mc_auth::AuthFlow;

    #[test]
    fn generate_code() {
        let mut auth = AuthFlow::new("9c1f1f43-58d5-4b7a-af0d-4e487f073441");
        let data = auth.request_code().unwrap();
        assert_eq!(data.verification_uri, "https://www.microsoft.com/link");
    }

    #[test]
    #[should_panic]
    fn generate_code_invalid() {
        let mut auth = AuthFlow::new("invalid");
        let data = auth.request_code().unwrap();
        assert_eq!(data.verification_uri, "");
    }
}
