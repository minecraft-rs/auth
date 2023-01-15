#[cfg(test)]
mod tests {
    use dotenv::dotenv;
    use std::env;

    use mc_auth::AuthFlow;

    #[test]
    fn generate_code() {
        dotenv().ok();

        let client_id = env::var("CLIENT_ID").unwrap();
        let mut auth = AuthFlow::new(&client_id);
        let data = auth.request_code().unwrap();
        assert_eq!(data.verification_uri, "https://www.microsoft.com/link");
    }
}
