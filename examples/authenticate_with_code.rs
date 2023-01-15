use mc_auth::AuthFlow;

fn main() {
    let mut auth = AuthFlow::new("9c1f1f43-58d5-4b7a-af0d-4e487f073441");
    let data = auth.request_code().unwrap();

    println!(
        "Open this link in your browser {} and enter the following code: {}\nWaiting authentication...",
        data.verification_uri, data.user_code
    );

    let response = auth.wait_for_login().unwrap();
    println!("Access token: {}", response.access_token);
}
