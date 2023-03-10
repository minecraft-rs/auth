use mc_auth::AuthFlow;

fn main() {
    let mut auth = AuthFlow::new("{app client id}");
    let code_res = auth.request_code().unwrap();

    println!(
        "Open this link in your browser {} and enter the following code: {}\nWaiting authentication...",
        code_res.verification_uri, code_res.user_code
    );
    auth.wait_for_login().unwrap();

    println!("Logging in xbox live services...");
    auth.login_in_xbox_live().unwrap();

    println!("Logging in minecraft services...");
    let minecraft = auth.login_in_minecraft().unwrap();

    println!("Logged in:");
    println!("Bearer token: {}", minecraft.access_token);
    println!("UUID: {}", minecraft.username);
}
