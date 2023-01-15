# MC Auth

Xbox live authentication flow for Minecraft in Rust.

## Why?

In order to create tools for Minecraft based on rust that implement the user profile it is necessary to first authenticate the user through Microsoft servers. With this library you can do it in just 3 lines of code.

## Prepare

You must first have an account in Azure and then register an application in Azure Active Directory.  

1. Go to [https://portal.azure.com/](Azure Portal) and register or log in.
2. Once in your account, go to the "Azure Active Directory" service.
3. On the service page go to the application registration section in the sidebar.
4. Create a new application, name it whatever you want and copy the Client ID. You will need it to use this library.
5. Configure your app, in the api permissions section make sure you have the following permissions active: "XboxLive.signin offline_access".

## Usage

```rust
use mc_auth::AuthFlow;

fn main() {
    let mut auth = AuthFlow::new("9c1f1f43-58d5-4b7a-af0d-4e487f073441");
    let data = auth.request_code().unwrap();

    println!(
        "Open link {} and type code {}\nWaiting authentication...",
        data.verification_uri, data.user_code
    );

    let response = auth.wait_for_login().unwrap();
    println!("Access token: {}", response.access_token);
}
```

### Contribution

Feel free to contribute to the development of the library.
