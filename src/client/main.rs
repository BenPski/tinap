use std::{fmt::Display, process::exit};

use pants_gen::password::PasswordSpec;
use tinap::client::client::Client;

enum Choice {
    Register,
    Login,
}

impl Display for Choice {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Register => write!(f, "Register"),
            Self::Login => write!(f, "Login"),
        }
    }
}

#[tokio::main]
async fn main() {
    let client = Client::new("127.0.0.1".to_string(), 6969);
    let choices = vec![Choice::Login, Choice::Register];
    let action = inquire::Select::new("What would you like to do?", choices).prompt();
    let action = match action {
        Ok(choice) => choice,
        Err(err) => {
            println!("Error occurred: `{err}`");
            exit(1)
        }
    };

    match action {
        Choice::Register => {
            let username = inquire::Text::new("Username:").prompt().unwrap();
            let password = PasswordSpec::default().generate().unwrap();
            println!("Your password is:");
            println!("{password}");
            let validator = move |input: &str| {
                if input != password {
                    Ok(inquire::validator::Validation::Invalid(
                        "You must use the provided password".into(),
                    ))
                } else {
                    Ok(inquire::validator::Validation::Valid)
                }
            };
            let password_input = inquire::Password::new("Password:")
                .with_display_mode(inquire::PasswordDisplayMode::Masked)
                .with_help_message("Enter the provided password to confirm")
                .without_confirmation()
                .with_validator(validator)
                .prompt()
                .unwrap();

            println!("Registering `{username}`");

            match client.register(username, password_input).await {
                Ok(auth) => {
                    if auth {
                        println!("User registered");
                    } else {
                        println!("User already registered");
                    }
                }
                Err(err) => {
                    println!("Error occurred: `{err}`");
                }
            }
        }
        Choice::Login => {
            let username = inquire::Text::new("Username:").prompt().unwrap();
            let password = inquire::Password::new("Password:")
                .with_display_mode(inquire::PasswordDisplayMode::Masked)
                .without_confirmation()
                .prompt()
                .unwrap();

            match client.authenticate(username, password).await {
                Ok(auth) => {
                    if let Some(auth) = auth {
                        println!("User authorized");
                        println!("session_key: `{:?}`", auth.session_key());
                        println!("export_key: `{:?}`", auth.export_key());
                    } else {
                        println!("Could not authenticate");
                    }
                }
                Err(err) => {
                    println!("Error occurred: `{err}`");
                }
            }
        }
    }
    //
    // let (username, password) = ("bobody".to_string(), "something".to_string());
    // client
    //     .register_user(username.clone(), password.clone())
    //     .await
    //     .unwrap();
    // let auth = client.authenticate_user(username, password).await.unwrap();
    // println!("Auth: {auth}");
}
