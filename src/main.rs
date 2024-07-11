use std::collections::HashMap;

use generic_array::GenericArray;
use opaque_ke::{
    CipherSuite, ClientLogin, ClientLoginFinishParameters, ClientRegistration,
    ClientRegistrationFinishParameters, CredentialFinalization, CredentialRequest,
    CredentialResponse, RegistrationRequest, RegistrationResponse, RegistrationUpload, ServerLogin,
    ServerLoginStartParameters, ServerRegistration, ServerRegistrationLen, ServerSetup,
};
use rand::rngs::OsRng;

struct Scheme;

impl CipherSuite for Scheme {
    type OprfCs = opaque_ke::Ristretto255;
    type KeGroup = opaque_ke::Ristretto255;
    type KeyExchange = opaque_ke::key_exchange::tripledh::TripleDh;
    type Ksf = opaque_ke::ksf::Identity;
}

fn account_registration(
    server_setup: &ServerSetup<Scheme>,
    username: String,
    password: String,
) -> GenericArray<u8, ServerRegistrationLen<Scheme>> {
    // let client_state = ClientRegState::Initial;
    // let server_state = ServerRegState::WaitingForInput;

    // let client_state = client_state.receive(ClientRegMessage::Start);

    let mut client_rng = OsRng;
    let client_registration_start_result =
        ClientRegistration::<Scheme>::start(&mut client_rng, password.as_bytes()).unwrap();
    let registration_request_bytes = client_registration_start_result.message.serialize();

    // send to server

    let server_registration_start_result = ServerRegistration::<Scheme>::start(
        server_setup,
        RegistrationRequest::deserialize(&registration_request_bytes).unwrap(),
        username.as_bytes(),
    )
    .unwrap();
    let registration_response_bytes = server_registration_start_result.message.serialize();

    // send to client

    let client_finish_registration_result = client_registration_start_result
        .state
        .finish(
            &mut client_rng,
            password.as_bytes(),
            RegistrationResponse::deserialize(&registration_response_bytes).unwrap(),
            ClientRegistrationFinishParameters::default(),
        )
        .unwrap();
    let message_bytes = client_finish_registration_result.message.serialize();

    // send to server

    let password_file = ServerRegistration::finish(
        RegistrationUpload::<Scheme>::deserialize(&message_bytes).unwrap(),
    );
    password_file.serialize()
}

fn account_login(
    server_setup: &ServerSetup<Scheme>,
    username: String,
    password: String,
    password_file_bytes: &[u8],
) -> bool {
    let mut client_rng = OsRng;
    let client_login_start_result =
        ClientLogin::<Scheme>::start(&mut client_rng, password.as_bytes()).unwrap();
    let credential_request_bytes = client_login_start_result.message.serialize();

    // send to server

    let password_file = ServerRegistration::<Scheme>::deserialize(password_file_bytes).unwrap();
    let mut server_rng = OsRng;
    let server_login_start_result = ServerLogin::start(
        &mut server_rng,
        server_setup,
        Some(password_file),
        CredentialRequest::deserialize(&credential_request_bytes).unwrap(),
        username.as_bytes(),
        ServerLoginStartParameters::default(),
    )
    .unwrap();
    let credential_response_bytes = server_login_start_result.message.serialize();

    // send to client

    let result = client_login_start_result.state.finish(
        password.as_bytes(),
        CredentialResponse::deserialize(&credential_response_bytes).unwrap(),
        ClientLoginFinishParameters::default(),
    );

    if result.is_err() {
        return false;
    }

    let client_login_finish_result = result.unwrap();
    let credential_finalization_bytes = client_login_finish_result.message.serialize();

    // send to server

    let server_login_finish_result = server_login_start_result
        .state
        .finish(CredentialFinalization::deserialize(&credential_finalization_bytes).unwrap())
        .unwrap();
    client_login_finish_result.session_key == server_login_finish_result.session_key
}

fn main() {
    let mut server_rng = OsRng;
    let server_setup = ServerSetup::<Scheme>::new(&mut server_rng);

    let mut registered_users =
        HashMap::<String, GenericArray<u8, ServerRegistrationLen<Scheme>>>::new();

    println!("Registered users: {:?}", registered_users.keys());

    // somehow get client input
    let (username, password) = ("poop".to_string(), "weiner".to_string());
    registered_users.insert(
        username.clone(),
        account_registration(&server_setup, username, password),
    );

    println!("Registered users: {:?}", registered_users.keys());

    let (username, password) = ("nobody".to_string(), "notreal".to_string());
    match registered_users.get(&username) {
        Some(password_file_bytes) => {
            if account_login(
                &server_setup,
                username.clone(),
                password,
                password_file_bytes,
            ) {
                println!("`{username}` logged in");
            } else {
                println!("`{username}` wrong password");
            }
        }
        None => println!("`{username}` not registered"),
    }

    let (username, password) = ("poop".to_string(), "notreal".to_string());
    match registered_users.get(&username) {
        Some(password_file_bytes) => {
            if account_login(
                &server_setup,
                username.clone(),
                password,
                password_file_bytes,
            ) {
                println!("`{username}` logged in");
            } else {
                println!("`{username}` wrong password");
            }
        }
        None => println!("`{username}` not registered"),
    }

    let (username, password) = ("poop".to_string(), "weiner".to_string());
    match registered_users.get(&username) {
        Some(password_file_bytes) => {
            if account_login(
                &server_setup,
                username.clone(),
                password,
                password_file_bytes,
            ) {
                println!("`{username}` logged in");
            } else {
                println!("`{username}` wrong password");
            }
        }
        None => println!("`{username}` not registered"),
    }

    // let client_registration_start =
    //     ClientRegistration::<Scheme>::start(&mut OsRng, b"cool").unwrap();
    // let server_registration_start = ServerRegistration::<Scheme>::start(
    //     &server_setup,
    //     client_registration_start.message,
    //     b"weiner",
    // )
    // .unwrap();
    // let client_registration_finish = client_registration_start
    //     .state
    //     .finish(
    //         &mut OsRng,
    //         b"cool",
    //         server_registration_start.message,
    //         ClientRegistrationFinishParameters::default(),
    //     )
    //     .unwrap();
    // println!("Hello, world!");
}
