use opaque_ke::{
    CredentialFinalization, CredentialRequest, ServerLogin, ServerLoginFinishResult,
    ServerLoginStartParameters, ServerLoginStartResult, ServerRegistration, ServerSetup,
};
use rand::rngs::OsRng;

use crate::{Scheme, WithUsername};

use super::server::ServerError;

pub struct AuthWaiting {
    server_setup: ServerSetup<Scheme>,
}

impl AuthWaiting {
    pub fn new(server_setup: ServerSetup<Scheme>) -> Self {
        Self { server_setup }
    }

    pub fn step(self, initial_data: Vec<u8>) -> Result<AuthInitial, ServerError> {
        let data: WithUsername = bincode::deserialize(&initial_data)?;
        let username = data.username;
        let credential_request_bytes = data.data;
        let credential_request = CredentialRequest::deserialize(credential_request_bytes)?;
        Ok(AuthInitial::new(
            username.into(),
            credential_request,
            self.server_setup,
        ))
    }
}

pub struct AuthInitial {
    username: Vec<u8>,
    credential_request: CredentialRequest<Scheme>,
    server_setup: ServerSetup<Scheme>,
}

impl AuthInitial {
    pub fn new(
        username: Vec<u8>,
        credential_request: CredentialRequest<Scheme>,
        server_setup: ServerSetup<Scheme>,
    ) -> Self {
        Self {
            username,
            credential_request,
            server_setup,
        }
    }

    pub fn username(&self) -> &[u8] {
        &self.username
    }

    pub fn step(self, password_file_bytes: &[u8]) -> Result<AuthWithCreds, ServerError> {
        let password_file = ServerRegistration::<Scheme>::deserialize(&password_file_bytes)?;
        let server_login_start_result = ServerLogin::start(
            &mut OsRng,
            &self.server_setup,
            Some(password_file),
            self.credential_request,
            &self.username,
            ServerLoginStartParameters::default(),
        )?;
        Ok(AuthWithCreds::new(server_login_start_result))
    }
}

pub struct AuthWithCreds {
    server_login_start_result: ServerLoginStartResult<Scheme>,
}

impl AuthWithCreds {
    pub fn new(server_login_start_result: ServerLoginStartResult<Scheme>) -> Self {
        Self {
            server_login_start_result,
        }
    }

    pub fn to_data(&self) -> Vec<u8> {
        self.server_login_start_result
            .message
            .serialize()
            .as_slice()
            .into()
    }

    pub fn step(self, credential_finalization_bytes: Vec<u8>) -> Result<AuthFinal, ServerError> {
        let credential_finalization =
            CredentialFinalization::deserialize(&credential_finalization_bytes)?;
        let server_login_finish_result = self
            .server_login_start_result
            .state
            .finish(credential_finalization)?;
        Ok(AuthFinal::new(server_login_finish_result))
    }
}

pub struct AuthFinal {
    server_login_finish_result: ServerLoginFinishResult<Scheme>,
}

impl AuthFinal {
    pub fn new(server_login_finish_result: ServerLoginFinishResult<Scheme>) -> Self {
        Self {
            server_login_finish_result,
        }
    }

    pub fn to_data(&self) -> Vec<u8> {
        self.server_login_finish_result
            .session_key
            .as_slice()
            .into()
    }

    pub fn step(self, state: Vec<u8>) -> AuthConfirm {
        AuthConfirm::new(state == vec![1])
    }
}

pub struct AuthConfirm {
    authenticated: bool,
}

impl AuthConfirm {
    pub fn new(authenticated: bool) -> Self {
        Self { authenticated }
    }

    pub fn authenticated(&self) -> bool {
        self.authenticated
    }
}

// async fn authenticate(&self, fut: upgrade::UpgradeFut) -> anyhow::Result<()> {
//     let mut ws = fastwebsockets::FragmentCollector::new(fut.await?);
//     let mut state = ServerAuthStateWrapper {
//         state: ServerAuthState::Initial,
//         server_login_start_result: None,
//     };
//     let mut result = Ok(());
//     loop {
//         let frame = ws.read_frame().await?;
//         match state.state {
//             ServerAuthState::Initial => match frame.opcode {
//                 OpCode::Binary => {
//                     println!("Server login start");
//                     let data = frame.payload.to_vec();
//                     let data: WithUsername = match bincode::deserialize(&data) {
//                         Ok(data) => data,
//                         Err(_err) => {
//                             result = Err(ServerError::DeserializeFailure);
//                             break;
//                         }
//                     };
//                     let username = data.username;
//                     let credential_request_bytes = data.data;
//                     println!("username: `{username:?}`");
//                     let contains_key = match self.store.contains_key(username) {
//                         Ok(res) => res,
//                         Err(_err) => {
//                             result = Err(ServerError::DBConnection);
//                             break;
//                         }
//                     };
//                     if !contains_key {
//                         println!("User is not registered");
//                         result = Err(ServerError::UserAlreadyExists);
//                         break;
//                     }
//                     // println!("Server received: `{:?}`", &credential_request_bytes);
//                     let password_lookup = match self.store.get(username) {
//                         Ok(res) => res,
//                         Err(_err) => {
//                             result = Err(ServerError::DBConnection);
//                             break;
//                         }
//                     };
//                     let password_file_bytes = if let Some(res) = password_lookup {
//                         res
//                     } else {
//                         result = Err(ServerError::NotRegistered);
//                         break;
//                     };
//                     println!("Looked up: {:?}, {:?}", username, password_file_bytes);
//                     let password_file =
//                         match ServerRegistration::<Scheme>::deserialize(&password_file_bytes) {
//                             Ok(res) => res,
//                             Err(_err) => {
//                                 result = Err(ServerError::DeserializeFailure);
//                                 break;
//                             }
//                         };
//                     let credential_request =
//                         match CredentialRequest::deserialize(&credential_request_bytes) {
//                             Ok(res) => res,
//                             Err(_err) => {
//                                 result = Err(ServerError::DeserializeFailure);
//                                 break;
//                             }
//                         };
//                     let server_login_start_result = match ServerLogin::start(
//                         &mut OsRng,
//                         &self.server_setup,
//                         Some(password_file),
//                         credential_request,
//                         &username,
//                         ServerLoginStartParameters::default(),
//                     ) {
//                         Ok(res) => res,
//                         Err(_err) => {
//                             result = Err(ServerError::LoginFailure);
//                             break;
//                         }
//                     };
//                     let credential_response_bytes =
//                         server_login_start_result.message.serialize();
//
//                     // println!("Server sending: `{credential_response_bytes:?}`");
//                     ws.write_frame(Frame::new(
//                         true,
//                         OpCode::Binary,
//                         None,
//                         credential_response_bytes.as_slice().into(),
//                     ))
//                     .await?;
//                     state.state = ServerAuthState::WaitingForFinal;
//                     state.server_login_start_result = Some(server_login_start_result.clone());
//                 }
//                 OpCode::Close => {
//                     println!("Prematurely closed");
//                     return Err(ServerError::ClosedEarly.into());
//                 }
//                 _ => {
//                     println!(
//                         "Unexpected frame received `{:?}` with `{:?}`",
//                         frame.opcode, frame.payload
//                     );
//                 }
//             },
//             ServerAuthState::WaitingForFinal => match frame.opcode {
//                 OpCode::Binary => {
//                     println!("Server finalization");
//                     let credential_finalization_bytes = frame.payload.to_vec();
//
//                     let server_login_start_result =
//                         state.server_login_start_result.clone().unwrap();
//                     // let server_login_finish_result =
//                     //     CredentialFinalization::deserialize(&credential_finalization_bytes)
//                     //         .and_then(|credential_finalization| {
//                     //             server_login_start_result
//                     //                 .state
//                     //                 .finish(credential_finalization)
//                     //         })
//                     //         .map_err(|_| ServerError::LoginFailure)?;
//
//                     let credential_finalization = match CredentialFinalization::deserialize(
//                         &credential_finalization_bytes,
//                     ) {
//                         Ok(res) => res,
//                         Err(_err) => {
//                             result = Err(ServerError::DeserializeFailure);
//                             break;
//                         }
//                     };
//                     let server_login_finish_result = match server_login_start_result
//                         .state
//                         .finish(credential_finalization)
//                     {
//                         Ok(res) => res,
//                         Err(_err) => {
//                             result = Err(ServerError::LoginFailure);
//                             break;
//                         }
//                     };
//
//                     ws.write_frame(Frame::new(
//                         true,
//                         OpCode::Binary,
//                         None,
//                         server_login_finish_result.session_key.as_slice().into(),
//                     ))
//                     .await?;
//                     state.state = ServerAuthState::Confirm;
//                 }
//                 OpCode::Close => {
//                     println!("Prematurely closed");
//                     return Err(ServerError::ClosedEarly.into());
//                 }
//                 _ => {
//                     println!(
//                         "Unexpected frame received `{:?}` with `{:?}`",
//                         frame.opcode, frame.payload
//                     );
//                 }
//             },
//             ServerAuthState::Confirm => match frame.opcode {
//                 OpCode::Binary => {
//                     let status = frame.payload.to_vec();
//                     let authenticated = vec![1] == status;
//                     println!("Authenticated: `{authenticated}`");
//                     ws.write_frame(Frame::close(1000, "done".as_bytes().into()))
//                         .await?;
//                     break;
//                 }
//                 OpCode::Close => {
//                     println!("Prematurely closed");
//                     return Err(ServerError::ClosedEarly.into());
//                 }
//                 _ => {
//                     println!(
//                         "Unexpected frame received `{:?}` with `{:?}`",
//                         frame.opcode, frame.payload
//                     );
//                 }
//             },
//         }
//     }
//
//     if let Err(err) = result {
//         Server::error(ws, &err).await?;
//         return Err(err.into());
//     }
//
//     Ok(())
// }
