use opaque_ke::{
    ClientLogin, ClientLoginFinishParameters, ClientLoginFinishResult, ClientLoginStartResult,
    CredentialResponse,
};
use rand::rngs::OsRng;

use crate::{Scheme, WithUsername};

use super::client::ClientError;

pub struct AuthenticateInitialize {
    username: String,
    password: String,
    client_login_start_result: ClientLoginStartResult<Scheme>,
}

impl AuthenticateInitialize {
    pub fn step(
        self,
        credential_response_bytes: Vec<u8>,
    ) -> Result<AuthenticateWaiting, ClientError> {
        let credential_response = CredentialResponse::deserialize(&credential_response_bytes)?;
        let client_login_finish_result = self.client_login_start_result.state.finish(
            self.password.as_bytes(),
            credential_response,
            ClientLoginFinishParameters::default(),
        )?;

        Ok(AuthenticateWaiting::new(client_login_finish_result))
    }

    pub fn to_data(&self) -> Vec<u8> {
        let credential_request_bytes = self.client_login_start_result.message.serialize();
        let with_username = WithUsername {
            username: self.username.as_bytes().into(),
            data: credential_request_bytes.as_slice(),
        };
        bincode::serialize(&with_username).unwrap()
    }

    pub fn new(username: String, password: String) -> Result<Self, ClientError> {
        let mut client_rng = OsRng;
        let client_login_start_result =
            match ClientLogin::<Scheme>::start(&mut client_rng, password.as_bytes()) {
                Ok(res) => res,
                Err(err) => {
                    return Err(ClientError::ProtocolError(err).into());
                }
            };
        Ok(Self {
            username,
            password,
            client_login_start_result,
        })
    }
}

pub struct AuthenticateWaiting {
    client_login_finish_result: ClientLoginFinishResult<Scheme>,
}

impl AuthenticateWaiting {
    pub fn new(client_login_finish_result: ClientLoginFinishResult<Scheme>) -> Self {
        Self {
            client_login_finish_result,
        }
    }

    pub fn to_data(&self) -> Vec<u8> {
        self.client_login_finish_result
            .message
            .serialize()
            .as_slice()
            .into()
    }

    pub fn step(self, server_key: Vec<u8>) -> AuthenticateFinish {
        AuthenticateFinish::new(server_key, self.client_login_finish_result)
    }
}

pub struct AuthenticateFinish {
    server_key: Vec<u8>,
    client_login_finish_result: ClientLoginFinishResult<Scheme>,
}

impl AuthenticateFinish {
    pub fn new(
        server_key: Vec<u8>,
        client_login_finish_result: ClientLoginFinishResult<Scheme>,
    ) -> Self {
        Self {
            server_key,
            client_login_finish_result,
        }
    }

    pub fn to_data(&self) -> bool {
        self.client_login_finish_result.session_key.to_vec() == self.server_key
    }

    pub fn step(self) -> AuthenticateConfirm {
        AuthenticateConfirm::new(
            self.client_login_finish_result.session_key.to_vec(),
            self.client_login_finish_result.export_key.to_vec(),
        )
    }
}

pub struct AuthenticateConfirm {
    session_key: Vec<u8>,
    export_key: Vec<u8>,
}

impl AuthenticateConfirm {
    pub fn new(session_key: Vec<u8>, export_key: Vec<u8>) -> Self {
        Self {
            session_key,
            export_key,
        }
    }

    pub fn session_key(&self) -> &[u8] {
        &self.session_key
    }

    pub fn export_key(&self) -> &[u8] {
        &self.export_key
    }
}

//
// let mut client_rng = OsRng;
//    let client_login_start_result =
//        match ClientLogin::<Scheme>::start(&mut client_rng, password.as_bytes()) {
//            Ok(res) => res,
//            Err(err) => {
//                return Err(ClientError::ProtocolError(err).into());
//            }
//        };
//    let credential_request_bytes = client_login_start_result.message.serialize();
//
//    let mut ws = self.connect("authenticate").await?;
//    let data = WithUsername {
//        username: username.as_bytes().into(),
//        data: credential_request_bytes.as_slice(),
//    };
//    let data = bincode::serialize(&data).unwrap();
//    // println!("Client sending");
//    // println!("Client sent: `{data:?}`");
//    ws.write_frame(Frame::new(
//        true,
//        OpCode::Binary,
//        None,
//        data.as_slice().into(),
//    ))
//    .await?;
//    let mut state = ClientAuthStateWrapper {
//        state: ClientAuthState::WaitingAuth,
//        client_login_finish_result: None,
//    };
//    let mut result = Ok(true);
//    loop {
//        let frame = ws.read_frame().await?;
//        match state.state {
//            ClientAuthState::WaitingAuth => match frame.opcode {
//                OpCode::Binary => {
//                    let credential_response_bytes = frame.payload.to_vec();
//                    // println!("Client received: `{:?}`", &credential_response_bytes);
//                    let credential_response =
//                        match CredentialResponse::deserialize(&credential_response_bytes) {
//                            Ok(res) => res,
//                            Err(err) => {
//                                result = Err(ClientError::ProtocolError(err));
//                                break;
//                            }
//                        };
//                    let client_login_finish_result =
//                        match client_login_start_result.state.clone().finish(
//                            password.as_bytes(),
//                            credential_response,
//                            ClientLoginFinishParameters::default(),
//                        ) {
//                            Ok(res) => res,
//                            Err(_err) => {
//                                result = Err(ClientError::NotAuthenticated);
//                                break;
//                            }
//                        };
//
//                    // println!(
//                    //     "Static key login: {:?}",
//                    //     client_login_finish_result.server_s_pk
//                    // );
//                    let credential_finalization_bytes =
//                        client_login_finish_result.message.serialize();
//                    println!(
//                        "credential finalization `{:?}`",
//                        &credential_finalization_bytes
//                    );
//                    ws.write_frame(Frame::new(
//                        true,
//                        OpCode::Binary,
//                        None,
//                        credential_finalization_bytes.as_slice().into(),
//                    ))
//                    .await?;
//                    state.state = ClientAuthState::LoginFinish;
//                    state.client_login_finish_result = Some(client_login_finish_result);
//                }
//                OpCode::Close => {
//                    println!("Prematurely closed");
//                    return Err(ClientError::ClosedEarly.into());
//                }
//                _ => {
//                    println!(
//                        "Unexpected frame received `{:?}` with `{:?}`",
//                        frame.opcode, frame.payload
//                    );
//                }
//            },
//            ClientAuthState::LoginFinish => match frame.opcode {
//                OpCode::Binary => {
//                    let client_login_finish_result =
//                        state.client_login_finish_result.clone().unwrap();
//                    let server_key = frame.payload.to_vec();
//                    let auth =
//                        client_login_finish_result.clone().session_key.to_vec() == server_key;
//                    result = Ok(auth);
//                    ws.write_frame(Frame::new(
//                        true,
//                        OpCode::Binary,
//                        None,
//                        if auth { vec![1] } else { vec![0] }.as_slice().into(),
//                    ))
//                    .await?;
//                    state.state = ClientAuthState::Confirm;
//                }
//                OpCode::Close => {
//                    println!("Prematurely closed");
//                    return Err(ClientError::ClosedEarly.into());
//                }
//                _ => {
//                    println!(
//                        "Unexpected frame received `{:?}` with `{:?}`",
//                        frame.opcode, frame.payload
//                    );
//                }
//            },
//            ClientAuthState::Confirm => match frame.opcode {
//                OpCode::Close => {
//                    println!("Done with authentication");
//                    break;
//                }
//                _ => {
//                    println!(
//                        "Unexpected frame received `{:?}` with `{:?}`",
//                        frame.opcode, frame.payload
//                    );
//                }
//            },
//        }
//    }
//    if let Err(err) = result {
//        Client::error(ws, &err).await?;
//        return Err(err.into());
//    }
//
//    result.map_err(|x| x.into())
//
