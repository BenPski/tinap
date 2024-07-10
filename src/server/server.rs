use std::fs::{read, write};

use axum::{extract::State, response::IntoResponse};
use fastwebsockets::{upgrade, Frame, OpCode, WebSocketError};
use hyper::upgrade::Upgraded;
use hyper_util::rt::TokioIo;
use opaque_ke::{
    CredentialFinalization, CredentialRequest, RegistrationRequest, RegistrationUpload,
    ServerLogin, ServerLoginStartParameters, ServerLoginStartResult, ServerRegistration,
    ServerSetup,
};
use rand::rngs::OsRng;
use thiserror::Error;

use crate::{Scheme, WithUsername};

// NOTE: don't like how there is cloning shared data between states
// most of the error handling is a bit of a mess and it feels like it could be better organized

#[derive(Clone)]
pub struct Server {
    server_setup: ServerSetup<Scheme>,
    store: sled::Db,
}

impl Server {
    pub fn new(server_setup: ServerSetup<Scheme>, store: sled::Db) -> Self {
        Self {
            server_setup,
            store,
        }
    }

    pub fn initialize() -> Self {
        let server_setup = match read("server_setup") {
            Ok(data) => bincode::deserialize(&data).expect("Failed to deserialize server_setup"),
            Err(err) => {
                println!("Error reading server_setup: `{err}`");
                println!("Creating server_setup");
                let server_setup = ServerSetup::<Scheme>::new(&mut OsRng);
                let encode =
                    bincode::serialize(&server_setup).expect("Failed to serialize server_setup");
                write("server_setup", encode).expect("Failed to write file");
                server_setup
            }
        };
        Server {
            server_setup,
            store: sled::open("tinap_db").unwrap(),
        }
    }
}

struct ServerRegStateWrapper {
    state: ServerRegState,
    username: Vec<u8>,
}

enum ServerRegState {
    Initial,
    WaitingForFinal,
}

struct ServerAuthStateWrapper {
    state: ServerAuthState,
    server_login_start_result: Option<ServerLoginStartResult<Scheme>>,
}

enum ServerAuthState {
    Initial,
    WaitingForFinal,
    Confirm,
}

#[derive(Debug, Error)]
enum ServerError {
    #[error("Communication terminated early")]
    ClosedEarly,
    #[error("Failed to deserialize transferred data")]
    DeserializeFailure,
    #[error("registration error")]
    RegistrationError,
    #[error("Could not query database")]
    DBConnection,
    #[error("User already exists")]
    UserAlreadyExists,
    #[error("User is not registered")]
    NotRegistered,
    #[error("Login process failed")]
    LoginFailure,
}

impl ServerError {
    // not sure how appropriate these are
    fn to_code(&self) -> u16 {
        match self {
            Self::ClosedEarly => 1000,
            Self::DeserializeFailure => 1007,
            Self::RegistrationError => 1008,
            Self::DBConnection => 1011,
            Self::UserAlreadyExists => 1008,
            Self::NotRegistered => 1008,
            Self::LoginFailure => 1008,
        }
    }
}

impl Server {
    async fn error(
        mut ws: fastwebsockets::FragmentCollector<TokioIo<Upgraded>>,
        err: &ServerError,
    ) -> Result<(), WebSocketError> {
        ws.write_frame(Frame::close(
            err.to_code(),
            err.to_string().as_bytes().into(),
        ))
        .await?;
        Ok(())
    }

    async fn registration(&self, fut: upgrade::UpgradeFut) -> anyhow::Result<()> {
        let mut ws = fastwebsockets::FragmentCollector::new(fut.await?);
        let mut state = ServerRegStateWrapper {
            state: ServerRegState::Initial,
            username: vec![],
        };
        loop {
            let frame = ws.read_frame().await?;
            match state.state {
                ServerRegState::Initial => match frame.opcode {
                    OpCode::Binary => {
                        println!("Server registration start");

                        // extract data from payload
                        let frame_data = frame.payload.to_vec();
                        let data: WithUsername = if let Ok(data) = bincode::deserialize(&frame_data)
                        {
                            data
                        } else {
                            let err = ServerError::DeserializeFailure;
                            Server::error(ws, &err).await?;
                            return Err(err.into());
                        };
                        let username = data.username;
                        println!("Got username: `{:?}`", username);
                        let registration_request_bytes = data.data;

                        // handle registration
                        let registration_request =
                            match RegistrationRequest::deserialize(&registration_request_bytes) {
                                Ok(registration_request) => registration_request,
                                Err(_err) => {
                                    let err = ServerError::DeserializeFailure;
                                    Server::error(ws, &err).await?;
                                    return Err(err.into());
                                }
                            };
                        let server_registration_start_result =
                            match ServerRegistration::<Scheme>::start(
                                &self.server_setup,
                                registration_request,
                                username,
                            ) {
                                Ok(res) => res,
                                Err(_err) => {
                                    let err = ServerError::RegistrationError;
                                    Server::error(ws, &err).await?;
                                    return Err(err.into());
                                }
                            };
                        let registration_response_bytes =
                            server_registration_start_result.message.serialize();
                        let next_frame = Frame::new(
                            true,
                            OpCode::Binary,
                            None,
                            registration_response_bytes.as_slice().into(),
                        );

                        ws.write_frame(next_frame).await?;
                        state.state = ServerRegState::WaitingForFinal;
                        state.username = username.to_vec();
                    }
                    OpCode::Close => break,
                    _ => {}
                },
                ServerRegState::WaitingForFinal => match frame.opcode {
                    OpCode::Binary => {
                        println!("Server finalization");

                        // extract data
                        let message_bytes = frame.payload.to_vec();
                        // println!("Server received: `{:?}`", &message_bytes);

                        let registration_upload =
                            match RegistrationUpload::<Scheme>::deserialize(&message_bytes) {
                                Ok(res) => res,
                                Err(_err) => {
                                    let err = ServerError::RegistrationError;
                                    Server::error(ws, &err).await?;
                                    return Err(err.into());
                                }
                            };
                        let password_file = ServerRegistration::finish(registration_upload);
                        let password_serialized = password_file.serialize();

                        // insert credentials
                        let contains_key = match self.store.contains_key(&state.username) {
                            Ok(res) => res,
                            Err(_err) => {
                                let err = ServerError::DBConnection;
                                Server::error(ws, &err).await?;
                                return Err(err.into());
                            }
                        };
                        if !contains_key {
                            println!("Storing: {:?}, {:?}", &state.username, password_serialized);
                            if let Err(_err) = self
                                .store
                                .insert(&state.username, password_serialized.as_slice())
                            {
                                let err = ServerError::DBConnection;
                                Server::error(ws, &err).await?;
                                return Err(err.into());
                            }
                        } else {
                            let err = ServerError::UserAlreadyExists;
                            Server::error(ws, &err).await?;
                            return Err(err.into());
                        }

                        ws.write_frame(Frame::close(1000, b"done".as_slice().into()))
                            .await?;
                        return Ok(());
                    }
                    OpCode::Close => {
                        println!("Prematurely closed");
                        return Err(ServerError::ClosedEarly.into());
                    }
                    _ => {
                        println!(
                            "Unexpected frame received `{:?}` with `{:?}`",
                            frame.opcode, frame.payload
                        );
                    }
                },
            }
        }
        Ok(())
    }

    async fn authenticate(&self, fut: upgrade::UpgradeFut) -> anyhow::Result<()> {
        let mut ws = fastwebsockets::FragmentCollector::new(fut.await?);
        let mut state = ServerAuthStateWrapper {
            state: ServerAuthState::Initial,
            server_login_start_result: None,
        };
        let mut result = Ok(());
        loop {
            let frame = ws.read_frame().await?;
            match state.state {
                ServerAuthState::Initial => match frame.opcode {
                    OpCode::Binary => {
                        println!("Server login start");
                        let data = frame.payload.to_vec();
                        let data: WithUsername = match bincode::deserialize(&data) {
                            Ok(data) => data,
                            Err(_err) => {
                                result = Err(ServerError::DeserializeFailure);
                                break;
                            }
                        };
                        let username = data.username;
                        let credential_request_bytes = data.data;
                        println!("username: `{username:?}`");
                        let contains_key = match self.store.contains_key(username) {
                            Ok(res) => res,
                            Err(_err) => {
                                result = Err(ServerError::DBConnection);
                                break;
                            }
                        };
                        if !contains_key {
                            println!("User is not registered");
                            result = Err(ServerError::UserAlreadyExists);
                            break;
                        }
                        // println!("Server received: `{:?}`", &credential_request_bytes);
                        let password_lookup = match self.store.get(username) {
                            Ok(res) => res,
                            Err(_err) => {
                                result = Err(ServerError::DBConnection);
                                break;
                            }
                        };
                        let password_file_bytes = if let Some(res) = password_lookup {
                            res
                        } else {
                            result = Err(ServerError::NotRegistered);
                            break;
                        };
                        println!("Looked up: {:?}, {:?}", username, password_file_bytes);
                        let password_file =
                            match ServerRegistration::<Scheme>::deserialize(&password_file_bytes) {
                                Ok(res) => res,
                                Err(_err) => {
                                    result = Err(ServerError::DeserializeFailure);
                                    break;
                                }
                            };
                        let credential_request =
                            match CredentialRequest::deserialize(&credential_request_bytes) {
                                Ok(res) => res,
                                Err(_err) => {
                                    result = Err(ServerError::DeserializeFailure);
                                    break;
                                }
                            };
                        let server_login_start_result = match ServerLogin::start(
                            &mut OsRng,
                            &self.server_setup,
                            Some(password_file),
                            credential_request,
                            &username,
                            ServerLoginStartParameters::default(),
                        ) {
                            Ok(res) => res,
                            Err(_err) => {
                                result = Err(ServerError::LoginFailure);
                                break;
                            }
                        };
                        let credential_response_bytes =
                            server_login_start_result.message.serialize();

                        // println!("Server sending: `{credential_response_bytes:?}`");
                        ws.write_frame(Frame::new(
                            true,
                            OpCode::Binary,
                            None,
                            credential_response_bytes.as_slice().into(),
                        ))
                        .await?;
                        state.state = ServerAuthState::WaitingForFinal;
                        state.server_login_start_result = Some(server_login_start_result.clone());
                    }
                    OpCode::Close => {
                        println!("Prematurely closed");
                        return Err(ServerError::ClosedEarly.into());
                    }
                    _ => {
                        println!(
                            "Unexpected frame received `{:?}` with `{:?}`",
                            frame.opcode, frame.payload
                        );
                    }
                },
                ServerAuthState::WaitingForFinal => match frame.opcode {
                    OpCode::Binary => {
                        println!("Server finalization");
                        let credential_finalization_bytes = frame.payload.to_vec();

                        let server_login_start_result =
                            state.server_login_start_result.clone().unwrap();
                        // let server_login_finish_result =
                        //     CredentialFinalization::deserialize(&credential_finalization_bytes)
                        //         .and_then(|credential_finalization| {
                        //             server_login_start_result
                        //                 .state
                        //                 .finish(credential_finalization)
                        //         })
                        //         .map_err(|_| ServerError::LoginFailure)?;

                        let credential_finalization = match CredentialFinalization::deserialize(
                            &credential_finalization_bytes,
                        ) {
                            Ok(res) => res,
                            Err(_err) => {
                                result = Err(ServerError::DeserializeFailure);
                                break;
                            }
                        };
                        let server_login_finish_result = match server_login_start_result
                            .state
                            .finish(credential_finalization)
                        {
                            Ok(res) => res,
                            Err(_err) => {
                                result = Err(ServerError::LoginFailure);
                                break;
                            }
                        };

                        ws.write_frame(Frame::new(
                            true,
                            OpCode::Binary,
                            None,
                            server_login_finish_result.session_key.as_slice().into(),
                        ))
                        .await?;
                        state.state = ServerAuthState::Confirm;
                    }
                    OpCode::Close => {
                        println!("Prematurely closed");
                        return Err(ServerError::ClosedEarly.into());
                    }
                    _ => {
                        println!(
                            "Unexpected frame received `{:?}` with `{:?}`",
                            frame.opcode, frame.payload
                        );
                    }
                },
                ServerAuthState::Confirm => match frame.opcode {
                    OpCode::Binary => {
                        let status = frame.payload.to_vec();
                        let authenticated = vec![1] == status;
                        println!("Authenticated: `{authenticated}`");
                        ws.write_frame(Frame::close(1000, "done".as_bytes().into()))
                            .await?;
                        break;
                    }
                    OpCode::Close => {
                        println!("Prematurely closed");
                        return Err(ServerError::ClosedEarly.into());
                    }
                    _ => {
                        println!(
                            "Unexpected frame received `{:?}` with `{:?}`",
                            frame.opcode, frame.payload
                        );
                    }
                },
            }
        }

        if let Err(err) = result {
            Server::error(ws, &err).await?;
            return Err(err.into());
        }

        Ok(())
    }
}

pub async fn ws_registration(
    ws: upgrade::IncomingUpgrade,
    State(state): State<Server>,
) -> impl IntoResponse {
    let (response, fut) = ws.upgrade().unwrap();
    tokio::task::spawn(async move {
        if let Err(e) = state.registration(fut).await {
            eprintln!("Error in websocket connection: `{e}`");
        }
    });

    response
}

pub async fn ws_authenticate(
    ws: upgrade::IncomingUpgrade,
    State(state): State<Server>,
) -> impl IntoResponse {
    let (response, fut) = ws.upgrade().unwrap();
    tokio::task::spawn(async move {
        if let Err(e) = state.authenticate(fut).await {
            eprintln!("Error in websocket connection: `{e}`");
        }
    });

    response
}
