use std::future::Future;

use fastwebsockets::{handshake, FragmentCollector, Frame, OpCode, WebSocketError};
use http_body_util::Empty;
use hyper::{
    header::{CONNECTION, UPGRADE},
    upgrade::Upgraded,
    Request,
};
use hyper_util::rt::TokioIo;
use opaque_ke::{
    errors::ProtocolError, ClientLogin, ClientLoginFinishParameters, ClientLoginFinishResult,
    ClientRegistration, ClientRegistrationFinishParameters, CredentialResponse,
    RegistrationResponse,
};
use pants_gen::password::PasswordSpec;
use rand::rngs::OsRng;
use thiserror::Error;

use crate::{Scheme, WithUsername};

pub struct Client {
    domain: String,
    port: u16,
}

impl Client {
    pub fn new(domain: String, port: u16) -> Self {
        Self { domain, port }
    }
}

struct ClientRegStateWrapper {
    state: ClientRegState,
}

enum ClientRegState {
    WaitingReg,
    Confirm,
}

struct ClientAuthStateWrapper {
    state: ClientAuthState,
    client_login_finish_result: Option<ClientLoginFinishResult<Scheme>>,
}

enum ClientAuthState {
    WaitingAuth,
    LoginFinish,
    Confirm,
}

#[derive(Debug, Error)]
enum ClientError {
    #[error("Communication terminated early")]
    ClosedEarly,
    #[error("Protocal error `{0:?}`")]
    ProtocolError(ProtocolError),
    #[error("Failed to authenticate")]
    NotAuthenticated,
}

impl ClientError {
    fn to_code(&self) -> u16 {
        match self {
            Self::ClosedEarly => 1000,
            Self::ProtocolError(_) => 1008,
            Self::NotAuthenticated => 1008,
        }
    }
}

struct SpawnExecutor;

impl<Fut> hyper::rt::Executor<Fut> for SpawnExecutor
where
    Fut: Future + Send + 'static,
    Fut::Output: Send + 'static,
{
    fn execute(&self, fut: Fut) {
        tokio::task::spawn(fut);
    }
}

pub struct LoginStart {
    username: String,
    password: String,
}

impl LoginStart {
    pub fn new(username: String) -> Self {
        let password = PasswordSpec::default().generate().unwrap();
        Self { username, password }
    }

    pub fn confirm(self, password: String) -> Option<LoginInfo> {
        if password == self.password {
            Some(LoginInfo {
                username: self.username,
                password: self.password,
            })
        } else {
            None
        }
    }
}

pub struct LoginInfo {
    username: String,
    password: String,
}

impl LoginInfo {
    pub async fn authenticate(self, client: Client) -> anyhow::Result<bool> {
        client.authenticate_user(self.username, self.password).await
    }
}

impl Client {
    async fn connect(
        &self,
        endpoint: &str,
    ) -> anyhow::Result<FragmentCollector<TokioIo<Upgraded>>> {
        let dest = format!("{}:{}", self.domain, self.port);
        let stream = tokio::net::TcpStream::connect(&dest).await?;
        let req = Request::builder()
            .method("GET")
            .uri(format!("http://{dest}/{endpoint}"))
            .header("Host", dest)
            .header(UPGRADE, "websocket")
            .header(CONNECTION, "upgrade")
            .header(
                "Sec-WebSocket-Key",
                fastwebsockets::handshake::generate_key(),
            )
            .header("Sec-WebSocket-Version", "13")
            .body(Empty::<hyper::body::Bytes>::new())?;

        let (ws, _) = handshake::client(&SpawnExecutor, req, stream).await?;
        Ok(FragmentCollector::new(ws))
    }

    async fn error(
        mut ws: fastwebsockets::FragmentCollector<TokioIo<Upgraded>>,
        err: &ClientError,
    ) -> Result<(), WebSocketError> {
        ws.write_frame(Frame::close(
            err.to_code(),
            err.to_string().as_bytes().into(),
        ))
        .await?;
        Ok(())
    }

    pub async fn register_user(&self, username: String, password: String) -> anyhow::Result<()> {
        let mut ws = self.connect("registration").await?;

        let mut client_rng = OsRng;
        let client_registration_start_result =
            match ClientRegistration::<Scheme>::start(&mut client_rng, password.as_bytes()) {
                Ok(res) => res,
                Err(err) => {
                    return Err(ClientError::ProtocolError(err).into());
                }
            };
        let registration_request_bytes = client_registration_start_result.message.serialize();
        let client_state = client_registration_start_result.state;

        let username = username.as_bytes();
        let with_username = WithUsername {
            username: username.into(),
            data: registration_request_bytes.as_slice(),
        };
        // this should be fine as it is serializing a wrapper struct
        let data = bincode::serialize(&with_username).unwrap();

        println!("Client sending");
        println!("Client sent: `{data:?}`");
        ws.write_frame(Frame::new(
            true,
            OpCode::Binary,
            None,
            data.as_slice().into(),
        ))
        .await?;

        let mut state = ClientRegStateWrapper {
            state: ClientRegState::WaitingReg,
        };
        let mut result = Ok(());
        loop {
            let frame = ws.read_frame().await?;
            match state.state {
                ClientRegState::WaitingReg => match frame.opcode {
                    OpCode::Binary => {
                        let registration_response_bytes = frame.payload.to_vec();
                        // println!("Client received: `{:?}`", &registration_response_bytes);
                        let registration_response =
                            match RegistrationResponse::deserialize(&registration_response_bytes) {
                                Ok(res) => res,
                                Err(err) => {
                                    result = Err(ClientError::ProtocolError(err));
                                    break;
                                }
                            };

                        let client_finish_registration_result = match client_state.clone().finish(
                            &mut client_rng,
                            password.as_bytes(),
                            registration_response,
                            ClientRegistrationFinishParameters::default(),
                        ) {
                            Ok(res) => res,
                            Err(err) => {
                                result = Err(ClientError::ProtocolError(err));
                                break;
                            }
                        };

                        let message_bytes = client_finish_registration_result.message.serialize();
                        // println!("Client sending `{:?}`", &message_bytes);
                        ws.write_frame(Frame::new(
                            true,
                            OpCode::Binary,
                            None,
                            message_bytes.as_slice().into(),
                        ))
                        .await?;
                        state.state = ClientRegState::Confirm;
                    }
                    OpCode::Close => {
                        println!("Prematurely closed");
                        return Err(ClientError::ClosedEarly.into());
                    }
                    _ => {
                        println!(
                            "Unexpected frame received `{:?}` with `{:?}`",
                            frame.opcode, frame.payload
                        );
                    }
                },
                ClientRegState::Confirm => match frame.opcode {
                    OpCode::Close => {
                        println!("Communication ended");
                        break;
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
            Client::error(ws, &err).await?;
            return Err(err.into());
        }

        Ok(())
    }

    pub async fn authenticate_user(
        &self,
        username: String,
        password: String,
    ) -> anyhow::Result<bool> {
        let mut client_rng = OsRng;
        let client_login_start_result =
            match ClientLogin::<Scheme>::start(&mut client_rng, password.as_bytes()) {
                Ok(res) => res,
                Err(err) => {
                    return Err(ClientError::ProtocolError(err).into());
                }
            };
        let credential_request_bytes = client_login_start_result.message.serialize();

        let mut ws = self.connect("authenticate").await?;
        let data = WithUsername {
            username: username.as_bytes().into(),
            data: credential_request_bytes.as_slice(),
        };
        let data = bincode::serialize(&data).unwrap();
        // println!("Client sending");
        // println!("Client sent: `{data:?}`");
        ws.write_frame(Frame::new(
            true,
            OpCode::Binary,
            None,
            data.as_slice().into(),
        ))
        .await?;
        let mut state = ClientAuthStateWrapper {
            state: ClientAuthState::WaitingAuth,
            client_login_finish_result: None,
        };
        let mut result = Ok(true);
        loop {
            let frame = ws.read_frame().await?;
            match state.state {
                ClientAuthState::WaitingAuth => match frame.opcode {
                    OpCode::Binary => {
                        let credential_response_bytes = frame.payload.to_vec();
                        // println!("Client received: `{:?}`", &credential_response_bytes);
                        let credential_response =
                            match CredentialResponse::deserialize(&credential_response_bytes) {
                                Ok(res) => res,
                                Err(err) => {
                                    result = Err(ClientError::ProtocolError(err));
                                    break;
                                }
                            };
                        let client_login_finish_result =
                            match client_login_start_result.state.clone().finish(
                                password.as_bytes(),
                                credential_response,
                                ClientLoginFinishParameters::default(),
                            ) {
                                Ok(res) => res,
                                Err(_err) => {
                                    result = Err(ClientError::NotAuthenticated);
                                    break;
                                }
                            };

                        // println!(
                        //     "Static key login: {:?}",
                        //     client_login_finish_result.server_s_pk
                        // );
                        let credential_finalization_bytes =
                            client_login_finish_result.message.serialize();
                        println!(
                            "credential finalization `{:?}`",
                            &credential_finalization_bytes
                        );
                        ws.write_frame(Frame::new(
                            true,
                            OpCode::Binary,
                            None,
                            credential_finalization_bytes.as_slice().into(),
                        ))
                        .await?;
                        state.state = ClientAuthState::LoginFinish;
                        state.client_login_finish_result = Some(client_login_finish_result);
                    }
                    OpCode::Close => {
                        println!("Prematurely closed");
                        return Err(ClientError::ClosedEarly.into());
                    }
                    _ => {
                        println!(
                            "Unexpected frame received `{:?}` with `{:?}`",
                            frame.opcode, frame.payload
                        );
                    }
                },
                ClientAuthState::LoginFinish => match frame.opcode {
                    OpCode::Binary => {
                        let client_login_finish_result =
                            state.client_login_finish_result.clone().unwrap();
                        let server_key = frame.payload.to_vec();
                        let auth =
                            client_login_finish_result.clone().session_key.to_vec() == server_key;
                        result = Ok(auth);
                        ws.write_frame(Frame::new(
                            true,
                            OpCode::Binary,
                            None,
                            if auth { vec![1] } else { vec![0] }.as_slice().into(),
                        ))
                        .await?;
                        state.state = ClientAuthState::Confirm;
                    }
                    OpCode::Close => {
                        println!("Prematurely closed");
                        return Err(ClientError::ClosedEarly.into());
                    }
                    _ => {
                        println!(
                            "Unexpected frame received `{:?}` with `{:?}`",
                            frame.opcode, frame.payload
                        );
                    }
                },
                ClientAuthState::Confirm => match frame.opcode {
                    OpCode::Close => {
                        println!("Done with authentication");
                        break;
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
            Client::error(ws, &err).await?;
            return Err(err.into());
        }

        result.map_err(|x| x.into())
    }
}
