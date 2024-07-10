use std::future::Future;

use boring_derive::From;
use fastwebsockets::{handshake, FragmentCollector, Frame, OpCode};
use http_body_util::Empty;
use hyper::{
    header::{CONNECTION, UPGRADE},
    upgrade::Upgraded,
    Request,
};
use hyper_util::rt::TokioIo;
use opaque_ke::errors::ProtocolError;
use pants_gen::password::PasswordSpec;
use thiserror::Error;

use super::{
    authenticate::{AuthenticateConfirm, AuthenticateInitialize},
    registration::RegistrationInitialize,
};

pub struct Client {
    domain: String,
    port: u16,
}

impl Client {
    pub fn new(domain: String, port: u16) -> Self {
        Self { domain, port }
    }
}

#[derive(Debug, Error, From)]
pub enum ClientError {
    #[from(skip)]
    #[error("Communication terminated early")]
    ClosedEarly,
    #[error("Protocal error `{0:?}`")]
    ProtocolError(ProtocolError),
    #[from(skip)]
    #[error("Failed to authenticate")]
    NotAuthenticated,
    #[error("Websocket connection error `{0}`")]
    Websocket(fastwebsockets::WebSocketError),
    #[error("Error with io `{0}`")]
    IOError(std::io::Error),
    #[error("Error with http communication `{0}`")]
    HyperError(hyper::http::Error),
    #[error("Received unexpected frame `{0:?}` with `{1:?}`")]
    UnexpectedFrame(OpCode, Vec<u8>),
}

impl ClientError {
    fn to_code(&self) -> u16 {
        match self {
            Self::ClosedEarly => 1000,
            Self::ProtocolError(_) => 1008,
            Self::NotAuthenticated => 1008,
            Self::Websocket(_) => 1002,
            Self::IOError(_) => 1002,
            Self::HyperError(_) => 1002,
            Self::UnexpectedFrame(_, _) => 1008,
        }
    }
}

impl<'a> From<Frame<'a>> for ClientError {
    fn from(value: Frame) -> Self {
        Self::UnexpectedFrame(value.opcode, value.payload.to_vec())
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
    pub async fn authenticate(
        self,
        client: Client,
    ) -> Result<Option<AuthenticateConfirm>, ClientError> {
        client.authenticate(self.username, self.password).await
    }
}

impl Client {
    async fn connect(
        &self,
        endpoint: &str,
    ) -> Result<FragmentCollector<TokioIo<Upgraded>>, ClientError> {
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

    async fn close(
        mut ws: fastwebsockets::FragmentCollector<TokioIo<Upgraded>>,
        err: &ClientError,
    ) -> Result<(), ClientError> {
        ws.write_frame(Frame::close(
            err.to_code(),
            err.to_string().as_bytes().into(),
        ))
        .await?;
        Ok(())
    }

    pub async fn register(&self, username: String, password: String) -> Result<bool, ClientError> {
        let mut ws = self.connect("registration").await?;
        let state = RegistrationInitialize::new(username, password)?;

        let data = state.to_data();
        ws.write_frame(Frame::new(true, OpCode::Binary, None, data.into()))
            .await?;
        let frame = ws.read_frame().await?;

        match frame.opcode {
            OpCode::Close => return Err(ClientError::ClosedEarly),
            OpCode::Binary => {}
            _ => {
                let err = frame.into();
                Self::close(ws, &err).await?;
                return Err(err);
            }
        }

        let registration_response_bytes = frame.payload.to_vec();
        let state = match state.step(registration_response_bytes) {
            Ok(res) => res,
            Err(err) => {
                Self::close(ws, &err).await?;
                return Err(err);
            }
        };

        let data = state.to_data();
        ws.write_frame(Frame::new(true, OpCode::Binary, None, data.into()))
            .await?;
        let frame = ws.read_frame().await?;

        match frame.opcode {
            OpCode::Close => {}
            _ => {
                let err = frame.into();
                Self::close(ws, &err).await?;
                return Err(err);
            }
        }

        Ok(true)
    }

    pub async fn authenticate(
        &self,
        username: String,
        password: String,
    ) -> Result<Option<AuthenticateConfirm>, ClientError> {
        // setup authentication
        let mut ws = self.connect("authenticate").await?;
        let state = AuthenticateInitialize::new(username, password)?;
        let data = state.to_data();

        // send and receive with server
        ws.write_frame(Frame::new(true, OpCode::Binary, None, data.into()))
            .await?;
        let frame = ws.read_frame().await?;
        match frame.opcode {
            OpCode::Binary => {}
            OpCode::Close => {
                return Err(ClientError::ClosedEarly);
            }
            _ => {
                let err = frame.into();
                Self::close(ws, &err).await?;
                return Err(err);
            }
        }

        // advance state
        let credential_response_bytes = frame.payload.to_vec();
        let state = match state.step(credential_response_bytes) {
            Ok(res) => res,
            Err(err) => {
                Self::close(ws, &err).await?;
                return Err(err);
            }
        };
        let data = state.to_data();

        // send and receive with server
        ws.write_frame(Frame::new(true, OpCode::Binary, None, data.into()))
            .await?;
        let frame = ws.read_frame().await?;
        match frame.opcode {
            OpCode::Binary => {}
            OpCode::Close => return Err(ClientError::ClosedEarly),
            _ => {
                let err = frame.into();
                Self::close(ws, &err).await?;
                return Err(err);
            }
        };

        // check if authentication passed
        let server_key = frame.payload.into();
        let state = state.step(server_key);
        let auth = state.to_data();

        // let server know state of authentication
        let data = if auth { vec![1] } else { vec![0] };
        ws.write_frame(Frame::new(true, OpCode::Binary, None, data.into()))
            .await?;
        let frame = ws.read_frame().await?;
        match frame.opcode {
            OpCode::Close => {}
            _ => {
                let err = frame.into();
                Self::close(ws, &err).await?;
                return Err(err);
            }
        };

        let state = state.step();

        let auth = if auth { Some(state) } else { None };

        Ok(auth)
    }

    // pub async fn authenticate_user(
    //     &self,
    //     username: String,
    //     password: String,
    // ) -> anyhow::Result<bool> {
    //     let mut client_rng = OsRng;
    //     let client_login_start_result =
    //         match ClientLogin::<Scheme>::start(&mut client_rng, password.as_bytes()) {
    //             Ok(res) => res,
    //             Err(err) => {
    //                 return Err(ClientError::ProtocolError(err).into());
    //             }
    //         };
    //     let credential_request_bytes = client_login_start_result.message.serialize();
    //
    //     let mut ws = self.connect("authenticate").await?;
    //     let data = WithUsername {
    //         username: username.as_bytes().into(),
    //         data: credential_request_bytes.as_slice(),
    //     };
    //     let data = bincode::serialize(&data).unwrap();
    //     // println!("Client sending");
    //     // println!("Client sent: `{data:?}`");
    //     ws.write_frame(Frame::new(
    //         true,
    //         OpCode::Binary,
    //         None,
    //         data.as_slice().into(),
    //     ))
    //     .await?;
    //     let mut state = ClientAuthStateWrapper {
    //         state: ClientAuthState::WaitingAuth,
    //         client_login_finish_result: None,
    //     };
    //     let mut result = Ok(true);
    //     loop {
    //         let frame = ws.read_frame().await?;
    //         match state.state {
    //             ClientAuthState::WaitingAuth => match frame.opcode {
    //                 OpCode::Binary => {
    //                     let credential_response_bytes = frame.payload.to_vec();
    //                     // println!("Client received: `{:?}`", &credential_response_bytes);
    //                     let credential_response =
    //                         match CredentialResponse::deserialize(&credential_response_bytes) {
    //                             Ok(res) => res,
    //                             Err(err) => {
    //                                 result = Err(ClientError::ProtocolError(err));
    //                                 break;
    //                             }
    //                         };
    //                     let client_login_finish_result =
    //                         match client_login_start_result.state.clone().finish(
    //                             password.as_bytes(),
    //                             credential_response,
    //                             ClientLoginFinishParameters::default(),
    //                         ) {
    //                             Ok(res) => res,
    //                             Err(_err) => {
    //                                 result = Err(ClientError::NotAuthenticated);
    //                                 break;
    //                             }
    //                         };
    //
    //                     // println!(
    //                     //     "Static key login: {:?}",
    //                     //     client_login_finish_result.server_s_pk
    //                     // );
    //                     let credential_finalization_bytes =
    //                         client_login_finish_result.message.serialize();
    //                     println!(
    //                         "credential finalization `{:?}`",
    //                         &credential_finalization_bytes
    //                     );
    //                     ws.write_frame(Frame::new(
    //                         true,
    //                         OpCode::Binary,
    //                         None,
    //                         credential_finalization_bytes.as_slice().into(),
    //                     ))
    //                     .await?;
    //                     state.state = ClientAuthState::LoginFinish;
    //                     state.client_login_finish_result = Some(client_login_finish_result);
    //                 }
    //                 OpCode::Close => {
    //                     println!("Prematurely closed");
    //                     return Err(ClientError::ClosedEarly.into());
    //                 }
    //                 _ => {
    //                     println!(
    //                         "Unexpected frame received `{:?}` with `{:?}`",
    //                         frame.opcode, frame.payload
    //                     );
    //                 }
    //             },
    //             ClientAuthState::LoginFinish => match frame.opcode {
    //                 OpCode::Binary => {
    //                     let client_login_finish_result =
    //                         state.client_login_finish_result.clone().unwrap();
    //                     let server_key = frame.payload.to_vec();
    //                     let auth =
    //                         client_login_finish_result.clone().session_key.to_vec() == server_key;
    //                     result = Ok(auth);
    //                     ws.write_frame(Frame::new(
    //                         true,
    //                         OpCode::Binary,
    //                         None,
    //                         if auth { vec![1] } else { vec![0] }.as_slice().into(),
    //                     ))
    //                     .await?;
    //                     state.state = ClientAuthState::Confirm;
    //                 }
    //                 OpCode::Close => {
    //                     println!("Prematurely closed");
    //                     return Err(ClientError::ClosedEarly.into());
    //                 }
    //                 _ => {
    //                     println!(
    //                         "Unexpected frame received `{:?}` with `{:?}`",
    //                         frame.opcode, frame.payload
    //                     );
    //                 }
    //             },
    //             ClientAuthState::Confirm => match frame.opcode {
    //                 OpCode::Close => {
    //                     println!("Done with authentication");
    //                     break;
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
    //     if let Err(err) = result {
    //         Client::error(ws, &err).await?;
    //         return Err(err.into());
    //     }
    //
    //     result.map_err(|x| x.into())
    // }
}
