pub mod authenticate;
pub mod error;
pub mod registration;

use std::future::Future;

use authenticate::{AuthenticateConfirm, AuthenticateInitialize};
use error::ClientError;
use fastwebsockets::{handshake, FragmentCollector, Frame, OpCode};
use http_body_util::Empty;
use hyper::{
    header::{CONNECTION, UPGRADE},
    upgrade::Upgraded,
    Request,
};
use hyper_util::rt::TokioIo;
use pants_gen::password::PasswordSpec;
use registration::RegistrationInitialize;

pub struct Client {
    domain: String,
    port: u16,
}

impl Client {
    pub fn new(domain: String, port: u16) -> Self {
        Self { domain, port }
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
        ws.write_frame(Frame::close(err.to_code(), err.to_string().as_bytes()))
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

    pub async fn delete(&self, username: String, password: String) -> Result<bool, ClientError> {
        // setup authentication
        let mut ws = self.connect("delete").await?;
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

        let data = frame.payload.to_vec();

        // ignore the headers
        Ok(data[data.len() - 1] == 1)
    }
}
