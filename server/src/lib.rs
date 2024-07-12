pub mod authenticate;
pub mod error;
pub mod registration;

use std::fs::{read, write};

use authenticate::{AuthConfirm, AuthWaiting};
use axum::{extract::State, response::IntoResponse};
use error::ServerError;
use fastwebsockets::{upgrade, Frame, OpCode, WebSocketError};
use hyper::upgrade::Upgraded;
use hyper_util::rt::TokioIo;
use opaque_ke::ServerSetup;
use rand::rngs::OsRng;
use registration::RegWaiting;

use tinap::Scheme;

/// [`Server`] maintains the server side setup for OPAQUE protocol, maintains the connection to the
/// underlying `sled` database, and responds to the websocket connections
#[derive(Clone)]
pub struct Server<'a> {
    server_setup: ServerSetup<Scheme<'a>>,
    store: sled::Db,
}

impl<'a> Server<'a> {
    pub fn new(server_setup: ServerSetup<Scheme<'a>>, store: sled::Db) -> Self {
        Self {
            server_setup,
            store,
        }
    }

    /// ensures that the server makes use of previously established keys and connects to the
    /// database. Opens or creates files as needed
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

impl<'a> Server<'a> {
    /// wrapper to send a `Close` message in case there is an error
    async fn close(
        mut ws: fastwebsockets::FragmentCollector<TokioIo<Upgraded>>,
        err: &ServerError,
    ) -> Result<(), WebSocketError> {
        ws.write_frame(Frame::close(err.to_code(), err.to_string().as_bytes()))
            .await?;
        Ok(())
    }

    /// handle a registration request
    async fn registration(&self, fut: upgrade::UpgradeFut) -> Result<(), ServerError> {
        let mut ws = fastwebsockets::FragmentCollector::new(fut.await?);
        let state = RegWaiting::new(self.server_setup.clone());
        let frame = ws.read_frame().await?;
        match frame.opcode {
            OpCode::Binary => {}
            OpCode::Close => {
                let err = ServerError::ClosedEarly;
                return Err(err);
            }
            _ => {
                let err = frame.into();
                Self::close(ws, &err).await?;
                return Err(err);
            }
        }

        let data = frame.payload.to_vec();
        let state = match state.step(data) {
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
            OpCode::Binary => {}
            OpCode::Close => {
                return Err(ServerError::ClosedEarly);
            }
            _ => {
                let err = frame.into();
                Self::close(ws, &err).await?;
                return Err(err);
            }
        }

        let data = frame.payload.to_vec();
        let state = match state.step(data) {
            Ok(res) => res,
            Err(err) => {
                Self::close(ws, &err).await?;
                return Err(err);
            }
        };

        let (username, password_serialized) = state.to_data();
        let contains_key = match self.store.contains_key(username) {
            Ok(res) => res,
            Err(err) => {
                let err = err.into();
                Server::close(ws, &err).await?;
                return Err(err);
            }
        };
        if contains_key {
            let err = ServerError::UserAlreadyExists;
            Self::close(ws, &err).await?;
            return Err(err);
        }

        if let Err(err) = self.store.insert(username, password_serialized) {
            let err = err.into();
            Self::close(ws, &err).await?;
            return Err(err);
        }

        // let client know registration is complete
        ws.write_frame(Frame::close(1000, vec![1].as_slice()))
            .await?;

        Ok(())
    }

    /// handle an authentication request
    async fn authenticate(&self, fut: upgrade::UpgradeFut) -> Result<AuthConfirm, ServerError> {
        let mut ws = fastwebsockets::FragmentCollector::new(fut.await?);
        let state = AuthWaiting::new(self.server_setup.clone());
        let frame = ws.read_frame().await?;
        let data = frame.payload.to_vec();
        let state = match state.step(data) {
            Ok(res) => res,
            Err(err) => {
                Self::close(ws, &err).await?;
                return Err(err);
            }
        };

        let password_file_bytes = match self.store.get(state.username()) {
            Ok(res) => {
                if let Some(res) = res {
                    res
                } else {
                    let err = ServerError::UserDoesNotExist;
                    Self::close(ws, &err).await?;
                    return Err(err);
                }
            }
            Err(err) => {
                let err = err.into();
                Self::close(ws, &err).await?;
                return Err(err);
            }
        };

        let state = match state.step(password_file_bytes.to_vec()) {
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
            OpCode::Binary => {}
            OpCode::Close => {
                return Err(ServerError::ClosedEarly);
            }
            _ => {
                let err = frame.into();
                Self::close(ws, &err).await?;
                return Err(err);
            }
        }

        let data = frame.payload.to_vec();
        let state = match state.step(data) {
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
            OpCode::Binary => {}
            OpCode::Close => {
                return Err(ServerError::ClosedEarly);
            }
            _ => {
                let err = frame.into();
                Self::close(ws, &err).await?;
                return Err(err);
            }
        }

        let data = frame.payload.to_vec();
        let state = state.step(data);

        ws.write_frame(Frame::close(1000, b"done".as_slice()))
            .await?;

        Ok(state)
    }

    /// handle a delete request
    async fn delete(&self, fut: upgrade::UpgradeFut) -> Result<bool, ServerError> {
        let mut ws = fastwebsockets::FragmentCollector::new(fut.await?);
        let state = AuthWaiting::new(self.server_setup.clone());
        let frame = ws.read_frame().await?;
        let data = frame.payload.to_vec();
        let state = match state.step(data) {
            Ok(res) => res,
            Err(err) => {
                Self::close(ws, &err).await?;
                return Err(err);
            }
        };

        let password_file_bytes = match self.store.get(state.username()) {
            Ok(res) => {
                if let Some(res) = res {
                    res
                } else {
                    let err = ServerError::UserDoesNotExist;
                    Self::close(ws, &err).await?;
                    return Err(err);
                }
            }
            Err(err) => {
                let err = err.into();
                Self::close(ws, &err).await?;
                return Err(err);
            }
        };

        let state = match state.step(password_file_bytes.to_vec()) {
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
            OpCode::Binary => {}
            OpCode::Close => {
                return Err(ServerError::ClosedEarly);
            }
            _ => {
                let err = frame.into();
                Self::close(ws, &err).await?;
                return Err(err);
            }
        }

        let data = frame.payload.to_vec();
        let state = match state.step(data) {
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
            OpCode::Binary => {}
            OpCode::Close => {
                return Err(ServerError::ClosedEarly);
            }
            _ => {
                let err = frame.into();
                Self::close(ws, &err).await?;
                return Err(err);
            }
        }

        let data = frame.payload.to_vec();
        let state = state.step(data);

        let removed = if state.authenticated() {
            let res = match self.store.remove(state.username()) {
                Ok(res) => res,
                Err(err) => {
                    let err = err.into();
                    Self::close(ws, &err).await?;
                    return Err(err);
                }
            };
            res.is_some()
        } else {
            false
        };
        let response = if removed { vec![1] } else { vec![0] };
        ws.write_frame(Frame::close(1000, response.as_slice()))
            .await?;

        Ok(removed)
    }
}

/// hook for calling the registration endpoint
pub async fn ws_registration(
    ws: upgrade::IncomingUpgrade,
    State(state): State<Server<'static>>,
) -> impl IntoResponse {
    let (response, fut) = ws.upgrade().unwrap();
    tokio::task::spawn(async move {
        if let Err(e) = state.registration(fut).await {
            eprintln!("Error in websocket connection: `{e}`");
        }
    });

    response
}

/// hook for calling the authentication endpoint
pub async fn ws_authenticate(
    ws: upgrade::IncomingUpgrade,
    State(state): State<Server<'static>>,
) -> impl IntoResponse {
    let (response, fut) = ws.upgrade().unwrap();
    tokio::task::spawn(async move {
        if let Err(e) = state.authenticate(fut).await {
            eprintln!("Error in websocket connection: `{e}`");
        }
    });

    response
}

/// hook for calling the authentication endpoint
pub async fn ws_delete(
    ws: upgrade::IncomingUpgrade,
    State(state): State<Server<'static>>,
) -> impl IntoResponse {
    let (response, fut) = ws.upgrade().unwrap();
    tokio::task::spawn(async move {
        if let Err(e) = state.delete(fut).await {
            eprintln!("Error in websocket connection: `{e}`");
        }
    });

    response
}
