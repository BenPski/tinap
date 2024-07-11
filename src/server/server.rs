use std::fs::{read, write};

use axum::{extract::State, response::IntoResponse};
use boring_derive::From;
use fastwebsockets::{upgrade, Frame, OpCode, WebSocketError};
use hyper::upgrade::Upgraded;
use hyper_util::rt::TokioIo;
use opaque_ke::{errors::ProtocolError, ServerSetup};
use rand::rngs::OsRng;
use thiserror::Error;

use crate::Scheme;

use super::{
    autheticate::{AuthConfirm, AuthWaiting},
    registration::RegWaiting,
};

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

#[derive(Debug, Error, From)]
pub enum ServerError {
    #[from(skip)]
    #[error("Communication terminated early")]
    ClosedEarly,
    #[from(skip)]
    #[error("User already exists")]
    UserAlreadyExists,
    #[from(skip)]
    #[error("User does not exist")]
    UserDoesNotExist,
    #[error("Protocol error `{0:?}`")]
    ProtocolError(ProtocolError),
    #[error("Websocket connection error `{0}`")]
    Websocket(fastwebsockets::WebSocketError),
    #[error("Error with io `{0}`")]
    IOError(std::io::Error),
    #[error("Error with http connection `{0}`")]
    HyperError(hyper::http::Error),
    #[error("Received unexpected frame `{0:?}` with `{1:?}`")]
    UnexpectedFrame(OpCode, Vec<u8>),
    #[error("Error deserializing data `{0}`")]
    Serialization(bincode::Error),
    #[error("Error interacting with database `{0}`")]
    Database(sled::Error),
}

impl<'a> From<Frame<'a>> for ServerError {
    fn from(value: Frame<'a>) -> Self {
        Self::UnexpectedFrame(value.opcode, value.payload.into())
    }
}

impl ServerError {
    // not sure how appropriate these are
    fn to_code(&self) -> u16 {
        match self {
            Self::ClosedEarly => 1000,
            Self::ProtocolError(_) => 1008,
            Self::Websocket(_) => 1002,
            Self::IOError(_) => 1002,
            Self::HyperError(_) => 1002,
            Self::UnexpectedFrame(_, _) => 1008,
            Self::Serialization(_) => 1008,
            Self::Database(_) => 1008,
            Self::UserAlreadyExists => 1008,
            Self::UserDoesNotExist => 1008,
        }
    }
}

impl Server {
    async fn close(
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

        let data = frame.payload.into();
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

        let data = frame.payload.into();
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
        ws.write_frame(Frame::close(1000, vec![1].as_slice().into()))
            .await?;

        Ok(())
    }

    async fn authenticate(&self, fut: upgrade::UpgradeFut) -> Result<AuthConfirm, ServerError> {
        let mut ws = fastwebsockets::FragmentCollector::new(fut.await?);
        let state = AuthWaiting::new(self.server_setup.clone());
        let frame = ws.read_frame().await?;
        let data = frame.payload.into();
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

        let state = match state.step(&password_file_bytes) {
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

        let data = frame.payload.into();
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

        let data = frame.payload.into();
        let state = state.step(data);

        ws.write_frame(Frame::close(1000, b"done".as_slice().into()))
            .await?;

        Ok(state)
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
