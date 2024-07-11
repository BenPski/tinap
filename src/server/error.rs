use boring_derive::From;
use fastwebsockets::{Frame, OpCode, WebSocketError};
use opaque_ke::errors::ProtocolError;
use thiserror::Error;

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
    Websocket(WebSocketError),
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
    pub fn to_code(&self) -> u16 {
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
