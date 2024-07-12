use boring_derive::From;
use fastwebsockets::WebSocketError;
use fastwebsockets::{Frame, OpCode};
use opaque_ke::errors::ProtocolError;
use thiserror::Error;

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
    Websocket(WebSocketError),
    #[error("Error with io `{0}`")]
    IOError(std::io::Error),
    #[error("Error with http communication `{0}`")]
    HyperError(hyper::http::Error),
    #[error("Received unexpected frame `{0:?}` with `{1:?}`")]
    UnexpectedFrame(OpCode, Vec<u8>),
}

impl ClientError {
    pub fn to_code(&self) -> u16 {
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
