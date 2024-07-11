use opaque_ke::{
    ClientLogin, ClientLoginFinishParameters, ClientLoginFinishResult, ClientLoginStartResult,
    CredentialResponse,
};
use rand::rngs::OsRng;

use crate::{Scheme, WithUsername};

use super::error::ClientError;

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
            username: self.username.as_bytes(),
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
                    return Err(ClientError::ProtocolError(err));
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
