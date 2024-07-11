use opaque_ke::{
    CredentialFinalization, CredentialRequest, ServerLogin, ServerLoginFinishResult,
    ServerLoginStartParameters, ServerLoginStartResult, ServerRegistration, ServerSetup,
};
use rand::rngs::OsRng;

use crate::{Scheme, WithUsername};

use super::server::ServerError;

pub struct AuthWaiting {
    server_setup: ServerSetup<Scheme>,
}

impl AuthWaiting {
    pub fn new(server_setup: ServerSetup<Scheme>) -> Self {
        Self { server_setup }
    }

    pub fn step(self, initial_data: &[u8]) -> Result<AuthInitial, ServerError> {
        let data: WithUsername = bincode::deserialize(initial_data)?;
        let username = data.username;
        let credential_request_bytes = data.data;
        let credential_request = CredentialRequest::deserialize(credential_request_bytes)?;
        Ok(AuthInitial::new(
            username,
            credential_request,
            self.server_setup,
        ))
    }
}

pub struct AuthInitial<'a> {
    username: &'a [u8],
    credential_request: CredentialRequest<Scheme>,
    server_setup: ServerSetup<Scheme>,
}

impl<'a> AuthInitial<'a> {
    pub fn new(
        username: &'a [u8],
        credential_request: CredentialRequest<Scheme>,
        server_setup: ServerSetup<Scheme>,
    ) -> Self {
        Self {
            username,
            credential_request,
            server_setup,
        }
    }

    pub fn username(&self) -> &[u8] {
        &self.username
    }

    pub fn step(self, password_file_bytes: &[u8]) -> Result<AuthWithCreds, ServerError> {
        let password_file = ServerRegistration::<Scheme>::deserialize(&password_file_bytes)?;
        let server_login_start_result = ServerLogin::start(
            &mut OsRng,
            &self.server_setup,
            Some(password_file),
            self.credential_request,
            &self.username,
            ServerLoginStartParameters::default(),
        )?;
        Ok(AuthWithCreds::new(server_login_start_result))
    }
}

pub struct AuthWithCreds {
    server_login_start_result: ServerLoginStartResult<Scheme>,
}

impl AuthWithCreds {
    pub fn new(server_login_start_result: ServerLoginStartResult<Scheme>) -> Self {
        Self {
            server_login_start_result,
        }
    }

    pub fn to_data(&self) -> Vec<u8> {
        self.server_login_start_result
            .message
            .serialize()
            .as_slice()
            .into()
    }

    pub fn step(self, credential_finalization_bytes: &[u8]) -> Result<AuthFinal, ServerError> {
        let credential_finalization =
            CredentialFinalization::deserialize(&credential_finalization_bytes)?;
        let server_login_finish_result = self
            .server_login_start_result
            .state
            .finish(credential_finalization)?;
        Ok(AuthFinal::new(server_login_finish_result))
    }
}

pub struct AuthFinal {
    server_login_finish_result: ServerLoginFinishResult<Scheme>,
}

impl AuthFinal {
    pub fn new(server_login_finish_result: ServerLoginFinishResult<Scheme>) -> Self {
        Self {
            server_login_finish_result,
        }
    }

    pub fn to_data(&self) -> Vec<u8> {
        self.server_login_finish_result
            .session_key
            .as_slice()
            .into()
    }

    pub fn step(self, state: &[u8]) -> AuthConfirm {
        AuthConfirm::new(state == vec![1])
    }
}

pub struct AuthConfirm {
    authenticated: bool,
}

impl AuthConfirm {
    pub fn new(authenticated: bool) -> Self {
        Self { authenticated }
    }

    pub fn authenticated(&self) -> bool {
        self.authenticated
    }
}
