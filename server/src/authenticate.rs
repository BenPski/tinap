use super::error::ServerError;
use opaque_ke::{
    CredentialFinalization, CredentialRequest, ServerLogin, ServerLoginFinishResult,
    ServerLoginStartParameters, ServerLoginStartResult, ServerRegistration, ServerSetup,
};
use rand::rngs::OsRng;
use tinap::{Scheme, WithUsername};

pub struct AuthWaiting<'a> {
    server_setup: ServerSetup<Scheme<'a>>,
}

impl<'a> AuthWaiting<'a> {
    pub fn new(server_setup: ServerSetup<Scheme<'a>>) -> Self {
        Self { server_setup }
    }

    pub fn step(self, initial_data: Vec<u8>) -> Result<AuthInitial<'a>, ServerError> {
        let data: WithUsername = bincode::deserialize(&initial_data)?;
        let username = data.username;
        let credential_request_bytes = data.data;
        let credential_request = CredentialRequest::deserialize(credential_request_bytes)?;
        Ok(AuthInitial::new(
            username.into(),
            credential_request,
            self.server_setup,
        ))
    }
}

pub struct AuthInitial<'a> {
    username: Vec<u8>,
    credential_request: CredentialRequest<Scheme<'a>>,
    server_setup: ServerSetup<Scheme<'a>>,
}

impl<'a> AuthInitial<'a> {
    pub fn new(
        username: Vec<u8>,
        credential_request: CredentialRequest<Scheme<'a>>,
        server_setup: ServerSetup<Scheme<'a>>,
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

    pub fn step(self, password_file_bytes: Vec<u8>) -> Result<AuthWithCreds<'a>, ServerError> {
        let password_file = ServerRegistration::<Scheme>::deserialize(&password_file_bytes)?;
        let server_login_start_result = ServerLogin::start(
            &mut OsRng,
            &self.server_setup,
            Some(password_file),
            self.credential_request,
            &self.username,
            ServerLoginStartParameters::default(),
        )?;
        Ok(AuthWithCreds::new(self.username, server_login_start_result))
    }
}

pub struct AuthWithCreds<'a> {
    username: Vec<u8>,
    server_login_start_result: ServerLoginStartResult<Scheme<'a>>,
}

impl<'a> AuthWithCreds<'a> {
    pub fn new(
        username: Vec<u8>,
        server_login_start_result: ServerLoginStartResult<Scheme<'a>>,
    ) -> Self {
        Self {
            username,
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

    pub fn step(
        self,
        credential_finalization_bytes: Vec<u8>,
    ) -> Result<AuthFinal<'a>, ServerError> {
        let credential_finalization =
            CredentialFinalization::deserialize(&credential_finalization_bytes)?;
        let server_login_finish_result = self
            .server_login_start_result
            .state
            .finish(credential_finalization)?;
        Ok(AuthFinal::new(self.username, server_login_finish_result))
    }
}

pub struct AuthFinal<'a> {
    username: Vec<u8>,
    server_login_finish_result: ServerLoginFinishResult<Scheme<'a>>,
}

impl<'a> AuthFinal<'a> {
    pub fn new(
        username: Vec<u8>,
        server_login_finish_result: ServerLoginFinishResult<Scheme<'a>>,
    ) -> Self {
        Self {
            username,
            server_login_finish_result,
        }
    }

    pub fn to_data(&self) -> Vec<u8> {
        self.server_login_finish_result
            .session_key
            .as_slice()
            .into()
    }

    pub fn step(self, state: Vec<u8>) -> AuthConfirm {
        AuthConfirm::new(state == vec![1], self.username)
    }
}

pub struct AuthConfirm {
    authenticated: bool,
    username: Vec<u8>,
}

impl AuthConfirm {
    pub fn new(authenticated: bool, username: Vec<u8>) -> Self {
        Self {
            authenticated,
            username,
        }
    }

    pub fn authenticated(&self) -> bool {
        self.authenticated
    }

    pub fn username(&self) -> &[u8] {
        &self.username
    }
}
