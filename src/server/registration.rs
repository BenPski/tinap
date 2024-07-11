use opaque_ke::{
    RegistrationRequest, RegistrationUpload, ServerRegistration, ServerRegistrationStartResult,
    ServerSetup,
};

use crate::{Scheme, WithUsername};

use super::error::ServerError;

/// initial waiting state, given the first message from the client can move to the next state
/// [`RegInitial`]
pub struct RegWaiting<'a> {
    server_setup: ServerSetup<Scheme<'a>>,
}

impl<'a> RegWaiting<'a> {
    pub fn step(self, initial_data: Vec<u8>) -> Result<RegInitial<'a>, ServerError> {
        let data: WithUsername = bincode::deserialize(&initial_data)?;
        let username = data.username;
        let registration_request_bytes = data.data;
        let registration_request = RegistrationRequest::deserialize(registration_request_bytes)?;
        let server_registration_start_result = ServerRegistration::<Scheme>::start(
            &self.server_setup,
            registration_request,
            username,
        )?;

        Ok(RegInitial::new(
            username.into(),
            server_registration_start_result,
        ))
    }

    pub fn new(server_setup: ServerSetup<Scheme<'a>>) -> Self {
        Self { server_setup }
    }
}

/// the second state after receiving the first message, with the next message data moves to
/// [`RegUpload`]
/// Arguably poorly named
pub struct RegInitial<'a> {
    username: Vec<u8>,
    server_registration_start_result: ServerRegistrationStartResult<Scheme<'a>>,
}

impl<'a> RegInitial<'a> {
    pub fn new(
        username: Vec<u8>,
        server_registration_start_result: ServerRegistrationStartResult<Scheme<'a>>,
    ) -> Self {
        Self {
            username,
            server_registration_start_result,
        }
    }

    pub fn to_data(&self) -> Vec<u8> {
        self.server_registration_start_result
            .message
            .serialize()
            .as_slice()
            .into()
    }

    pub fn step(self, message_bytes: Vec<u8>) -> Result<RegUpload, ServerError> {
        let registration_upload = RegistrationUpload::<Scheme>::deserialize(&message_bytes)?;
        let password_file = ServerRegistration::finish(registration_upload);
        let password_serialized = password_file.serialize();

        Ok(RegUpload::new(
            self.username,
            password_serialized.as_slice().into(),
        ))
    }
}

/// final state with the username and verification data stored in the database
/// Also arguably poorly named
pub struct RegUpload {
    username: Vec<u8>,
    password_serialized: Vec<u8>,
}

impl RegUpload {
    pub fn new(username: Vec<u8>, password_serialized: Vec<u8>) -> Self {
        Self {
            username,
            password_serialized,
        }
    }

    pub fn to_data(&self) -> (&[u8], &[u8]) {
        (&self.username, &self.password_serialized)
    }
}
