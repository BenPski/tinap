use opaque_ke::{
    RegistrationRequest, RegistrationUpload, ServerRegistration, ServerRegistrationStartResult,
    ServerSetup,
};

use crate::{Scheme, WithUsername};

use super::error::ServerError;

pub struct RegWaiting {
    server_setup: ServerSetup<Scheme>,
}

impl RegWaiting {
    pub fn step(self, initial_data: &[u8]) -> Result<RegInitial, ServerError> {
        let data: WithUsername = bincode::deserialize(initial_data)?;
        let username = data.username;
        let registration_request_bytes = data.data;
        let registration_request = RegistrationRequest::deserialize(registration_request_bytes)?;
        let server_registration_start_result = ServerRegistration::<Scheme>::start(
            &self.server_setup,
            registration_request,
            username,
        )?;

        Ok(RegInitial::new(username, server_registration_start_result))
    }

    pub fn new(server_setup: ServerSetup<Scheme>) -> Self {
        Self { server_setup }
    }
}

pub struct RegInitial<'a> {
    username: &'a [u8],
    server_registration_start_result: ServerRegistrationStartResult<Scheme>,
}

impl<'a> RegInitial<'a> {
    pub fn new(
        username: &'a [u8],
        server_registration_start_result: ServerRegistrationStartResult<Scheme>,
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

    pub fn step(self, message_bytes: &[u8]) -> Result<RegUpload<'a>, ServerError> {
        let registration_upload = RegistrationUpload::<Scheme>::deserialize(message_bytes)?;
        let password_file = ServerRegistration::finish(registration_upload);
        let password_serialized = password_file.serialize();

        Ok(RegUpload::new(
            self.username,
            password_serialized.as_slice().into(),
        ))
    }
}

pub struct RegUpload<'a> {
    username: &'a [u8],
    password_serialized: Vec<u8>,
}

impl<'a> RegUpload<'a> {
    pub fn new(username: &'a [u8], password_serialized: Vec<u8>) -> Self {
        Self {
            username,
            password_serialized,
        }
    }

    pub fn to_data(&self) -> (&[u8], &[u8]) {
        (self.username, &self.password_serialized)
    }
}
