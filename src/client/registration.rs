use opaque_ke::{
    ClientRegistration, ClientRegistrationFinishParameters, ClientRegistrationFinishResult,
    ClientRegistrationStartResult, RegistrationResponse,
};
use rand::rngs::OsRng;

use crate::{Scheme, WithUsername};

use super::error::ClientError;

pub struct RegistrationInitialize {
    username: String,
    password: String,
    client_rng: OsRng,
    client_registration_start_result: ClientRegistrationStartResult<Scheme>,
}

impl RegistrationInitialize {
    pub fn step(
        self,
        registration_response_bytes: Vec<u8>,
    ) -> Result<RegistrationWaiting, ClientError> {
        let registration_response =
            match RegistrationResponse::deserialize(&registration_response_bytes) {
                Ok(res) => res,
                Err(err) => {
                    return Err(ClientError::ProtocolError(err));
                }
            };

        let client_finish_registration_result =
            match self.client_registration_start_result.state.finish(
                &mut self.client_rng.clone(),
                self.password.as_bytes(),
                registration_response,
                ClientRegistrationFinishParameters::default(),
            ) {
                Ok(res) => res,
                Err(err) => {
                    return Err(ClientError::ProtocolError(err));
                }
            };

        Ok(RegistrationWaiting::new(client_finish_registration_result))
    }

    pub fn to_data(&self) -> Vec<u8> {
        let registration_request_bytes = self.client_registration_start_result.message.serialize();
        let with_username = WithUsername {
            username: self.username.as_bytes(),
            data: registration_request_bytes.as_slice(),
        };
        bincode::serialize(&with_username).unwrap()
    }

    pub fn new(username: String, password: String) -> Result<Self, ClientError> {
        let mut client_rng = OsRng;
        let client_registration_start_result =
            match ClientRegistration::<Scheme>::start(&mut client_rng, password.as_bytes()) {
                Ok(res) => res,
                Err(err) => {
                    return Err(ClientError::ProtocolError(err));
                }
            };
        Ok(Self {
            username,
            password,
            client_rng,
            client_registration_start_result,
        })
    }
}

pub struct RegistrationWaiting {
    client_finish_registration_result: ClientRegistrationFinishResult<Scheme>,
}

impl RegistrationWaiting {
    pub fn new(client_finish_registration_result: ClientRegistrationFinishResult<Scheme>) -> Self {
        Self {
            client_finish_registration_result,
        }
    }

    pub fn to_data(&self) -> Vec<u8> {
        self.client_finish_registration_result
            .message
            .serialize()
            .as_slice()
            .into()
    }

    pub fn step(self) -> RegistrationConfirm {
        RegistrationConfirm
    }
}

pub struct RegistrationConfirm;
