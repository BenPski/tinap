use std::marker::PhantomData;

use generic_array::{ArrayLength, GenericArray};
use opaque_ke::{errors::InternalError, ksf::Ksf, CipherSuite};
use serde::{Deserialize, Serialize};

pub mod client;
pub mod server;

#[derive(Debug, Clone, Copy)]
pub struct Scheme<'a> {
    _lifetime: PhantomData<&'a ()>,
}

impl<'a> CipherSuite for Scheme<'a> {
    type OprfCs = opaque_ke::Ristretto255;
    type KeGroup = opaque_ke::Ristretto255;
    type KeyExchange = opaque_ke::key_exchange::tripledh::TripleDh;
    type Ksf = Argon2<'a>;
}

#[derive(Debug, Serialize, Deserialize)]
pub struct WithUsername<'a> {
    pub username: &'a [u8],
    pub data: &'a [u8],
}

#[derive(Default)]
pub struct Argon2<'a>(argon2::Argon2<'a>);
const ARGON2_RECOMMENDED_SALT_LEN: usize = 16;
impl Ksf for Argon2<'_> {
    fn hash<L: ArrayLength<u8>>(
        &self,
        input: GenericArray<u8, L>,
    ) -> Result<GenericArray<u8, L>, InternalError> {
        let mut output = GenericArray::default();
        self.0
            .hash_password_into(&input, &[0; ARGON2_RECOMMENDED_SALT_LEN], &mut output)
            .map_err(|_| InternalError::KsfError)?;
        Ok(output)
    }
}
