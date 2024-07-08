use opaque_ke::CipherSuite;
use serde::{Deserialize, Serialize};

pub mod client;
pub mod server;

#[derive(Debug, Clone, Copy)]
pub struct Scheme;

impl CipherSuite for Scheme {
    type OprfCs = opaque_ke::Ristretto255;
    type KeGroup = opaque_ke::Ristretto255;
    type KeyExchange = opaque_ke::key_exchange::tripledh::TripleDh;
    type Ksf = opaque_ke::ksf::Identity;
}

#[derive(Debug, Serialize, Deserialize)]
pub struct WithUsername {
    pub username: Vec<u8>,
    pub data: Vec<u8>,
}
