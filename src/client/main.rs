use std::future::Future;

use fastwebsockets::{handshake, FragmentCollector, Frame, OpCode};
use http_body_util::Empty;
use hyper::{
    header::{CONNECTION, UPGRADE},
    upgrade::Upgraded,
    Request,
};
use hyper_util::rt::TokioIo;
use opaque_ke::{
    ClientLogin, ClientLoginFinishParameters, ClientRegistration,
    ClientRegistrationFinishParameters, CredentialResponse, RegistrationResponse,
};
use rand::rngs::OsRng;
use tinap::{Scheme, WithUsername};

async fn connect(
    domain: &str,
    port: usize,
    endpoint: &str,
) -> anyhow::Result<FragmentCollector<TokioIo<Upgraded>>> {
    let dest = format!("{}:{}", domain, port);
    let stream = tokio::net::TcpStream::connect(&dest).await?;
    let req = Request::builder()
        .method("GET")
        .uri(format!("http://{dest}/{endpoint}"))
        .header("Host", dest)
        .header(UPGRADE, "websocket")
        .header(CONNECTION, "upgrade")
        .header(
            "Sec-WebSocket-Key",
            fastwebsockets::handshake::generate_key(),
        )
        .header("Sec-WebSocket-Version", "13")
        .body(Empty::<hyper::body::Bytes>::new())?;

    let (ws, _) = handshake::client(&SpawnExecutor, req, stream).await?;
    Ok(FragmentCollector::new(ws))
}

struct SpawnExecutor;

impl<Fut> hyper::rt::Executor<Fut> for SpawnExecutor
where
    Fut: Future + Send + 'static,
    Fut::Output: Send + 'static,
{
    fn execute(&self, fut: Fut) {
        tokio::task::spawn(fut);
    }
}

async fn register_user(username: String, password: String) -> anyhow::Result<()> {
    let mut client_rng = OsRng;
    let client_registration_start_result =
        ClientRegistration::<Scheme>::start(&mut client_rng, password.as_bytes()).unwrap();
    let registration_request_bytes = client_registration_start_result.message.serialize();
    let client_state = client_registration_start_result.state;

    let username = username.as_bytes();
    let with_username = WithUsername {
        username: username.into(),
        data: registration_request_bytes.as_slice(),
    };
    let data = bincode::serialize(&with_username).unwrap();

    let mut ws = connect("127.0.0.1", 6969, "registration").await.unwrap();
    println!("Client sending");
    println!("Client sent: `{data:?}`");
    ws.write_frame(Frame::new(
        true,
        OpCode::Binary,
        None,
        data.as_slice().into(),
    ))
    .await
    .unwrap();
    loop {
        let frame = ws.read_frame().await.unwrap();
        match frame.opcode {
            OpCode::Binary => {
                let registration_response_bytes = frame.payload.to_vec();
                println!("Client received: `{:?}`", &registration_response_bytes);

                let client_finish_registration_result = client_state
                    .clone()
                    .finish(
                        &mut client_rng,
                        password.as_bytes(),
                        RegistrationResponse::deserialize(&registration_response_bytes).unwrap(),
                        ClientRegistrationFinishParameters::default(),
                    )
                    .unwrap();
                let message_bytes = client_finish_registration_result.message.serialize();
                println!("Client sending `{:?}`", &message_bytes);
                ws.write_frame(Frame::new(
                    true,
                    OpCode::Binary,
                    None,
                    message_bytes.as_slice().into(),
                ))
                .await
                .unwrap();
            }
            OpCode::Close => {
                println!("Done with registration");
                break;
            }
            _ => {}
        }
    }
    Ok(())
}

async fn authenticate_user(username: String, password: String) -> anyhow::Result<bool> {
    let mut auth = false;
    let mut client_rng = OsRng;
    let client_login_start_result =
        ClientLogin::<Scheme>::start(&mut client_rng, password.as_bytes()).unwrap();
    let credential_request_bytes = client_login_start_result.message.serialize();

    let mut ws = connect("127.0.0.1", 6969, "authenticate").await.unwrap();
    let data = WithUsername {
        username: username.as_bytes().into(),
        data: credential_request_bytes.as_slice(),
    };
    let data = bincode::serialize(&data).unwrap();
    println!("Client sending");
    println!("Client sent: `{data:?}`");
    ws.write_frame(Frame::new(
        true,
        OpCode::Binary,
        None,
        data.as_slice().into(),
    ))
    .await
    .unwrap();
    let frame = ws.read_frame().await.unwrap();
    match frame.opcode {
        OpCode::Binary => {
            let credential_response_bytes = frame.payload.to_vec();
            println!("Client received: `{:?}`", &credential_response_bytes);
            let result = client_login_start_result.state.clone().finish(
                password.as_bytes(),
                CredentialResponse::deserialize(&credential_response_bytes).unwrap(),
                ClientLoginFinishParameters::default(),
            );

            if result.is_err() {
                ws.write_frame(Frame::close(1000, b"not authenitcated".as_slice()))
                    .await?;
                auth = false;
            } else {
                let client_login_finish_result = result.unwrap();
                let credential_finalization_bytes = client_login_finish_result.message.serialize();
                println!(
                    "credential finalization `{:?}`",
                    &credential_finalization_bytes
                );
                ws.write_frame(Frame::new(
                    true,
                    OpCode::Binary,
                    None,
                    credential_finalization_bytes.as_slice().into(),
                ))
                .await
                .unwrap();

                let session_frame = ws.read_frame().await?;
                match session_frame.opcode {
                    OpCode::Binary => {
                        let server_key = session_frame.payload.to_vec();
                        auth = client_login_finish_result.session_key.to_vec() == server_key;
                        ws.write_frame(Frame::new(
                            true,
                            OpCode::Binary,
                            None,
                            if auth { vec![1] } else { vec![0] }.as_slice().into(),
                        ))
                        .await
                        .unwrap();
                        let final_frame = ws.read_frame().await?;
                        match final_frame.opcode {
                            OpCode::Close => println!("Done with authentication"),
                            _ => {}
                        }
                    }
                    _ => {}
                }
            }
        }
        _ => {}
    }
    Ok(auth)
}

#[tokio::main]
async fn main() {
    let (username, password) = ("somebody".to_string(), "something".to_string());
    // register_user(username.clone(), password.clone())
    //     .await
    //     .unwrap();
    let auth = authenticate_user(username, password).await.unwrap();
    println!("Auth: {auth}");
}
