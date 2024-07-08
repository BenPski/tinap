// async fn hello(_: Request<hyper::body::Incoming>) -> Result<Response<Full<Bytes>>, Infallible> {
//     Ok(Response::new(Full::new(Bytes::from("Hey"))))
// }

// #[tokio::main]
// async fn main() -> Result<(), Box<dyn Error + Send + Sync>> {
//     let server_state = Arc::new(ServerSetup::<Scheme>::new(&mut OsRng));
//     let addr = SocketAddr::from(([127, 0, 0, 1], 6969));
//
//     let listener = TcpListener::bind(addr).await?;
//
//     loop {
//         let (stream, _) = listener.accept().await?;
//
//         let io = TokioIo::new(stream);
//
//         let server_state = server_state.clone();
//
//         let service = service_fn(move |req| async move {
//             Ok::<_, hyper::Error>(Response::new(Full::new(Bytes::from(format!("Request")))))
//         });
//
//         if let Err(err) = http1::Builder::new().serve_connection(io, service).await {
//             println!("Error serving connection: {:?}", err);
//         }
//     }
// }

use axum::{extract::State, response::IntoResponse, routing::get, Router};
use fastwebsockets::{upgrade, Frame, OpCode, WebSocketError};
use opaque_ke::{
    CredentialFinalization, CredentialRequest, RegistrationRequest, RegistrationUpload,
    ServerLogin, ServerLoginStartParameters, ServerRegistration, ServerSetup,
};
use rand::rngs::OsRng;
use tinap::{Scheme, WithUsername};

#[derive(Clone)]
struct Server {
    server_setup: ServerSetup<Scheme>,
    store: sled::Db,
}

async fn handle_client_registration(
    fut: upgrade::UpgradeFut,
    server: Server,
) -> Result<(), WebSocketError> {
    let mut ws = fastwebsockets::FragmentCollector::new(fut.await?);
    loop {
        let frame = ws.read_frame().await?;
        match frame.opcode {
            OpCode::Close => break,
            OpCode::Binary => {
                println!("Server registration start");
                let data = frame.payload.to_vec();
                let data: WithUsername = bincode::deserialize(&data).unwrap();
                let username = data.username;
                println!("Got username: `{:?}`", username);
                let registration_request_bytes = data.data;
                // println!("Server received: `{:?}`", &registration_request_bytes);
                let server_registration_start_result = ServerRegistration::<Scheme>::start(
                    &server.server_setup,
                    RegistrationRequest::deserialize(&registration_request_bytes).unwrap(),
                    username,
                )
                .unwrap();
                let registration_response_bytes =
                    server_registration_start_result.message.serialize();
                // println!("Server sending: `{registration_response_bytes:?}`");
                ws.write_frame(Frame::new(
                    true,
                    OpCode::Binary,
                    None,
                    registration_response_bytes.as_slice().into(),
                ))
                .await?;
                let final_frame = ws.read_frame().await?;
                match final_frame.opcode {
                    OpCode::Binary => {
                        println!("Server finalization");
                        let message_bytes = final_frame.payload.to_vec();
                        // println!("Server received: `{:?}`", &message_bytes);

                        let password_file = ServerRegistration::finish(
                            RegistrationUpload::<Scheme>::deserialize(&message_bytes).unwrap(),
                        );
                        let password_serialized = password_file.serialize();
                        // println!("Password to store: `{:?}`", password_serialized);
                        if !server.store.contains_key(username).unwrap() {
                            println!("Storing: {:?}, {:?}", username, password_serialized);
                            let res = server
                                .store
                                .insert(username, password_serialized.as_slice());
                            println!("Insertion result: `{res:?}`");
                        } else {
                            println!("User already registered");
                        }

                        ws.write_frame(Frame::close(1000, b"done".as_slice().into()))
                            .await
                            .unwrap();
                    }
                    _ => {}
                }
            }

            _ => {}
        }
    }

    Ok(())
}

async fn ws_registration(
    ws: upgrade::IncomingUpgrade,
    State(state): State<Server>,
) -> impl IntoResponse {
    let (response, fut) = ws.upgrade().unwrap();
    tokio::task::spawn(async move {
        if let Err(e) = handle_client_registration(fut, state).await {
            eprintln!("Error in websocket connection: `{e}`");
        }
    });

    response
}

async fn handle_client_authenticate(
    fut: upgrade::UpgradeFut,
    server: Server,
) -> Result<(), WebSocketError> {
    let mut ws = fastwebsockets::FragmentCollector::new(fut.await?);
    loop {
        let frame = ws.read_frame().await?;
        match frame.opcode {
            OpCode::Close => break,
            OpCode::Binary => {
                println!("Server login start");
                let data = frame.payload.to_vec();
                let data: WithUsername = bincode::deserialize(&data).unwrap();
                let username = data.username;
                let credential_request_bytes = data.data;
                println!("username: `{username:?}`");
                if !server.store.contains_key(username).unwrap() {
                    println!("User is not registered");
                    ws.write_frame(Frame::close(1000, "not registered".as_bytes()))
                        .await?;
                    break;
                }
                // println!("Server received: `{:?}`", &credential_request_bytes);
                let password_file_bytes = server.store.get(username).unwrap().unwrap();
                println!("Looked up: {:?}, {:?}", username, password_file_bytes);
                let password_file =
                    ServerRegistration::<Scheme>::deserialize(&password_file_bytes).unwrap();
                let server_login_start_result = ServerLogin::start(
                    &mut OsRng,
                    &server.server_setup,
                    Some(password_file),
                    CredentialRequest::deserialize(&credential_request_bytes).unwrap(),
                    &username,
                    ServerLoginStartParameters::default(),
                )
                .unwrap();
                let credential_response_bytes = server_login_start_result.message.serialize();

                // println!("Server sending: `{credential_response_bytes:?}`");
                ws.write_frame(Frame::new(
                    true,
                    OpCode::Binary,
                    None,
                    credential_response_bytes.as_slice().into(),
                ))
                .await?;

                let final_frame = ws.read_frame().await?;
                match final_frame.opcode {
                    OpCode::Close => {
                        println!("Failed to authenticate");
                        break;
                    }
                    OpCode::Binary => {
                        println!("Server finalization");
                        let credential_finalization_bytes = final_frame.payload.to_vec();
                        // println!(
                        //     "credential finalization: `{:?}`",
                        //     &credential_finalization_bytes
                        // );

                        let server_login_finish_result = server_login_start_result
                            .state
                            .finish(
                                CredentialFinalization::deserialize(&credential_finalization_bytes)
                                    .unwrap(),
                            )
                            .unwrap();
                        // println!(
                        //     "Server sending: `{:?}`",
                        //     server_login_finish_result.session_key
                        // );
                        ws.write_frame(Frame::new(
                            true,
                            OpCode::Binary,
                            None,
                            server_login_finish_result.session_key.as_slice().into(),
                        ))
                        .await?;

                        let confirm_frame = ws.read_frame().await?;
                        match confirm_frame.opcode {
                            OpCode::Close => {}
                            OpCode::Binary => {
                                let status = confirm_frame.payload.to_vec();
                                let authenticated = vec![1] == status;
                                println!("Authenticated: `{authenticated}`");
                                ws.write_frame(Frame::close(1000, "done".as_bytes().into()))
                                    .await?;
                            }
                            _ => {}
                        }
                    }
                    _ => {}
                }
            }

            _ => {}
        }
    }

    Ok(())
}

async fn ws_authenticate(
    ws: upgrade::IncomingUpgrade,
    State(state): State<Server>,
) -> impl IntoResponse {
    let (response, fut) = ws.upgrade().unwrap();
    tokio::task::spawn(async move {
        if let Err(e) = handle_client_authenticate(fut, state).await {
            eprintln!("Error in websocket connection: `{e}`");
        }
    });

    response
}

async fn handle_root(fut: upgrade::UpgradeFut) -> Result<(), WebSocketError> {
    let mut ws = fastwebsockets::FragmentCollector::new(fut.await?);

    loop {
        let mut frame = ws.read_frame().await?;
        match frame.opcode {
            OpCode::Close => break,
            OpCode::Text | OpCode::Binary => {
                let mut buf = Vec::new();
                frame.write(&mut buf);
                println!("Received: `{:?}`", buf);
                ws.write_frame(frame).await?;
            }
            _ => {}
        }
    }
    Ok(())
}

async fn root(ws: upgrade::IncomingUpgrade) -> impl IntoResponse {
    let (response, fut) = ws.upgrade().unwrap();
    tokio::task::spawn(async move {
        if let Err(e) = handle_root(fut).await {
            eprintln!("Error in websocket connection: `{e}`");
        }
    });
    response
}

#[tokio::main]
async fn main() {
    let state = Server {
        server_setup: ServerSetup::new(&mut OsRng),
        store: sled::open("tinap_db").unwrap(),
    };
    let app = Router::new()
        .route("/", get(root))
        .route("/registration", get(ws_registration))
        .route("/authenticate", get(ws_authenticate))
        .with_state(state);
    // .route("/login", get(ws_login));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:6969")
        .await
        .unwrap();
    axum::serve(listener, app).await.unwrap()
}
