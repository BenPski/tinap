use tinap::client::client::Client;

#[tokio::main]
async fn main() {
    let client = Client::new("127.0.0.1".to_string(), 6969);
    let (username, password) = ("bobody".to_string(), "something".to_string());
    client
        .register_user(username.clone(), password.clone())
        .await
        .unwrap();
    let auth = client.authenticate_user(username, password).await.unwrap();
    println!("Auth: {auth}");
}
