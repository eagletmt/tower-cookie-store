#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let key = b"secret-32-bytes-string-value-123";
    let cookie_store = tower_cookie_store::CookieStoreLayer::new(key.as_slice(), "my-session")
        .secure(true)
        .http_only(true);

    let app = axum::Router::new()
        .route("/me", axum::routing::get(get_me))
        .route("/signin", axum::routing::post(post_signin))
        .route("/signout", axum::routing::post(post_signout))
        .layer(cookie_store);
    axum::Server::bind(&std::net::SocketAddr::from(([127, 0, 0, 1], 3000)))
        .serve(app.into_make_service())
        .await?;
    Ok(())
}

async fn get_me(session: tower_cookie_store::Session) -> String {
    let user_name: Option<String> = session.get("user_name");
    if let Some(user_name) = user_name {
        format!("Hello, {}\n", user_name)
    } else {
        "You're not signed in\n".to_owned()
    }
}

async fn post_signin(session: tower_cookie_store::Session) {
    session.insert("user_name".to_owned(), "eagletmt").unwrap();
}

async fn post_signout(session: tower_cookie_store::Session) {
    session.clear();
}
