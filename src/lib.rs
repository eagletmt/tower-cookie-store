#[derive(Clone)]
pub struct Session {
    inner: std::sync::Arc<std::sync::Mutex<std::cell::RefCell<SessionInner>>>,
}

type SessionState = std::collections::HashMap<String, String>;

#[derive(Default)]
struct SessionInner {
    state: SessionState,
}

impl Session {
    pub fn get<T>(&self, key: &str) -> Option<T>
    where
        T: serde::de::DeserializeOwned,
    {
        let inner = self
            .inner
            .lock()
            .expect("tower_cookie_store: internal mutex is poisoned");
        let inner = inner.borrow();
        if let Some(s) = inner.state.get(key) {
            match serde_json::from_str(s) {
                Ok(value) => Some(value),
                Err(e) => {
                    tracing::warn!(
                        "failed to deserialize session value of {}, removing it: {}",
                        key,
                        e
                    );
                    self.remove(key);
                    None
                }
            }
        } else {
            None
        }
    }

    pub fn insert<T: ?Sized>(&self, key: String, value: &T) -> Result<(), serde_json::Error>
    where
        T: serde::Serialize,
    {
        let inner = self
            .inner
            .lock()
            .expect("tower_cookie_store: internal mutex is poisoned");
        inner
            .borrow_mut()
            .state
            .insert(key, serde_json::to_string(value)?);
        Ok(())
    }

    pub fn remove(&self, key: &str) -> Option<String> {
        let inner = self
            .inner
            .lock()
            .expect("tower_cookie_store: internal mutex is poisoned");
        let mut inner = inner.borrow_mut();
        inner.state.remove(key)
    }

    pub fn clear(&self) {
        let inner = self
            .inner
            .lock()
            .expect("tower_cookie_store: internal mutex is poisoned");
        let mut inner = inner.borrow_mut();
        inner.state.clear();
    }
}

#[async_trait::async_trait]
impl<B> axum_core::extract::FromRequest<B> for Session
where
    B: Send,
{
    type Rejection = (http::StatusCode, &'static str);

    async fn from_request(
        req: &mut axum_core::extract::RequestParts<B>,
    ) -> Result<Self, Self::Rejection> {
        let extensions = req.extensions().ok_or((
            http::StatusCode::INTERNAL_SERVER_ERROR,
            "http::Extensions is alrady taken",
        ))?;
        let session: Session = extensions.get().cloned().ok_or((
            http::StatusCode::INTERNAL_SERVER_ERROR,
            "tower_cookie_store::Session is already taken",
        ))?;
        Ok(session)
    }
}

pub struct CookieStoreLayer {
    inner: std::sync::Arc<CookieStoreInner>,
}

struct CookieStoreInner {
    key: cookie::Key,
    name: String,
    domain: Option<String>,
    http_only: Option<bool>,
    max_age: Option<time::Duration>,
    path: String,
    same_site: Option<cookie::SameSite>,
    secure: Option<bool>,
}

impl CookieStoreLayer {
    pub fn new<S>(key: &[u8], name: S) -> Self
    where
        S: Into<String>,
    {
        Self {
            inner: std::sync::Arc::new(CookieStoreInner::new(key, name.into())),
        }
    }

    fn get_mut(&mut self) -> &mut CookieStoreInner {
        std::sync::Arc::get_mut(&mut self.inner)
            .expect("tower_cookie_store::CookieStoreInner is referenced from multiple pointers")
    }

    pub fn domain<S>(mut self, value: S) -> Self
    where
        S: Into<String>,
    {
        self.get_mut().domain = Some(value.into());
        self
    }

    pub fn http_only(mut self, value: bool) -> Self {
        self.get_mut().http_only = Some(value);
        self
    }

    pub fn max_age(mut self, value: time::Duration) -> Self {
        self.get_mut().max_age = Some(value);
        self
    }

    pub fn path<S>(mut self, path: S) -> Self
    where
        S: Into<String>,
    {
        self.get_mut().path = path.into();
        self
    }

    pub fn same_site(mut self, value: cookie::SameSite) -> Self {
        self.get_mut().same_site = Some(value);
        self
    }

    pub fn secure(mut self, value: bool) -> Self {
        self.get_mut().secure = Some(value);
        self
    }
}

impl CookieStoreInner {
    fn new(key: &[u8], name: String) -> Self {
        Self {
            key: cookie::Key::derive_from(key),
            name,
            domain: None,
            http_only: None,
            max_age: None,
            path: "/".to_owned(),
            same_site: None,
            secure: None,
        }
    }
}

impl<S> tower_layer::Layer<S> for CookieStoreLayer {
    type Service = CookieStoreService<S>;

    fn layer(&self, service: S) -> Self::Service {
        CookieStoreService {
            service,
            inner: self.inner.clone(),
        }
    }
}

#[derive(Clone)]
pub struct CookieStoreService<S> {
    service: S,
    inner: std::sync::Arc<CookieStoreInner>,
}
impl<ReqBody, ResBody, S> tower_service::Service<http::Request<ReqBody>> for CookieStoreService<S>
where
    S: tower_service::Service<http::Request<ReqBody>, Response = http::Response<ResBody>>,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = ResponseFuture<S::Future>;

    fn poll_ready(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.service.poll_ready(cx)
    }

    fn call(&mut self, mut req: http::Request<ReqBody>) -> Self::Future {
        let session_inner = load_session(&self.inner, req.headers());
        let session = Session {
            inner: std::sync::Arc::new(std::sync::Mutex::new(std::cell::RefCell::new(
                session_inner,
            ))),
        };
        req.extensions_mut().insert(session.clone());
        ResponseFuture {
            future: self.service.call(req),
            session,
            store: self.inner.clone(),
        }
    }
}

fn load_session(cookie_store: &CookieStoreInner, headers: &http::HeaderMap) -> SessionInner {
    let cookie_header = headers.get(http::header::COOKIE);
    if cookie_header.is_none() {
        return SessionInner::default();
    }
    let cookie_header = cookie_header.unwrap();

    let cookie_header = cookie_header.to_str();
    let cookie_header = match cookie_header {
        Ok(h) => h,
        Err(e) => {
            tracing::warn!(
                "failed to stringify cookie header value, discarding it: {}",
                e
            );
            return SessionInner::default();
        }
    };

    let signed_cookie = match cookie::Cookie::parse_encoded(cookie_header.to_owned()) {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!("failed to parse session cookie value, discarding it: {}", e);
            return SessionInner::default();
        }
    };

    let mut jar = cookie::CookieJar::new();
    jar.add_original(signed_cookie);
    let cookie = jar.signed(&cookie_store.key).get(&cookie_store.name);
    if cookie.is_none() {
        return SessionInner::default();
    }
    let cookie = cookie.unwrap();

    let state = match serde_json::from_str::<SessionState>(cookie.value()) {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(
                "failed to deserialize session cookie value, discarding it: {}",
                e
            );
            return SessionInner::default();
        }
    };
    SessionInner { state }
}

pin_project_lite::pin_project! {
    pub struct ResponseFuture<F> {
        #[pin]
        future: F,
        session: Session,
        store: std::sync::Arc<CookieStoreInner>,
    }
}
impl<F, ResBody, E> std::future::Future for ResponseFuture<F>
where
    F: std::future::Future<Output = Result<http::Response<ResBody>, E>>,
{
    type Output = F::Output;

    fn poll(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        let this = self.project();
        let mut res = futures_util::ready!(this.future.poll(cx)?);
        let inner = this
            .session
            .inner
            .lock()
            .expect("tower_cookie_store: internal mutex is poisoned");
        let inner = inner.borrow();
        if inner.state.is_empty() {
            // Clear session cookie
            let cookie = cookie::Cookie::build(this.store.name.clone(), "")
                .path(this.store.path.clone())
                .max_age(time::Duration::seconds(0))
                .finish();
            res.headers_mut().append(
                http::header::SET_COOKIE,
                http::HeaderValue::from_str(&cookie.encoded().to_string()).unwrap(),
            );
            return std::task::Poll::Ready(Ok(res));
        }

        let cookie_value = match serde_json::to_string(&inner.state) {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!("failed to serialize session cookie, discarding it: {}", e);
                return std::task::Poll::Ready(Ok(res));
            }
        };
        let mut jar = cookie::CookieJar::new();
        let mut builder = cookie::Cookie::build(this.store.name.clone(), cookie_value)
            .path(this.store.path.clone());
        if let Some(ref domain) = this.store.domain {
            builder = builder.domain(domain.to_owned());
        }
        if let Some(http_only) = this.store.http_only {
            builder = builder.http_only(http_only);
        }
        if let Some(max_age) = this.store.max_age {
            builder = builder.max_age(max_age);
        }
        if let Some(same_site) = this.store.same_site {
            builder = builder.same_site(same_site);
        }
        if let Some(secure) = this.store.secure {
            builder = builder.secure(secure);
        }
        let cookie = builder.finish();
        jar.signed_mut(&this.store.key).add(cookie);
        for cookie in jar.delta() {
            match http::HeaderValue::from_str(&cookie.encoded().to_string()) {
                Ok(value) => {
                    res.headers_mut().append(http::header::SET_COOKIE, value);
                }
                Err(e) => {
                    tracing::warn!("failed to stringify session cookie: {}", e);
                }
            }
        }
        std::task::Poll::Ready(Ok(res))
    }
}

#[cfg(test)]
mod tests {
    use tower::ServiceExt as _;

    #[derive(serde_derive::Serialize, serde_derive::Deserialize)]
    struct User {
        id: i64,
        name: String,
    }

    fn build_app() -> axum::Router {
        axum::Router::new()
            .route(
                "/me",
                axum::routing::get(|session: super::Session| async move {
                    if let Some(user) = session.get::<User>("user") {
                        format!("{}-{}", user.id, user.name)
                    } else {
                        "not-found".to_owned()
                    }
                }),
            )
            .route(
                "/signin",
                axum::routing::post(|session: super::Session| async move {
                    session
                        .insert(
                            "user".to_owned(),
                            &User {
                                id: 2,
                                name: "eagletmt".to_owned(),
                            },
                        )
                        .unwrap();
                }),
            )
            .route(
                "/clear",
                axum::routing::post(|session: super::Session| async move {
                    session.clear();
                }),
            )
            .route(
                "/remove",
                axum::routing::post(|session: super::Session| async move {
                    session.remove("user");
                }),
            )
            .layer(
                super::CookieStoreLayer::new(&[0; 32], "test-session")
                    .secure(true)
                    .http_only(true),
            )
    }

    #[tokio::test]
    async fn empty_session() {
        let req = http::Request::get("/me")
            .body(axum::body::Body::empty())
            .unwrap();
        let resp = build_app().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), http::StatusCode::OK);
        let body = hyper::body::to_bytes(resp.into_body()).await.unwrap();
        assert_eq!(body, "not-found");
    }

    #[tokio::test]
    async fn sign_in() {
        let req = http::Request::post("/signin")
            .body(axum::body::Body::empty())
            .unwrap();
        let resp = build_app().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), http::StatusCode::OK);
        let cookie_header = resp.headers().get(http::header::SET_COOKIE).unwrap();
        let cookie = cookie::Cookie::parse_encoded(cookie_header.to_str().unwrap()).unwrap();
        assert_eq!(cookie.name(), "test-session");
        assert_eq!(cookie.secure(), Some(true));
        assert_eq!(cookie.http_only(), Some(true));
        assert_eq!(cookie.expires(), None);

        let req = http::Request::get("/me")
            .header(
                http::header::COOKIE,
                cookie.encoded().stripped().to_string(),
            )
            .body(axum::body::Body::empty())
            .unwrap();
        let resp = build_app().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), http::StatusCode::OK);
        let body = hyper::body::to_bytes(resp.into_body()).await.unwrap();
        assert_eq!(body, "2-eagletmt");
    }

    #[tokio::test]
    async fn clear_session() {
        let req = http::Request::post("/signin")
            .body(axum::body::Body::empty())
            .unwrap();
        let resp = build_app().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), http::StatusCode::OK);
        let cookie_header = resp.headers().get(http::header::SET_COOKIE).unwrap();
        let cookie = cookie::Cookie::parse_encoded(cookie_header.to_str().unwrap()).unwrap();
        assert_eq!(cookie.name(), "test-session");
        assert_eq!(cookie.secure(), Some(true));
        assert_eq!(cookie.http_only(), Some(true));
        assert_eq!(cookie.expires(), None);

        let req = http::Request::get("/me")
            .header(
                http::header::COOKIE,
                cookie.encoded().stripped().to_string(),
            )
            .body(axum::body::Body::empty())
            .unwrap();
        let resp = build_app().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), http::StatusCode::OK);
        let body = hyper::body::to_bytes(resp.into_body()).await.unwrap();
        assert_eq!(body, "2-eagletmt");

        let req = http::Request::post("/clear")
            .body(axum::body::Body::empty())
            .unwrap();
        let resp = build_app().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), http::StatusCode::OK);
        let cookie_header = resp.headers().get(http::header::SET_COOKIE).unwrap();
        let cookie = cookie::Cookie::parse_encoded(cookie_header.to_str().unwrap()).unwrap();
        assert_eq!(cookie.name(), "test-session");
        assert_eq!(cookie.path(), Some("/"));
        assert_eq!(cookie.max_age(), Some(time::Duration::seconds(0)));
    }

    #[tokio::test]
    async fn remove_session() {
        let req = http::Request::post("/signin")
            .body(axum::body::Body::empty())
            .unwrap();
        let resp = build_app().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), http::StatusCode::OK);
        let cookie_header = resp.headers().get(http::header::SET_COOKIE).unwrap();
        let cookie = cookie::Cookie::parse_encoded(cookie_header.to_str().unwrap()).unwrap();
        assert_eq!(cookie.name(), "test-session");
        assert_eq!(cookie.secure(), Some(true));
        assert_eq!(cookie.http_only(), Some(true));
        assert_eq!(cookie.expires(), None);

        let req = http::Request::get("/me")
            .header(
                http::header::COOKIE,
                cookie.encoded().stripped().to_string(),
            )
            .body(axum::body::Body::empty())
            .unwrap();
        let resp = build_app().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), http::StatusCode::OK);
        let body = hyper::body::to_bytes(resp.into_body()).await.unwrap();
        assert_eq!(body, "2-eagletmt");

        let req = http::Request::post("/remove")
            .body(axum::body::Body::empty())
            .unwrap();
        let resp = build_app().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), http::StatusCode::OK);
        let cookie_header = resp.headers().get(http::header::SET_COOKIE).unwrap();
        let cookie = cookie::Cookie::parse_encoded(cookie_header.to_str().unwrap()).unwrap();
        assert_eq!(cookie.name(), "test-session");
        assert_eq!(cookie.path(), Some("/"));
        assert_eq!(cookie.max_age(), Some(time::Duration::seconds(0)));
    }
}
