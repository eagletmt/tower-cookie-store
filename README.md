# tower-cookie-store
Cookie session store for Tower and Axum.

tower-cookie-store is not suitable for production use because it stores all session values to a cookie.
It is recommended to use [async-session](https://docs.rs/async-session) for production and/or large session values.

## Usage
See [examples/axum.rs](examples/axum.rs).

```
% cargo run --example axum
```

```
% curl http://localhost:3000/me
You're not signed in
% curl -c cookie.txt -XPOST http://localhost:3000/signin
% curl -b cookie.txt http://localhost:3000/me
Hello, eagletmt
% curl -c cookie.txt -XPOST http://localhost:3000/signout
% curl -b cookie.txt http://localhost:3000/me
You're not signed in
```
