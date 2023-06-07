use std::marker::PhantomData;
use std::task::{Context, Poll};

use tonic::body::BoxBody;
use actix_web::dev::{forward_ready, Service, ServiceRequest, ServiceResponse};
use actix_web::error::Error;
use actix_web::http::Method;
use actix_web::HttpResponse;
use constant_time_eq::constant_time_eq;
use futures_util::future::{BoxFuture, LocalBoxFuture};

use reqwest::StatusCode;
use reqwest::header::HeaderValue;
use tonic::Code;
use tonic::codegen::http::{Request, Response};
use tonic::transport::Body;

use super::super::api_key::ApiKeyMiddleware;

#[derive(Clone)]
pub struct ReadOnlyKeyMiddleware<S> {
    pub read_only_key: String,
    pub service: S,
}

impl<S> ApiKeyMiddleware<S> for ReadOnlyKeyMiddleware<S>
where
    S: Service<Request<Body>, Response = Response<BoxBody>>,
    S::Future: Send + 'static,
{
}

impl<S> Service<Request<Body>> for ReadOnlyKeyMiddleware<S>
where
    S: Service<Request<Body>, Response = Response<BoxBody>>,
    S::Future: Send + 'static,
{
    type Response = Response<BoxBody>;
    type Error = S::Error;
    type Future = BoxFuture<'static, Result<S::Response, S::Error>>;

    fn poll_ready(&self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.service.poll_ready(cx)
    }

    fn call(
        &self,
        request: tonic::codegen::http::Request<tonic::transport::Body>,
    ) -> Self::Future {
        if let Some(key) = request.headers().get("api-key") {
            if let Ok(key) = key.to_str() {
                if request.method() == Method::GET && constant_time_eq(self.read_only_key.as_bytes(), key.as_bytes()) {
                    let future = self.service.call(request);return Box::pin(async move {
                        let response = future.await?;
                        Ok(response)
                    });
                }
            }
        }

        let mut response = Self::Response::new(BoxBody::default());
        *response.status_mut() = StatusCode::FORBIDDEN;
        response.headers_mut().append(
            "grpc-status",
            HeaderValue::from(Code::PermissionDenied as i32),
        );
        response
            .headers_mut()
            .append("grpc-message", HeaderValue::from_static("Invalid api-key"));

        Box::pin(async move { Ok(response) })
    }
}