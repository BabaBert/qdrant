use std::marker::PhantomData;
use std::task::{Context, Poll};

use actix_web::dev::{forward_ready, Service, ServiceRequest, ServiceResponse};
use actix_web::error::Error;
use actix_web::http::Method;
use actix_web::HttpResponse;
use constant_time_eq::constant_time_eq;
use futures_util::future::{BoxFuture, LocalBoxFuture};
use tonic::body::BoxBody;

use reqwest::header::HeaderValue;
use reqwest::StatusCode;
use tonic::codegen::http::{Request, Response};
use tonic::transport::Body;
use tonic::Code;

use super::super::api_key::ApiKeyMiddleware;

#[derive(Clone)]
pub struct PhantomMiddleware<S> {
    pub service: S,
}

impl<S> ApiKeyMiddleware<S> for PhantomMiddleware<S>
where
    S: Service<Request<Body>, Response = Response<BoxBody>>,
    S::Future: Send + 'static,
{
}

impl<S> Service<Request<Body>> for PhantomMiddleware<S>
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

    fn call(&self, request: tonic::codegen::http::Request<tonic::transport::Body>) -> Self::Future {
        let future = self.service.call(request);
        Box::pin(async move {
            let response = future.await?;
            Ok(response)
        })
    }
}
