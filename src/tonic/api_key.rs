use std::future::{ready, Ready};

use actix_web::body::EitherBody;
use actix_web::dev::{Service, ServiceRequest, ServiceResponse, Transform};
use actix_web::error::Error;
use futures_util::future::{BoxFuture, LocalBoxFuture};
use futures_util::Future;
use tonic::body::BoxBody;
use tonic::codegen::http::{Request, Response};
use tonic::transport::Body;
use tower_layer::Layer;

use super::api_key_middleware::full_api_key_middleware::FullApiKeyMiddleware;
use super::api_key_middleware::master_api_key_middleware::MasterKeyMiddleware;
use super::api_key_middleware::phantom_api_key_middleware::PhantomMiddleware;
use super::api_key_middleware::read_only_key_middleware::ReadOnlyKeyMiddleware;

#[derive(Clone)]
pub struct ApiKeyMiddlewareLayer {
    pub master_key: Option<String>,
    pub read_only_key: Option<String>,
}

impl<S> Layer<S> for ApiKeyMiddlewareLayer
where
    S: Service<Request<Body>, Response = Response<BoxBody>>,
    S::Future: Send + 'static,
{
    type Service = Box<dyn ApiKeyMiddleware<S>>;

    fn layer(&self, inner: S) -> Self::Service {
        match (self.master_key, self.read_only_key) {
            (Some(master_key), Some(read_only_key)) => Box::new(FullApiKeyMiddleware {
                master_key: master_key.to_owned(),
                read_only_key: read_only_key.to_owned(),
                service: inner,
            }),
            (Some(master_key), None) => Box::new(MasterKeyMiddleware {
                master_key: master_key.to_owned(),
                service: inner,
            }),
            (None, Some(read_only_key)) => Box::new(ReadOnlyKeyMiddleware {
                read_only_key: read_only_key.to_owned(),
                service: inner,
            }),
            _ => Box::new(PhantomMiddleware { service: inner }),
        }
    }
}

pub trait ApiKeyMiddleware<S>:
    Service<
    Request<Body>,
    Response = Response<BoxBody>,
    Error = S::Error,
    Future = BoxFuture<'static, Result<S::Response, S::Error>>,
>
where
    S: Service<Request<Body>, Response = Response<BoxBody>>,
    S::Future: Send + 'static,
{
}
