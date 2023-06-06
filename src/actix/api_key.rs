use std::future::{ready, Ready};

use actix_web::body::EitherBody;
use actix_web::dev::{Service, ServiceRequest, ServiceResponse, Transform};
use actix_web::error::Error;
use futures_util::future::LocalBoxFuture;
use futures_util::Future;

use super::api_key_middleware::full_api_key_middleware::FullApiKeyMiddleware;
use super::api_key_middleware::master_api_key_middleware::MasterKeyMiddleware;
use super::api_key_middleware::phantom_api_key_middleware::PhantomMiddleware;
use super::api_key_middleware::read_only_key_middleware::ReadOnlyKeyMiddleware;

pub struct ApiKeyGuard {
    pub master_key: Option<String>,
    pub read_only_key: Option<String>,
}

impl<S, B: 'static, F> Transform<S, ServiceRequest> for ApiKeyGuard
where
    S: Service<
        ServiceRequest,
        Future = F,
        Response = ServiceResponse<EitherBody<B>>,
        Error = Error,
    >,
    S: 'static,
    F: Future<
        Output = Result<
            <S as Service<ServiceRequest>>::Response,
            <S as Service<ServiceRequest>>::Error,
        >,
    >,
    F: 'static,
{
    /// Responses produced by the service.
    type Response = S::Response;
    /// Errors produced by the service.
    type Error = S::Error;
    /// The `TransformService` value created by this factory
    type Transform = Box<dyn ApiKeyMiddleware<B>>;
    /// Errors produced while building a transform service.
    type InitError = ();
    /// The future response value.
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        let keys = (&self.master_key, &self.read_only_key);
        ready(Ok(match keys {
            (Some(master_key), Some(read_only_key)) => Box::new(FullApiKeyMiddleware {
                master_key: master_key.to_owned(),
                read_only_key: read_only_key.to_owned(),
                service,
                _phantom: Default::default(),
            }),
            (Some(master_key), None) => Box::new(MasterKeyMiddleware {
                master_key: master_key.to_owned(),
                service,
                _phantom: Default::default(),
            }),
            (None, Some(read_only_key)) => Box::new(ReadOnlyKeyMiddleware {
                read_only_key: read_only_key.to_owned(),
                service,
                _phantom: Default::default(),
            }),
            _ => Box::new(PhantomMiddleware {
                service,
                _phantom: Default::default(),
            }),
        }))
    }
}

pub trait ApiKeyMiddleware<B>:
    Service<
    ServiceRequest,
    Response = ServiceResponse<EitherBody<B>>,
    Error = Error,
    Future = LocalBoxFuture<'static, Result<ServiceResponse<EitherBody<B>>, Error>>,
>
{
}
