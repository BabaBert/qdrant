use std::marker::PhantomData;

use actix_web::body::{BoxBody, EitherBody};
use actix_web::dev::{forward_ready, Service, ServiceRequest, ServiceResponse};
use actix_web::error::Error;
use futures_util::future::LocalBoxFuture;

use super::super::api_key::ApiKeyMiddleware;

pub struct PhantomMiddleware<S, B> {
    pub service: S,
    pub _phantom: PhantomData<B>,
}

impl<S, B> ApiKeyMiddleware<B> for PhantomMiddleware<S, B>
where
    S: Service<ServiceRequest, Response = ServiceResponse<EitherBody<B>>, Error = Error>,
    S::Future: 'static,
{
}

impl<S, B> Service<ServiceRequest> for PhantomMiddleware<S, B>
where
    S: Service<ServiceRequest, Response = ServiceResponse<EitherBody<B, BoxBody>>, Error = Error>,
    S::Future: 'static,
{
    type Response = ServiceResponse<EitherBody<B>>;
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<ServiceResponse<EitherBody<B>>, Error>>;

    forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        Box::pin(self.service.call(req))
    }
}
