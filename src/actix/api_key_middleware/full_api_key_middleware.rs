use std::marker::PhantomData;

use actix_web::body::{BoxBody, EitherBody};
use actix_web::dev::{forward_ready, Service, ServiceRequest, ServiceResponse};
use actix_web::error::Error;
use actix_web::http::Method;
use actix_web::HttpResponse;
use constant_time_eq::constant_time_eq;
use futures_util::future::LocalBoxFuture;

use super::master_api_key_middleware::MasterKeyMiddleware;
use crate::actix::api_key::ApiKeyMiddleware;

pub struct FullApiKeyMiddleware<S, B> {
    pub master_key: String,
    pub read_only_key: String,
    pub service: S,
    pub _phantom: PhantomData<B>,
}

impl<S, B> ApiKeyMiddleware<B> for FullApiKeyMiddleware<S, B>
where
    S: Service<ServiceRequest, Response = ServiceResponse<EitherBody<B>>, Error = Error>,
    S::Future: 'static,
{
}

impl<S, B> Service<ServiceRequest> for FullApiKeyMiddleware<S, B>
where
    S: Service<ServiceRequest, Response = ServiceResponse<EitherBody<B, BoxBody>>, Error = Error>,
    S::Future: 'static,
    MasterKeyMiddleware<S, B>: ApiKeyMiddleware<B>,
{
    type Response = ServiceResponse<EitherBody<B>>;
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<ServiceResponse<EitherBody<B>>, Error>>;

    forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        if let Some(key) = req.headers().get("api-key") {
            if let Ok(key) = key.to_str() {
                if req.method() == Method::GET {
                    if constant_time_eq(self.read_only_key.as_bytes(), key.as_bytes())
                        || constant_time_eq(self.master_key.as_bytes(), key.as_bytes())
                    {
                        return Box::pin(self.service.call(req));
                    }
                } else if constant_time_eq(self.master_key.as_bytes(), key.as_bytes()) {
                    return Box::pin(self.service.call(req));
                }
            }
        }
        Box::pin(async {
            Ok(req
                .into_response(HttpResponse::Forbidden().body("Invalid api-key"))
                .map_into_right_body())
        })
    }
}
