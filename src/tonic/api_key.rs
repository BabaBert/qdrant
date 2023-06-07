use std::any::Any;
use std::future::{ready, Ready};

use actix_web::body::EitherBody;
use actix_web::dev::{ServiceRequest, ServiceResponse, Transform};
use actix_web::error::Error;
use futures_util::future::{BoxFuture, LocalBoxFuture};
use futures_util::Future;
use tonic::body::BoxBody;
use tonic::codegen::http::{Request, Response};
use tonic::transport::Body;
use tower::Service;
use tower_layer::Layer;

use std::marker::PhantomData;
use std::task::{Context, Poll};

use actix_web::http::Method;
use actix_web::HttpResponse;
use constant_time_eq::constant_time_eq;

use reqwest::header::HeaderValue;
use reqwest::StatusCode;
use tonic::Code;
// use super::api_key_middleware::full_api_key_middleware::FullApiKeyMiddleware;
// use super::api_key_middleware::master_api_key_middleware::MasterApiKeyMiddleware;
// use super::api_key_middleware::phantom_api_key_middleware::PhantomMiddleware;
// use super::api_key_middleware::read_only_key_middleware::ReadOnlyApiKeyMiddleware;

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
    type Service = ApiKeyMiddleware<S>;

    fn layer(&self, inner: S) -> Self::Service {
        match (self.master_key, self.read_only_key) {
            (Some(master_key), Some(read_only_key)) => ApiKeyMiddleware::FullApiKeyMiddleware {
                master_key: master_key.to_owned(),
                read_only_key: read_only_key.to_owned(),
                service: inner,
            },
            (Some(master_key), None) => ApiKeyMiddleware::MasterKeyMiddleware {
                master_key: master_key.to_owned(),
                service: inner,
            },
            (None, Some(read_only_key)) => ApiKeyMiddleware::ReadOnlyKeyMiddleware {
                read_only_key: read_only_key.to_owned(),
                service: inner,
            },
            _ => ApiKeyMiddleware::PhantomMiddleware { service: inner },
        }
    }
}

// pub trait ApiKeyMiddleware<S>:
//     Service<
//     Request<Body>,
//     Response = Response<BoxBody>,
//     Error = S::Error,
//     Future = BoxFuture<'static, Result<Response<BoxBody>, S::Error>>,
// > + Clone + Sized
// where
//     S: Service<Request<Body>, Response = Response<BoxBody>>,
//     S::Future: Send + 'static,
// {
// }

#[derive(Clone)]
enum ApiKeyMiddleware<S> {
    FullApiKeyMiddleware {
        master_key: String,
        read_only_key: String,
        service: S,
    },
    ReadOnlyApiKeyMiddleware {
        read_only_key: String,
        service: S,
    },
    MasterApiKeyMiddleware {
        master_key: String,
        service: S,
    },
    PhantomMiddleware {
        service: S,
    },
}

impl<S> Service<Request<Body>> for ApiKeyMiddleware<S>
where
    S: Service<Request<Body>, Response = Response<BoxBody>>,
    S::Future: Send + 'static,
{
    type Response = Response<BoxBody>;
    type Error = S::Error;
    type Future = BoxFuture<'static, Result<Response<BoxBody>, S::Error>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        match self {
            ApiKeyMiddleware::FullApiKeyMiddleware { service, .. }
            | ApiKeyMiddleware::MasterApiKeyMiddleware { service, .. }
            | ApiKeyMiddleware::ReadOnlyApiKeyMiddleware { service, .. }
            | ApiKeyMiddleware::PhantomMiddleware { service } => service.poll_ready(cx),
        }
    }

    fn call(&mut self, request: Request<Body>) -> Self::Future {
        match self {
            Self::FullApiKeyMiddleware {
                master_key,
                read_only_key,
                service,
            } => {
                if let Some(key) = request.headers().get("api-key") {
                    if let Ok(key) = key.to_str() {
                        if request.method() == Method::GET
                            && constant_time_eq(read_only_key.as_bytes(), key.as_bytes())
                        {
                            let future = self.service.call(request);
                            return Box::pin(async move {
                                let response = future.await?;
                                Ok(response)
                            });
                        }
                        if constant_time_eq(self.master_key.as_bytes(), key.as_bytes()) {
                            let future = self.service.call(request);

                            return Box::pin(async move {
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
            Self::MasterApiKeyMiddleware {
                master_key,
                service,
            } => {
                if let Some(key) = request.headers().get("api-key") {
                    if let Ok(key) = key.to_str() {
                        if constant_time_eq(master_key.as_bytes(), key.as_bytes()) {
                            let future = service.call(request);

                            return Box::pin(async move {
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
            Self::ReadOnlyApiKeyMiddleware {
                read_only_key,
                service,
            } => {
                if let Some(key) = request.headers().get("api-key") {
                    if let Ok(key) = key.to_str() {
                        if request.method() == Method::GET
                            && constant_time_eq(read_only_key.as_bytes(), key.as_bytes())
                        {
                            let future = service.call(request);
                            return Box::pin(async move {
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
            _ => {
                let future = self.service.call(request);
                Box::pin(async move {
                    let response = future.await?;
                    Ok(response)
                })
            }
        }
    }
}
