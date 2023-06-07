use std::task::{Context, Poll};

use actix_web::http::Method;
use constant_time_eq::constant_time_eq;
use futures_util::future::BoxFuture;
use reqwest::header::HeaderValue;
use reqwest::StatusCode;
use tonic::body::BoxBody;
use tonic::codegen::http::{Request, Response};
use tonic::transport::Body;
use tonic::Code;
use tower::Service;
use tower_layer::Layer;

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
        match (&self.master_key, &self.read_only_key) {
            (Some(master_key), Some(read_only_key)) => ApiKeyMiddleware::Full {
                master_key: master_key.to_owned(),
                read_only_key: read_only_key.to_owned(),
                service: inner,
            },
            (Some(master_key), None) => ApiKeyMiddleware::Master {
                master_key: master_key.to_owned(),
                service: inner,
            },
            (None, Some(read_only_key)) => ApiKeyMiddleware::ReadOnly {
                read_only_key: read_only_key.to_owned(),
                service: inner,
            },
            _ => ApiKeyMiddleware::Phantom { service: inner },
        }
    }
}

#[derive(Clone)]
pub enum ApiKeyMiddleware<S> {
    Full {
        master_key: String,
        read_only_key: String,
        service: S,
    },
    ReadOnly {
        read_only_key: String,
        service: S,
    },
    Master {
        master_key: String,
        service: S,
    },
    Phantom {
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
            ApiKeyMiddleware::Full { service, .. }
            | ApiKeyMiddleware::Master { service, .. }
            | ApiKeyMiddleware::ReadOnly { service, .. }
            | ApiKeyMiddleware::Phantom { service } => service.poll_ready(cx),
        }
    }

    fn call(&mut self, request: Request<Body>) -> Self::Future {
        match self {
            Self::Full {
                master_key,
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
            Self::Master {
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
            Self::ReadOnly {
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
            Self::Phantom { service } => {
                let future = service.call(request);
                Box::pin(async move {
                    let response = future.await?;
                    Ok(response)
                })
            }
        }
    }
}
