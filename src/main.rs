//! This is a Discord Bot that notifies a Channel and Group when a new F1 or
//! F1-Feeder session starts.

use std::{fmt::Write, str::FromStr};

use axum::{
    body::Body,
    extract::State,
    http::{HeaderMap, Request},
    response::IntoResponse,
    routing::post,
};
use ed25519_dalek::{Signature, VerifyingKey};
use reqwest::{StatusCode, header::CONTENT_TYPE};
use sentry::{integrations::tracing::EventFilter, types::Dsn};
use serde::Deserialize;
use serde_repr::{Deserialize_repr, Serialize_repr};
use tower::ServiceBuilder;
use tracing::info;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[derive(Debug, Serialize_repr, Deserialize_repr)]
#[repr(u8)]
enum Interaction {
    Ping = 1,
    ApplicationCommand,
    MessageComponent,
    Autocomplete,
    ModalSubmit,
}

#[derive(serde::Deserialize, Debug)]
struct Testing;

#[derive(Debug)]
enum InteractionData {
    Ping,
    ApplicationCommand(Testing),
    MessageComponent(Testing),
    Autocomplete(Testing),
    ModalSubmit(Testing),
}

impl<'de> Deserialize<'de> for InteractionData {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = serde_json::Value::deserialize(deserializer)?;
        let t = value
            .get("type")
            .and_then(|v| v.as_u64())
            .ok_or_else(|| serde::de::Error::custom("Missing Type"))?;
        match t {
            1 => Ok(InteractionData::Ping),
            2 => Ok(Self::ApplicationCommand(
                serde_json::from_value::<Testing>(value)
                    .map_err(|v| serde::de::Error::custom(format!("{v}")))?,
            )),

            3 => Ok(Self::MessageComponent(
                serde_json::from_value::<Testing>(value)
                    .map_err(|v| serde::de::Error::custom(format!("{v}")))?,
            )),

            4 => Ok(Self::Autocomplete(
                serde_json::from_value::<Testing>(value)
                    .map_err(|v| serde::de::Error::custom(format!("{v}")))?,
            )),

            5 => Ok(Self::ModalSubmit(
                serde_json::from_value::<Testing>(value)
                    .map_err(|v| serde::de::Error::custom(format!("{v}")))?,
            )),
            _ => Err(serde::de::Error::custom(format!(
                "Unknown interaction type {t}"
            ))),
        }
    }
}

#[allow(dead_code)]
#[derive(serde::Deserialize, Debug)]
struct InteractionReceive {
    pub id: u64,
    pub application_id: u64,
    #[serde(rename = "type")]
    pub kind: Interaction,
    #[serde(flatten)]
    pub data: Option<InteractionData>,
}

#[derive(Clone, Debug)]
struct AxumState<'a> {
    pub public_key: &'a VerifyingKey,
}

fn main() {
    _ = dotenvy::dotenv();
    let mut sentry_client = None;
    if let Ok(dsn) = std::env::var("SENTRY_DSN") {
        sentry_client = Some(sentry::init(sentry::ClientOptions {
            release: sentry::release_name!(),
            dsn: Some(Dsn::from_str(&dsn).expect("Valid DSN")),
            sample_rate: 1.0,
            traces_sample_rate: 1.0,
            ..Default::default()
        }));
    };

    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer())
        .with(
            sentry::integrations::tracing::layer().event_filter(|f| match *f.level() {
                tracing::Level::ERROR => EventFilter::Event,
                tracing::Level::INFO => EventFilter::Log | EventFilter::Breadcrumb,
                tracing::Level::WARN => EventFilter::Log | EventFilter::Breadcrumb,
                _ => EventFilter::Ignore,
            }),
        )
        .init();
    info!("App Start up at {}", chrono::Utc::now());
    sentry::start_session();
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {

        let mut public_key = [0u8; 32];
        hex::decode_to_slice(std::env::var("PUBLIC_KEY").unwrap(), &mut public_key).unwrap();
        let vk = Box::leak(Box::new(VerifyingKey::from_bytes(&public_key).unwrap()));

            let router = axum::Router::new()
                .route("/interaction", post(interaction))
                .with_state(AxumState {
                    public_key: vk,
                })
                .fallback(fallback)
                .layer(ServiceBuilder::new()
                    .layer(sentry::integrations::tower::NewSentryLayer::<Request<Body>>::new_from_top())
                    .layer(sentry::integrations::tower::SentryHttpLayer::new().enable_transaction())
                )
                .into_make_service();

            let tcp_listener = tokio::net::TcpListener::bind("0.0.0.0:8123").await.unwrap();
            info!("Listener bound to {}", tcp_listener.local_addr().unwrap());
            axum::serve(tcp_listener, router)
                .with_graceful_shutdown(async {
                    tokio::signal::ctrl_c().await.unwrap();
                })
                .await
                .unwrap();
        });
    sentry::end_session_with_status(sentry::protocol::SessionStatus::Ok);
    if let Some(client) = sentry::Hub::current().client() {
        client.close(Some(std::time::Duration::from_secs(2)));
    }
    drop(sentry_client);
}

async fn fallback() -> (StatusCode, &'static str) {
    (StatusCode::NOT_FOUND, "Not Found.")
}

#[derive(serde::Serialize)]
struct DiscordResponse {
    #[serde(rename = "type")]
    kind: u32,
}

async fn interaction(
    State(state): State<AxumState<'_>>,
    headers: HeaderMap,
    body: String,
) -> impl IntoResponse {
    let (Some(signature), Some(timestamp)) = (
        headers.get("X-Signature-Ed25519"),
        headers.get("X-Signature-Timestamp"),
    ) else {
        return (
            StatusCode::UNAUTHORIZED,
            HeaderMap::new(),
            "Unauthorized.".to_owned(),
        );
    };

    let (Ok(signature), Ok(timestamp)) = (signature.to_str(), timestamp.to_str()) else {
        return (
            StatusCode::UNAUTHORIZED,
            HeaderMap::new(),
            "Unauthorized.".to_owned(),
        );
    };

    let mut decoded_signature = [0u8; 64];
    hex::decode_to_slice(signature, &mut decoded_signature).unwrap();
    let sign = Signature::from_bytes(&decoded_signature);
    let mut message = String::with_capacity(timestamp.len() + body.len());
    message.write_str(timestamp).unwrap();
    message.write_str(&body).unwrap();
    if let Err(why) = state.public_key.verify_strict(message.as_bytes(), &sign) {
        info!("{why}");
        return (
            StatusCode::UNAUTHORIZED,
            HeaderMap::new(),
            "Unauthorized.".to_owned(),
        );
    }

    let serialized_body: InteractionReceive = serde_json::from_str(&body).unwrap();
    println!("{serialized_body:#?}");
    match serialized_body.kind {
        Interaction::Ping => {
            let response = serde_json::to_string(&DiscordResponse { kind: 1 }).unwrap();
            let mut headers = HeaderMap::new();
            headers.append(CONTENT_TYPE, "application/json".parse().unwrap());

            (StatusCode::OK, headers, response)
        }
        Interaction::ApplicationCommand => (
            StatusCode::ACCEPTED,
            HeaderMap::new(),
            String::with_capacity(0),
        ),
        Interaction::MessageComponent => (
            StatusCode::ACCEPTED,
            HeaderMap::new(),
            String::with_capacity(0),
        ),
        Interaction::Autocomplete => (
            StatusCode::ACCEPTED,
            HeaderMap::new(),
            String::with_capacity(0),
        ),
        Interaction::ModalSubmit => (
            StatusCode::ACCEPTED,
            HeaderMap::new(),
            String::with_capacity(0),
        ),
    }
}
