use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use axum::body::Body;
use axum::extract::{Query, State};
use axum::http::{header, StatusCode};
use axum::response::Response;
use axum::routing::get;
use axum::{Json, Router};
use parking_lot::RwLock;
use serde::Deserialize;

use crate::topology::TopologyStore;

pub struct DaemonState {
    pub store: RwLock<TopologyStore>,
    sse_seq: AtomicU64,
}

impl DaemonState {
    #[must_use]
    pub fn new(store: TopologyStore) -> Self {
        Self {
            store: RwLock::new(store),
            sse_seq: AtomicU64::new(1),
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct FlameQuery {
    #[serde(default = "default_flame_mode")]
    pub mode: String,
}

fn default_flame_mode() -> String {
    "oncpu".to_owned()
}

pub fn build_router(state: Arc<DaemonState>) -> Router {
    Router::new()
        .route("/metrics", get(handle_metrics))
        .route("/v1/topology", get(handle_topology))
        .route("/v1/spans", get(handle_spans))
        .route("/v1/flamegraph", get(handle_flamegraph))
        .route("/v1/events/stream", get(handle_events_sse))
        .with_state(state)
}

async fn handle_metrics(State(state): State<Arc<DaemonState>>) -> Response {
    let body = state.store.read().render_prometheus_metrics();
    Response::builder()
        .status(StatusCode::OK)
        .header(
            header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )
        .body(Body::from(body))
        .unwrap_or_else(|_| Response::new(Body::empty()))
}

async fn handle_topology(
    State(state): State<Arc<DaemonState>>,
) -> Json<crate::topology::TopologySnapshot> {
    Json(state.store.read().snapshot())
}

async fn handle_spans(State(state): State<Arc<DaemonState>>) -> Json<Vec<spectre_l7::L7Span>> {
    Json(state.store.read().recent_spans(100))
}

async fn handle_flamegraph(
    State(state): State<Arc<DaemonState>>,
    Query(q): Query<FlameQuery>,
) -> Json<crate::topology::FlameGraphBundle> {
    Json(state.store.read().flamegraph(&q.mode))
}

async fn handle_events_sse(State(state): State<Arc<DaemonState>>) -> Response {
    let id = state.sse_seq.fetch_add(1, Ordering::Relaxed);
    let snap = state.store.read().snapshot();
    let json = serde_json::to_string(&snap).unwrap_or_else(|_| "{}".to_owned());
    let payload = format!("retry: 1500\nid: {id}\nevent: telemetry\ndata: {json}\n\n");
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "text/event-stream; charset=utf-8")
        .header(header::CACHE_CONTROL, "no-cache")
        .body(Body::from(payload))
        .unwrap_or_else(|_| Response::new(Body::empty()))
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    use super::*;

    async fn http_get(addr: std::net::SocketAddr, path: &str) -> String {
        let mut stream = TcpStream::connect(addr).await.unwrap();
        let req = format!("GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n");
        stream.write_all(req.as_bytes()).await.unwrap();
        let mut resp = Vec::new();
        stream.read_to_end(&mut resp).await.unwrap();
        String::from_utf8_lossy(&resp).into_owned()
    }

    #[tokio::test]
    async fn daemon_http_prometheus_topology_and_sse_endpoints() {
        let mut store = TopologyStore::new();
        store.populate_demo_telemetry();
        let state = Arc::new(DaemonState::new(store));
        let app = build_router(state);

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let srv = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });

        let metrics = http_get(addr, "/metrics").await;
        assert!(metrics.starts_with("HTTP/1.1 200 OK"));
        assert!(metrics.contains("spectre_l7_requests_total"));

        let topo = http_get(addr, "/v1/topology").await;
        assert!(topo.contains("\"total_requests\":80"));

        let spans = http_get(addr, "/v1/spans").await;
        assert!(spans.contains("/spectre.MeshService/Infer"));

        let fg = http_get(addr, "/v1/flamegraph?mode=offcpu").await;
        assert!(fg.contains("contended_mutex_wait"));

        let sse = http_get(addr, "/v1/events/stream").await;
        assert!(sse.contains("text/event-stream"));
        assert!(sse.contains("event: telemetry"));

        srv.abort();
    }
}
