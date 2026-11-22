use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use spectre_daemon::{FlameGraphBundle, TopologySnapshot, TopologyStore};
use spectre_l7::L7Span;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CockpitTab {
    All = 0,
    Topology = 1,
    L7Stream = 2,
    XdpRingBuf = 3,
    Flamegraph = 4,
}

impl CockpitTab {
    #[must_use]
    pub const fn next(self) -> Self {
        match self {
            Self::All => Self::Topology,
            Self::Topology => Self::L7Stream,
            Self::L7Stream => Self::XdpRingBuf,
            Self::XdpRingBuf => Self::Flamegraph,
            Self::Flamegraph => Self::All,
        }
    }
}

pub struct CockpitApp {
    pub tab: CockpitTab,
    pub paused: bool,
    pub should_quit: bool,
    pub status_line: String,
    pub snapshot: TopologySnapshot,
    pub spans: Vec<L7Span>,
    pub oncpu_folded: String,
    pub offcpu_folded: String,
    pub xdp_history: Vec<u64>,
}

impl CockpitApp {
    #[must_use]
    pub fn from_demo() -> Self {
        let mut store = TopologyStore::new();
        store.populate_demo_telemetry();
        let snapshot = store.snapshot();
        let spans = store.recent_spans(32);
        let oncpu = store.flamegraph("oncpu").folded;
        let offcpu = store.flamegraph("offcpu").folded;
        let mut app = Self {
            tab: CockpitTab::All,
            paused: false,
            should_quit: false,
            status_line: "DEMO MODE — Synthetic Encrypted Mesh Telemetry".to_owned(),
            snapshot,
            spans,
            oncpu_folded: oncpu,
            offcpu_folded: offcpu,
            xdp_history: vec![120, 145, 190, 220, 185, 240, 260, 210, 195, 230, 250, 215],
        };
        app.push_xdp_point();
        app
    }

    pub fn push_xdp_point(&mut self) {
        let v = self.snapshot.xdp_stats.rx_packets % 400;
        self.xdp_history.push(v.max(40));
        if self.xdp_history.len() > 36 {
            self.xdp_history.remove(0);
        }
    }

    pub fn toggle_pause(&mut self) {
        self.paused = !self.paused;
    }

    pub fn next_tab(&mut self) {
        self.tab = self.tab.next();
    }

    pub fn select_tab(&mut self, n: u8) {
        self.tab = match n {
            1 => CockpitTab::Topology,
            2 => CockpitTab::L7Stream,
            3 => CockpitTab::XdpRingBuf,
            4 => CockpitTab::Flamegraph,
            _ => CockpitTab::All,
        };
    }

    pub fn apply_remote_refresh(&mut self, base_url: &str) {
        if self.paused {
            return;
        }
        if let Ok((snap, spans, oncpu, offcpu)) = fetch_daemon_snapshot(base_url) {
            self.snapshot = snap;
            self.spans = spans;
            self.oncpu_folded = oncpu.folded;
            self.offcpu_folded = offcpu.folded;
            self.push_xdp_point();
            self.status_line = format!("LIVE DAEMON: {base_url}");
        }
    }
}

fn http_get_json_body(host_port: &str, path: &str) -> Result<String, String> {
    let mut stream = TcpStream::connect(host_port).map_err(|e| e.to_string())?;
    let _ = stream.set_read_timeout(Some(Duration::from_millis(500)));
    let _ = stream.set_write_timeout(Some(Duration::from_millis(500)));
    let req = format!("GET {path} HTTP/1.1\r\nHost: {host_port}\r\nConnection: close\r\n\r\n");
    stream
        .write_all(req.as_bytes())
        .map_err(|e| e.to_string())?;
    let mut raw = String::new();
    stream.read_to_string(&mut raw).map_err(|e| e.to_string())?;
    let Some((_hdrs, body)) = raw.split_once("\r\n\r\n") else {
        return Err("malformed HTTP response".to_owned());
    };
    Ok(body.to_owned())
}

pub fn fetch_daemon_snapshot(
    base_url: &str,
) -> Result<
    (
        TopologySnapshot,
        Vec<L7Span>,
        FlameGraphBundle,
        FlameGraphBundle,
    ),
    String,
> {
    let host_port = base_url
        .trim()
        .trim_start_matches("http://")
        .trim_end_matches('/');
    let snap: TopologySnapshot =
        serde_json::from_str(&http_get_json_body(host_port, "/v1/topology")?)
            .map_err(|e| e.to_string())?;
    let spans: Vec<L7Span> = serde_json::from_str(&http_get_json_body(host_port, "/v1/spans")?)
        .map_err(|e| e.to_string())?;
    let oncpu: FlameGraphBundle =
        serde_json::from_str(&http_get_json_body(host_port, "/v1/flamegraph?mode=oncpu")?)
            .map_err(|e| e.to_string())?;
    let offcpu: FlameGraphBundle = serde_json::from_str(&http_get_json_body(
        host_port,
        "/v1/flamegraph?mode=offcpu",
    )?)
    .map_err(|e| e.to_string())?;
    Ok((snap, spans, oncpu, offcpu))
}
