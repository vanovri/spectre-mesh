use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Cell, Paragraph, Row, Sparkline, Table, Wrap};
use ratatui::Frame;
use spectre_l7::L7Protocol;

use crate::app::{CockpitApp, CockpitTab};

pub fn render_cockpit(f: &mut Frame<'_>, app: &CockpitApp) {
    let root = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(10),
            Constraint::Length(1),
        ])
        .split(f.area());

    render_header(f, root[0], app);

    match app.tab {
        CockpitTab::All => {
            let rows = Layout::default()
                .direction(Direction::Vertical)
                .constraints([Constraint::Percentage(52), Constraint::Percentage(48)])
                .split(root[1]);
            let top = Layout::default()
                .direction(Direction::Horizontal)
                .constraints([Constraint::Percentage(48), Constraint::Percentage(52)])
                .split(rows[0]);
            let bot = Layout::default()
                .direction(Direction::Horizontal)
                .constraints([Constraint::Percentage(45), Constraint::Percentage(55)])
                .split(rows[1]);

            render_topology_panel(f, top[0], app);
            render_l7_panel(f, top[1], app);
            render_xdp_panel(f, bot[0], app);
            render_flamegraph_panel(f, bot[1], app);
        }
        CockpitTab::Topology => render_topology_panel(f, root[1], app),
        CockpitTab::L7Stream => render_l7_panel(f, root[1], app),
        CockpitTab::XdpRingBuf => render_xdp_panel(f, root[1], app),
        CockpitTab::Flamegraph => render_flamegraph_panel(f, root[1], app),
    }

    render_footer(f, root[2], app);
}

fn render_header(f: &mut Frame<'_>, area: Rect, app: &CockpitApp) {
    let pause_tag = if app.paused { "PAUSED" } else { "LIVE" };
    let line = Line::from(vec![
        Span::styled(
            " SPECTREMESH ",
            Style::default()
                .fg(Color::Black)
                .bg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw(format!(
            " [{pause_tag}] Reqs: {} | Errs: {} | RingBuf Drops: {} | {}",
            app.snapshot.total_requests,
            app.snapshot.total_errors,
            app.snapshot.ringbuf_drops,
            app.status_line,
        )),
    ]);
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Cyan))
        .title(" SpectreTop eBPF Mesh Cockpit ");
    f.render_widget(Paragraph::new(line).block(block), area);
}

fn render_topology_panel(f: &mut Frame<'_>, area: Rect, app: &CockpitApp) {
    let header = Row::new(["Service", "Proto", "Reqs", "Err%", "p99(ms)", "TLS Mode"]).style(
        Style::default()
            .fg(Color::Yellow)
            .add_modifier(Modifier::BOLD),
    );
    let rows: Vec<Row<'_>> = app
        .snapshot
        .nodes
        .iter()
        .map(|n| {
            Row::new([
                Cell::from(n.service.as_str()),
                Cell::from(proto_name(n.protocol_primary)),
                Cell::from(n.requests.to_string()),
                Cell::from(format!("{:.1}%", n.error_rate_pct)),
                Cell::from(format!("{:.2}", n.p99_ms)),
                Cell::from(n.tls_mode.as_str()),
            ])
        })
        .collect();

    let table = Table::new(
        rows,
        [
            Constraint::Length(16),
            Constraint::Length(6),
            Constraint::Length(5),
            Constraint::Length(5),
            Constraint::Length(7),
            Constraint::Min(10),
        ],
    )
    .header(header)
    .block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Green))
            .title("[1] Service Mesh Topology & Golden Signals"),
    );
    f.render_widget(table, area);
}

fn render_l7_panel(f: &mut Frame<'_>, area: Rect, app: &CockpitApp) {
    let header = Row::new([
        "Proto",
        "Method",
        "Target / Fingerprint",
        "Status",
        "Lat(ms)",
    ])
    .style(
        Style::default()
            .fg(Color::Yellow)
            .add_modifier(Modifier::BOLD),
    );
    let rows: Vec<Row<'_>> = app
        .spans
        .iter()
        .take(20)
        .map(|s| {
            let target = s
                .sql_fingerprint
                .as_deref()
                .or(s.redis_key_prefix.as_deref())
                .unwrap_or(s.path_or_query.as_str());
            Row::new([
                Cell::from(proto_name(s.protocol)),
                Cell::from(s.method.as_str()),
                Cell::from(target),
                Cell::from(s.status_code.to_string()),
                Cell::from(format!("{:.2}", (s.latency_ns as f64) / 1_000_000.0)),
            ])
        })
        .collect();

    let table = Table::new(
        rows,
        [
            Constraint::Length(7),
            Constraint::Length(8),
            Constraint::Min(22),
            Constraint::Length(7),
            Constraint::Length(8),
        ],
    )
    .header(header)
    .block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Magenta))
            .title("[2] Live Plaintext L7 / TLS Stream Inspector"),
    );
    f.render_widget(table, area);
}

fn render_xdp_panel(f: &mut Frame<'_>, area: Rect, app: &CockpitApp) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Blue))
        .title("[3] XDP Firewall & RingBuf Telemetry");
    let inner = block.inner(area);
    f.render_widget(block, area);

    let split = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(5), Constraint::Min(2)])
        .split(inner);

    let x = &app.snapshot.xdp_stats;
    let info = vec![
        Line::from(format!(
            "RX Pkts: {} | Pass: {} | Drops(RL/Blk/Bad): {}/{}/{}",
            x.rx_packets, x.pass, x.drop_ratelimit, x.drop_blocklist, x.drop_malformed
        )),
        Line::from(format!(
            "TCP Avg SRTT: {:.1} us | Retransmits: {}",
            app.snapshot.avg_srtt_us, app.snapshot.tcp_retransmits
        )),
        Line::from(format!(
            "RingBuf Drops: {} | Edges Active: {}",
            app.snapshot.ringbuf_drops,
            app.snapshot.edges.len()
        )),
    ];
    f.render_widget(Paragraph::new(info).wrap(Wrap { trim: true }), split[0]);
    f.render_widget(
        Sparkline::default()
            .data(&app.xdp_history)
            .style(Style::default().fg(Color::Cyan)),
        split[1],
    );
}

fn render_flamegraph_panel(f: &mut Frame<'_>, area: Rect, app: &CockpitApp) {
    let mut lines = Vec::new();
    lines.push(Line::styled(
        "On-CPU 99Hz Samples:",
        Style::default()
            .fg(Color::LightRed)
            .add_modifier(Modifier::BOLD),
    ));
    for line in app.oncpu_folded.lines().take(5) {
        lines.push(Line::from(format!("  {line}")));
    }
    lines.push(Line::styled(
        "Off-CPU Stall Delays (ns):",
        Style::default()
            .fg(Color::LightBlue)
            .add_modifier(Modifier::BOLD),
    ));
    for line in app.offcpu_folded.lines().take(5) {
        lines.push(Line::from(format!("  {line}")));
    }

    let para = Paragraph::new(lines).wrap(Wrap { trim: true }).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::LightRed))
            .title("[4] On-CPU / Off-CPU Flamegraph Hotspots"),
    );
    f.render_widget(para, area);
}

fn render_footer(f: &mut Frame<'_>, area: Rect, app: &CockpitApp) {
    let active = match app.tab {
        CockpitTab::All => "0:All",
        CockpitTab::Topology => "1:Topology",
        CockpitTab::L7Stream => "2:L7/TLS",
        CockpitTab::XdpRingBuf => "3:XDP/RingBuf",
        CockpitTab::Flamegraph => "4:Flamegraph",
    };
    let foot = Paragraph::new(Line::from(format!(
        "View: [{active}] | Keys: [0] All [1-4] Panel [Tab] Next [p] Pause [q] Quit"
    )))
    .style(Style::default().fg(Color::DarkGray));
    f.render_widget(foot, area);
}

const fn proto_name(p: L7Protocol) -> &'static str {
    match p {
        L7Protocol::Http1 => "HTTP/1",
        L7Protocol::Http2 => "HTTP/2",
        L7Protocol::Grpc => "gRPC",
        L7Protocol::Postgres => "PG v3",
        L7Protocol::Redis => "Redis",
        L7Protocol::Unknown => "Unk",
    }
}

#[cfg(test)]
mod tests {
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;

    use super::*;

    fn buffer_text(term: &Terminal<TestBackend>) -> String {
        let buf = term.backend().buffer();
        let mut s = String::new();
        for y in 0..buf.area.height {
            for x in 0..buf.area.width {
                s.push_str(buf[(x, y)].symbol());
            }
            s.push('\n');
        }
        s
    }

    #[test]
    fn tui_renders_all_4_cockpit_panels_and_tab_focus_headlessly() {
        let mut app = CockpitApp::from_demo();
        let backend = TestBackend::new(120, 40);
        let mut term = Terminal::new(backend).unwrap();

        term.draw(|f| render_cockpit(f, &app)).unwrap();
        let out = buffer_text(&term);
        assert!(out.contains("SpectreTop eBPF Mesh Cockpit"));
        assert!(out.contains("[1] Service Mesh Topology"));
        assert!(out.contains("[2] Live Plaintext L7 / TLS"));
        assert!(out.contains("[3] XDP Firewall & RingBuf"));
        assert!(out.contains("[4] On-CPU / Off-CPU Flamegraph"));
        assert!(out.contains("checkout-api"));
        assert!(out.contains("ml-scorer-go"));
        assert!(out.contains("orders-postgres"));
        assert!(out.contains("contended_mutex_wait"));

        app.select_tab(2);
        app.toggle_pause();
        term.draw(|f| render_cockpit(f, &app)).unwrap();
        let out_tab2 = buffer_text(&term);
        assert!(out_tab2.contains("PAUSED"));
        assert!(out_tab2.contains("SELECT id, total"));
        assert!(out_tab2.contains("session:"));
    }
}
