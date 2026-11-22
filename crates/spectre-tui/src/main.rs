#![deny(unsafe_code)]

use std::time::{Duration, Instant};

use clap::Parser;
use crossterm::event::{self, Event, KeyCode};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use ratatui::backend::CrosstermBackend;
use ratatui::Terminal;
use spectre_tui::{render_cockpit, CockpitApp};

#[derive(Debug, Parser)]
#[command(name = "spectre-top", about = "SpectreMesh Live eBPF Cockpit TUI")]
struct Cli {
    /// Launch in deterministic offline demo mode
    #[arg(long, default_value_t = false)]
    demo: bool,

    /// Poll telemetry JSON from running spectred HTTP endpoint
    #[arg(long)]
    daemon_url: Option<String>,

    /// Target PID label when running standalone
    #[arg(long)]
    attach: Option<u32>,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    let mut app = CockpitApp::from_demo();
    if let Some(pid) = cli.attach {
        app.status_line =
            format!("TARGET PID: {pid} (use --daemon-url http://127.0.0.1:9095 for live stream)");
    } else if cli.demo {
        app.status_line = "DEMO MODE — Interactive Offline Cockpit".to_owned();
    }
    if let Some(ref url) = cli.daemon_url {
        app.apply_remote_refresh(url);
    }

    enable_raw_mode()?;
    let mut stdout = std::io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let res = run_event_loop(&mut terminal, &mut app, cli.daemon_url.as_deref());

    let _ = disable_raw_mode();
    let _ = execute!(terminal.backend_mut(), LeaveAlternateScreen);
    let _ = terminal.show_cursor();
    res
}

fn run_event_loop(
    terminal: &mut Terminal<CrosstermBackend<std::io::Stdout>>,
    app: &mut CockpitApp,
    daemon_url: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut last_tick = Instant::now();
    loop {
        terminal.draw(|f| render_cockpit(f, app))?;

        if event::poll(Duration::from_millis(100))? {
            if let Event::Key(key) = event::read()? {
                match key.code {
                    KeyCode::Char('q') | KeyCode::Esc => app.should_quit = true,
                    KeyCode::Char('p') => app.toggle_pause(),
                    KeyCode::Tab => app.next_tab(),
                    KeyCode::Char('0') => app.select_tab(0),
                    KeyCode::Char('1') => app.select_tab(1),
                    KeyCode::Char('2') => app.select_tab(2),
                    KeyCode::Char('3') => app.select_tab(3),
                    KeyCode::Char('4') => app.select_tab(4),
                    _ => {}
                }
            }
        }
        if app.should_quit {
            break;
        }
        if last_tick.elapsed() >= Duration::from_millis(750) {
            if let Some(url) = daemon_url {
                app.apply_remote_refresh(url);
            } else if !app.paused {
                app.push_xdp_point();
            }
            last_tick = Instant::now();
        }
    }
    Ok(())
}
