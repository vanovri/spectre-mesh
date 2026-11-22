#![deny(unsafe_code)]

pub mod app;
pub mod ui;

pub use app::{fetch_daemon_snapshot, CockpitApp, CockpitTab};
pub use ui::render_cockpit;
