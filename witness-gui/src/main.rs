//! Witness desktop viewer: a read-mostly window onto the daemon's API (DESIGN.md §12).

mod model;
mod style;
mod views;

use dioxus::desktop::{Config, LogicalSize, WindowBuilder};
use witness_client::{Client, DEFAULT_SOCKET};

/// The daemon socket: `--socket PATH`, else `WITNESS_SOCKET`, else the default.
fn socket_path() -> std::path::PathBuf {
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        if a == "--socket" {
            if let Some(p) = args.next() {
                return p.into();
            }
        } else if let Some(p) = a.strip_prefix("--socket=") {
            return p.into();
        }
    }
    std::env::var_os("WITNESS_SOCKET")
        .map(Into::into)
        .unwrap_or_else(|| DEFAULT_SOCKET.into())
}

fn main() {
    let client = Client::new(socket_path());
    dioxus::LaunchBuilder::desktop()
        .with_cfg(
            Config::new().with_menu(None).with_window(
                WindowBuilder::new()
                    .with_title("Witness")
                    .with_inner_size(LogicalSize::new(1280.0, 800.0)),
            ),
        )
        .with_context(client)
        .launch(views::App);
}
