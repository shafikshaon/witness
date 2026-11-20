//! Witness desktop viewer: a read-mostly window onto the daemon's API (DESIGN.md §12).

mod model;
mod style;
mod views;

use dioxus::desktop::tao::window::Icon;
use dioxus::desktop::{Config, LogicalSize, WindowBuilder};

const ICON_PNG: &[u8] = include_bytes!("../../packaging/icons/witness-256.png");
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

/// The window/taskbar icon, decoded from the same PNG the package installs.
fn window_icon() -> Option<Icon> {
    let mut reader = png::Decoder::new(ICON_PNG).read_info().ok()?;
    let mut buf = vec![0; reader.output_buffer_size()];
    let info = reader.next_frame(&mut buf).ok()?;
    if info.color_type != png::ColorType::Rgba || info.bit_depth != png::BitDepth::Eight {
        return None;
    }
    buf.truncate(info.buffer_size());
    Icon::from_rgba(buf, info.width, info.height).ok()
}

fn main() {
    let socket = socket_path();
    // Just added to the `witness` group by the package? Use it without a new login.
    witness_client::rejoin_group_if_needed(&socket);
    let client = Client::new(socket);
    dioxus::LaunchBuilder::desktop()
        .with_cfg(
            Config::new().with_menu(None).with_window(
                WindowBuilder::new()
                    .with_title("Witness")
                    .with_window_icon(window_icon())
                    .with_inner_size(LogicalSize::new(1280.0, 800.0)),
            ),
        )
        .with_context(client)
        .launch(views::App);
}
