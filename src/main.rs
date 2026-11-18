#![cfg_attr(not(test), windows_subsystem = "windows")]
#![forbid(unsafe_code)]

mod ui;

use std::path::PathBuf;
use std::process::ExitCode;

use meskd_auth::{KdfParams, Vault};

const HELP: &str = "Meskd Authenticator

Usage: meskd-auth [--vault <file>]

  --vault <file>   use this vault file instead of the default location
  --version        print the version
  --help           print this help
";

fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    let mut path: Option<PathBuf> = None;
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--vault" => match args.next() {
                Some(p) => path = Some(PathBuf::from(p)),
                None => return usage("--vault needs a file path"),
            },
            "--version" => {
                println!("meskd-auth {}", env!("CARGO_PKG_VERSION"));
                return ExitCode::SUCCESS;
            }
            "--help" | "-h" => {
                print!("{HELP}");
                return ExitCode::SUCCESS;
            }
            other => return usage(&format!("unknown option {other}")),
        }
    }
    let Some(path) = path.or_else(Vault::default_path) else {
        return usage("could not find a data folder, pass --vault <file>");
    };

    let mut last_error = String::new();
    for renderer in [eframe::Renderer::Wgpu, eframe::Renderer::Glow] {
        let config = ui::Config {
            path: path.clone(),
            params: KdfParams::default(),
        };
        let options = eframe::NativeOptions {
            renderer,
            viewport: egui::ViewportBuilder::default()
                .with_title("Meskd Authenticator")
                .with_app_id("meskd-auth")
                .with_inner_size([440.0, 640.0])
                .with_min_inner_size([420.0, 460.0])
                .with_icon(ui::theme::icon()),
            centered: true,
            wgpu_options: wgpu_options(),
            ..Default::default()
        };
        let result = eframe::run_native(
            "Meskd Authenticator",
            options,
            Box::new(move |cc| {
                ui::theme::apply(&cc.egui_ctx);
                Ok(Box::new(ui::App::new(config)))
            }),
        );
        match result {
            Ok(()) => return ExitCode::SUCCESS,
            Err(e) => last_error = e.to_string(),
        }
    }
    eprintln!("meskd-auth: could not open a window: {last_error}");
    ExitCode::FAILURE
}

fn wgpu_options() -> eframe::egui_wgpu::WgpuConfiguration {
    let mut options = eframe::egui_wgpu::WgpuConfiguration::default();
    if cfg!(windows)
        && eframe::wgpu::Backends::from_env().is_none()
        && let eframe::egui_wgpu::WgpuSetup::CreateNew(setup) = &mut options.wgpu_setup
    {
        setup.instance_descriptor.backends = eframe::wgpu::Backends::DX12;
    }
    options
}

fn usage(message: &str) -> ExitCode {
    eprintln!("meskd-auth: {message}\n\n{HELP}");
    ExitCode::from(2)
}
