use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use clap::Parser;
use tokio::net::TcpListener;
use tracing_subscriber::EnvFilter;

use rynx_api::daemon::DaemonClient;
use rynx_api::ratelimit::LoginLimiter;
use rynx_api::routes;
use rynx_api::state::ApiState;
use rynx_core::ApiConfig;
use rynx_panel::PanelDb;

#[derive(Debug, Parser)]
#[command(name = "rynx-api", version, about = "RYNXCP web API and panel")]
struct Args {
    /// Path to the API configuration (TOML).
    #[arg(long, env = "RYNXCP_API_CONFIG")]
    config: Option<PathBuf>,
    /// Validate configuration and exit.
    #[arg(long)]
    check: bool,
}

fn default_config_path() -> PathBuf {
    if cfg!(windows) {
        PathBuf::from("rynx-api.toml")
    } else {
        PathBuf::from("/etc/rynxcp/api.toml")
    }
}

fn init_tracing(default_level: &str) {
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(default_level));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .init();
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let config_path = args.config.unwrap_or_else(default_config_path);
    let cfg = ApiConfig::load(&config_path)
        .with_context(|| format!("cannot load {}", config_path.display()))?;
    init_tracing(&cfg.log_level);

    let db = Arc::new(
        PanelDb::open(&cfg.database)
            .with_context(|| format!("cannot open {}", cfg.database.display()))?,
    );
    if db.count_users()? == 0 {
        tracing::warn!(
            "no panel users exist; create the first administrator with: rynxctl admin create <username>"
        );
    }

    let daemon = Arc::new(DaemonClient::new(&cfg).with_context(|| {
        format!(
            "cannot load daemon token from {} (start rynxd first)",
            cfg.daemon_token_file.display()
        )
    })?);

    let mailer = rynx_api::email::Mailer::from_config(&cfg)
        .context("invalid panel SMTP configuration")?
        .map(Arc::new);

    let state = ApiState {
        cfg: Arc::new(cfg.clone()),
        db,
        daemon,
        limiter: Arc::new(LoginLimiter::new(
            cfg.login_max_attempts,
            cfg.login_ip_max_attempts,
            cfg.login_window_secs,
            cfg.login_lockout_secs,
        )),
        reset_limiter: Arc::new(LoginLimiter::new(
            5,
            1000,
            cfg.login_window_secs.max(900),
            cfg.login_lockout_secs.max(900),
        )),
        cert_jobs: rynx_api::cert_jobs::new_store(),
        installer_jobs: rynx_api::installer::new_store(),
        mailer,
        two_factor: Arc::new(Default::default()),
        webauthn: rynx_api::webauthn::build(&cfg),
        passkey_flows: Arc::new(Default::default()),
        agent_lock: Arc::new(tokio::sync::Mutex::new(())),
        identity_lock: Arc::new(tokio::sync::Mutex::new(())),
    };

    if args.check {
        println!(
            "configuration OK: bind={} database={} web_root={} daemon={}",
            cfg.bind,
            cfg.database.display(),
            cfg.web_root.display(),
            cfg.daemon_tcp
                .clone()
                .unwrap_or_else(|| cfg.daemon_socket.display().to_string())
        );
        return Ok(());
    }

    if !cfg.web_root.exists() {
        tracing::warn!(path = %cfg.web_root.display(), "web root does not exist");
    }

    rynx_api::agent::spawn(state.clone());
    let app = routes::router(state);
    let listener = TcpListener::bind(&cfg.bind)
        .await
        .with_context(|| format!("cannot bind {}", cfg.bind))?;
    tracing::info!(bind = %cfg.bind, "RYNXCP API listening");

    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(async {
        let _ = tokio::signal::ctrl_c().await;
        tracing::info!("shutdown requested");
    })
    .await?;
    Ok(())
}
