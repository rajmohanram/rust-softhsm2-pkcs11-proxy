//! pkcs11-proxyd — PKCS#11 proxy server daemon.
//!
//! Accepts TLS-PSK connections from proxy clients, deserializes protobuf
//! requests, dispatches them to a real PKCS#11 module (e.g. libsofthsm2.so),
//! and returns protobuf responses.

mod handler;
mod server;
mod session_map;

use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::Parser;
use tracing::info;

/// PKCS#11 proxy server daemon.
#[derive(Parser, Debug)]
#[command(name = "pkcs11-proxyd", version, about)]
struct Args {
    /// Path to the PKCS#11 module shared library.
    #[arg(long, env = "PKCS11_MODULE")]
    module: PathBuf,

    /// Address and port to listen on.
    #[arg(long, default_value = "0.0.0.0:2345", env = "PKCS11_LISTEN")]
    listen: String,

    /// Path to the PSK identity/key file.
    #[arg(long, env = "PKCS11_PSK_FILE")]
    psk_file: PathBuf,
}

#[tokio::main]
async fn main() -> Result<()> {
    // Log level: PKCS11_PROXY_LOG_LEVEL > RUST_LOG > default "info"
    let filter = std::env::var("PKCS11_PROXY_LOG_LEVEL")
        .ok()
        .and_then(|v| tracing_subscriber::EnvFilter::try_new(&v).ok())
        .or_else(|| tracing_subscriber::EnvFilter::try_from_default_env().ok())
        .unwrap_or_else(|| tracing_subscriber::EnvFilter::new("info"));

    tracing_subscriber::fmt().with_env_filter(filter).init();

    let args = Args::parse();

    info!(module = %args.module.display(), "loading PKCS#11 module");

    // Load the PKCS#11 module directly via libloading and resolve
    // C_GetFunctionList. This gives us the raw function list pointer
    // without the double-load issue that occurs when using cryptoki::Pkcs11
    // alongside a separate libloading::Library::new().
    let fn_list: *mut cryptoki_sys::CK_FUNCTION_LIST = unsafe {
        let lib = libloading::Library::new(&args.module)
            .with_context(|| format!("failed to load PKCS#11 module: {}", args.module.display()))?;

        let get_fn_list: libloading::Symbol<
            unsafe extern "C" fn(*mut *mut cryptoki_sys::CK_FUNCTION_LIST) -> cryptoki_sys::CK_RV,
        > = lib
            .get(b"C_GetFunctionList")
            .context("C_GetFunctionList symbol not found")?;

        let mut fl: *mut cryptoki_sys::CK_FUNCTION_LIST = std::ptr::null_mut();
        let rv = get_fn_list(&mut fl);
        if rv != cryptoki_sys::CKR_OK || fl.is_null() {
            anyhow::bail!("C_GetFunctionList failed (rv=0x{:x})", rv);
        }

        // Initialize the module.
        let c_initialize = (*fl).C_Initialize.context("C_Initialize not available")?;
        let rv = c_initialize(std::ptr::null_mut());
        if rv != cryptoki_sys::CKR_OK && rv != cryptoki_sys::CKR_CRYPTOKI_ALREADY_INITIALIZED {
            anyhow::bail!("C_Initialize failed (rv=0x{:x})", rv);
        }

        // Leak the library so it stays loaded for the process lifetime.
        std::mem::forget(lib);

        fl
    };

    handler::set_function_list(fn_list);
    info!("PKCS#11 module initialized");

    // Load PSK: env vars first, then file.
    let psk = if let Some(entry) = pkcs11_common::load_psk_from_env()
        .context("failed to parse PKCS11_PROXY_TLS_PSK env var")?
    {
        info!("using PSK from PKCS11_PROXY_TLS_PSK env var");
        entry
    } else {
        info!(path = %args.psk_file.display(), "using PSK from file");
        pkcs11_common::load_psk_file(&args.psk_file)
            .with_context(|| format!("failed to load PSK file: {}", args.psk_file.display()))?
    };

    info!(listen = %args.listen, "starting TLS-PSK server");

    server::run_server(&args.listen, psk).await?;

    Ok(())
}
