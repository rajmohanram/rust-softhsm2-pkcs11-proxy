use std::path::Path;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let proto_file = Path::new("../proto/pkcs11_proxy.proto");

    if proto_file.exists() {
        prost_build::compile_protos(&["../proto/pkcs11_proxy.proto"], &["../proto/"])?;
    } else {
        // Proto file does not exist yet. Generate an empty module so the
        // `include!` in protocol.rs still compiles.
        let out_dir = std::env::var("OUT_DIR")?;
        let dest = Path::new(&out_dir).join("pkcs11_proxy.rs");
        std::fs::write(
            &dest,
            "// Auto-generated stub — proto file not yet available.\n",
        )?;
        eprintln!(
            "cargo:warning=Proto file {:?} not found; generating empty stub.",
            proto_file
        );
    }

    Ok(())
}
