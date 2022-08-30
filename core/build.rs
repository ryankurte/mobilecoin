//! Build script to compile protobuf files


#[cfg(feature = "protos")]
const PROTO_DIR: &str = "../api/proto";

fn main() -> anyhow::Result<()> {
    
    #[cfg(feature = "protos")]
    build_protos(PROTO_DIR)?;
    
    Ok(())
}

#[cfg(feature = "protos")]
const FIELD_ATTRS: &[(&str, &str)] = &[
];

#[cfg(feature = "protos")]
const TYPE_ATTRS: &[(&str, &str)] = &[

];

/// Build protocol files from specified directory
#[cfg(feature = "protos")]
fn build_protos(proto_dir: &str) -> anyhow::Result<()> {
    
    // Rebuild on proto changes
    println!("cargo:rerun-if-changed={}", proto_dir);

    // Glob for proto files
    let files: Vec<_> = glob::glob(&format!("{}/*.proto", proto_dir))?
            .filter_map(|f| f.ok() ).collect();

    // Setup prost
    let mut c = &mut prost_build::Config::new();

    // Apply field attributes
    for (path, attr) in FIELD_ATTRS {
        c = c.field_attribute(path, attr);
    }
    
    // Apply type attributes
    for (path, attr) in TYPE_ATTRS {
        c = c.type_attribute(path, attr);
    }

    // Build proto files
    c.compile_protos(&files, &[proto_dir])?;

    Ok(())
}
