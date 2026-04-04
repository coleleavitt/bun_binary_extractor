use std::path::{Component, PathBuf};
use std::{fs, process};

use bun_binary_extractor::extractor::BunBinary;
use bun_binary_extractor::sourcemap::BunSourceMap;
use clap::Parser;

#[derive(Parser)]
#[command(name = "bun_binary_extractor")]
#[command(about = "Extract embedded files from Bun-compiled single-file executables")]
struct Cli {
    /// Path to Bun-compiled binary
    binary_path: PathBuf,

    /// Output directory
    #[arg(short, long, default_value = "./extracted")]
    output: PathBuf,

    /// Print detailed module info
    #[arg(short, long)]
    verbose: bool,

    /// Only extract JavaScript files
    #[arg(long)]
    js_only: bool,

    /// List modules without extracting
    #[arg(long)]
    list: bool,

    /// Decode binary sourcemaps to standard JSON format
    #[arg(long)]
    decode_sourcemaps: bool,
}

fn main() {
    let cli = Cli::parse();

    if let Err(e) = run(&cli) {
        eprintln!("Error: {e}");
        process::exit(1);
    }
}

fn run(cli: &Cli) -> Result<(), Box<dyn std::error::Error>> {
    let binary = BunBinary::from_file(&cli.binary_path)?;

    if cli.verbose {
        eprintln!("Detected version: {}", binary.version);
        eprintln!("Embed method: {}", binary.embed_method);
        eprintln!("Payload base: 0x{:x}", binary.payload_base);
        eprintln!("Module struct size: {} bytes", binary.module_struct_size);
        eprintln!("Module count: {}", binary.modules.len());
        eprintln!("Entry point: {}", binary.offsets.entry_point_id);
        if binary.offsets.flags != 0 {
            let flags = binary.offsets.decoded_flags();
            eprintln!("Flags: {:#010x}", binary.offsets.flags);
            eprintln!("  disable_env_files: {}", flags.disable_default_env_files);
            eprintln!("  disable_bunfig: {}", flags.disable_autoload_bunfig);
            eprintln!("  disable_tsconfig: {}", flags.disable_autoload_tsconfig);
            eprintln!(
                "  disable_package_json: {}",
                flags.disable_autoload_package_json
            );
        }
        if let Some(ref argv) = binary.argv {
            eprintln!("Argv: {argv}");
        }
        eprintln!();
    }

    println!(
        "Found {} modules in {:?} ({})",
        binary.modules.len(),
        cli.binary_path,
        binary.version,
    );
    println!();

    for module in &binary.modules {
        let entry_marker = if module.is_entry_point {
            " [ENTRY]"
        } else {
            ""
        };
        let sm_info = module
            .sourcemap
            .as_ref()
            .map(|sm| format!(" (sourcemap: {} bytes)", sm.len()))
            .unwrap_or_default();

        println!(
            "  [{:>2}] {} ({}, {} bytes, {}, {}, {}){}{sm_info}",
            module.index,
            module.name,
            module.file_type(),
            module.contents.len(),
            module.loader.as_str(),
            module.encoding.as_str(),
            module.module_format.as_str(),
            entry_marker,
        );
    }

    if cli.list {
        return Ok(());
    }

    println!();
    println!("Extracting to {:?}...", cli.output);

    let mut extracted = 0;
    for module in &binary.modules {
        if cli.js_only
            && !module.loader.is_javascript()
            && !matches!(module.file_type(), "JavaScript" | "TypeScript")
        {
            continue;
        }

        let rel_path = module.relative_path();
        let rel = std::path::Path::new(rel_path);
        let has_unsafe_component = rel.components().any(|c| {
            matches!(
                c,
                Component::ParentDir | Component::RootDir | Component::Prefix(_)
            )
        });
        if has_unsafe_component {
            eprintln!("  Skipping module with unsafe path: {}", module.name);
            continue;
        }
        let out_path = cli.output.join(rel_path);

        if let Some(parent) = out_path.parent() {
            fs::create_dir_all(parent)?;
        }

        fs::write(&out_path, &module.contents)?;
        extracted += 1;

        if cli.verbose {
            println!(
                "  Wrote {} ({} bytes)",
                out_path.display(),
                module.contents.len()
            );
        }

        if let Some(ref sourcemap) = module.sourcemap {
            let mut sm_name = out_path.as_os_str().to_owned();
            sm_name.push(".map");
            let sm_path = PathBuf::from(sm_name);

            if cli.decode_sourcemaps {
                match BunSourceMap::parse(sourcemap) {
                    Ok(decoded) => {
                        decoded.write_json(&sm_path)?;
                        if cli.verbose {
                            println!(
                                "  Wrote {} (decoded JSON, {} sources)",
                                sm_path.display(),
                                decoded.sources.len()
                            );
                        }

                        let sources_dir = out_path.parent().unwrap_or(&cli.output).join("sources");
                        let written = decoded.write_sources(&sources_dir)?;
                        if cli.verbose {
                            println!(
                                "  Wrote {} source files to {}",
                                written,
                                sources_dir.display()
                            );
                        }
                    }
                    Err(e) => {
                        eprintln!(
                            "  Warning: failed to decode sourcemap for {}: {e}",
                            module.name
                        );
                        fs::write(&sm_path, sourcemap)?;
                        if cli.verbose {
                            println!(
                                "  Wrote {} ({} bytes, raw binary)",
                                sm_path.display(),
                                sourcemap.len()
                            );
                        }
                    }
                }
            } else {
                fs::write(&sm_path, sourcemap)?;
                if cli.verbose {
                    println!("  Wrote {} ({} bytes)", sm_path.display(), sourcemap.len());
                }
            }
        }
    }

    println!("Extracted {extracted} files.");
    Ok(())
}
