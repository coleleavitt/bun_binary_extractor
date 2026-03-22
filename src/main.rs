use std::fs;
use std::path::PathBuf;
use std::process;

use clap::Parser;

use bun_binary_extractor::extractor::BunBinary;

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
        eprintln!("Embed method: {:?}", binary.embed_method);
        eprintln!("Payload base: 0x{:x}", binary.payload_base);
        eprintln!("Module struct size: {} bytes", binary.module_struct_size);
        eprintln!("Module count: {}", binary.modules.len());
        eprintln!("Entry point: {}", binary.offsets.entry_point_id);
        if let Some(argv) = binary.argv() {
            eprintln!("Argv: {argv}");
        }
        eprintln!();
    }

    println!(
        "Found {} modules in {:?}",
        binary.modules.len(),
        cli.binary_path
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
            "  [{:>2}] {} ({}, {} bytes, {}, {}){}{sm_info}",
            module.index,
            module.name,
            module.file_type(),
            module.contents.len(),
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
        if cli.js_only && !matches!(module.file_type(), "JavaScript" | "TypeScript") {
            continue;
        }

        let rel_path = module.relative_path();
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
            let sm_path = out_path.with_extension(format!(
                "{}.map",
                out_path.extension().and_then(|e| e.to_str()).unwrap_or("")
            ));
            fs::write(&sm_path, sourcemap)?;
            if cli.verbose {
                println!("  Wrote {} ({} bytes)", sm_path.display(), sourcemap.len());
            }
        }
    }

    println!("Extracted {extracted} files.");
    Ok(())
}
