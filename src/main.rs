use std::path::PathBuf;
use std::{fs, process};

use bun_binary_extractor::extractor::BunBinary;
use bun_binary_extractor::format::{
    BUNFS_PREFIX_UNIX,
    BUNFS_PREFIX_WIN,
    BUNFS_PREFIX_WIN_PUBLIC,
    MODULE_NAME_PREFIX,
};
use bun_binary_extractor::sourcemap::BunSourceMap;
use clap::Parser;
use regex::Regex;

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

    /// Preserve directory structure from sourcemap paths (default: true when --decode-sourcemaps)
    #[arg(long, default_value_t = true)]
    preserve_paths: bool,

    /// Flatten sourcemap sources to basename only (disables --preserve-paths)
    #[arg(long, conflicts_with = "preserve_paths")]
    no_preserve_paths: bool,

    /// Regex pattern to filter which sourcemap sources to extract (e.g., "^src/" to exclude node_modules)
    #[arg(long, value_name = "REGEX")]
    filter_sources: Option<String>,

    /// Do not write best-effort recovered JSX/TSX for transformed sourcemap sources
    #[arg(long)]
    no_decompile_sources: bool,

    /// Extract bytecode blobs (Bun precompiled bytecode, can be 100MB+)
    #[arg(long)]
    extract_bytecode: bool,

    /// Extract module info blobs used by Bun bytecode metadata
    #[arg(long)]
    extract_module_info: bool,
}

fn main() {
    let cli = Cli::parse();

    let filter_regex = cli.filter_sources.as_ref().map(|pattern| {
        Regex::new(pattern).unwrap_or_else(|e| {
            eprintln!("Error: invalid regex pattern '{}': {}", pattern, e);
            process::exit(1);
        })
    });

    if let Err(e) = run(&cli, filter_regex.as_ref()) {
        eprintln!("Error: {e}");
        process::exit(1);
    }
}

fn run(cli: &Cli, filter_regex: Option<&Regex>) -> Result<(), Box<dyn std::error::Error>> {
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
        let bc_info = module
            .bytecode
            .as_ref()
            .map(|bc| format!(" (bytecode: {:.1} MB)", bc.len() as f64 / 1_048_576.0))
            .unwrap_or_default();
        let mi_info = module
            .module_info
            .as_ref()
            .map(|mi| format!(" (module_info: {} bytes)", mi.len()))
            .unwrap_or_default();

        println!(
            "  [{:>2}] {} ({}, {} bytes, {}, {}, {}){}{sm_info}{bc_info}{mi_info}",
            module.index,
            module.name,
            module.file_type(),
            module.contents.len(),
            module.loader.as_str(),
            module.encoding.as_str(),
            module.module_format.as_str(),
            entry_marker,
        );

        if cli.verbose {
            if let Some(ref path) = module.bytecode_origin_path {
                println!("       bytecode_origin_path: {path}");
            }
        }
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

        let Some(rel_path) = output_relative_path(&module.name) else {
            eprintln!("  Skipping module with unsafe path: {}", module.name);
            continue;
        };
        let out_path = cli.output.join(&rel_path);

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
                        let preserve = cli.preserve_paths && !cli.no_preserve_paths;
                        let source_report = decoded.write_sources_with_manifest(
                            &sources_dir,
                            preserve,
                            filter_regex,
                            !cli.no_decompile_sources,
                        )?;
                        if cli.verbose {
                            println!(
                                "  Wrote {} source files to {}",
                                source_report.written,
                                sources_dir.display()
                            );
                            println!(
                                "  Wrote source manifest to {}",
                                source_report.manifest_path.display()
                            );
                            if source_report.recovered > 0 {
                                println!(
                                    "  Wrote {} recovered source files to {}",
                                    source_report.recovered,
                                    source_report
                                        .recovered_dir
                                        .as_ref()
                                        .map(|path| path.display().to_string())
                                        .unwrap_or_else(|| "<none>".to_string())
                                );
                            }
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

        // Extract bytecode blob if --extract-bytecode is set
        if cli.extract_bytecode {
            if let Some(ref bytecode) = module.bytecode {
                let mut bc_name = out_path.as_os_str().to_owned();
                bc_name.push(".bytecode");
                let bc_path = PathBuf::from(bc_name);
                fs::write(&bc_path, bytecode)?;
                if cli.verbose {
                    println!(
                        "  Wrote {} ({:.1} MB, Bun bytecode)",
                        bc_path.display(),
                        bytecode.len() as f64 / 1_048_576.0
                    );
                } else {
                    println!(
                        "  Bytecode: {} ({:.1} MB)",
                        bc_path.display(),
                        bytecode.len() as f64 / 1_048_576.0
                    );
                }
            }
        }

        if cli.extract_module_info {
            if let Some(ref module_info) = module.module_info {
                let mut info_name = out_path.as_os_str().to_owned();
                info_name.push(".module_info");
                let info_path = PathBuf::from(info_name);
                fs::write(&info_path, module_info)?;
                if cli.verbose {
                    println!(
                        "  Wrote {} ({} bytes, Bun module info)",
                        info_path.display(),
                        module_info.len()
                    );
                } else {
                    println!(
                        "  Module info: {} ({} bytes)",
                        info_path.display(),
                        module_info.len()
                    );
                }
            }
        }
    }

    println!("Extracted {extracted} files.");
    Ok(())
}

fn output_relative_path(module_name: &str) -> Option<PathBuf> {
    if module_name.as_bytes().contains(&0) {
        return None;
    }

    let (mut rel, is_bun_virtual) = if let Some(rel) = module_name.strip_prefix(BUNFS_PREFIX_UNIX) {
        (rel, true)
    } else if let Some(rel) = module_name.strip_prefix(MODULE_NAME_PREFIX) {
        (rel, true)
    } else if let Some(rel) = module_name.strip_prefix(BUNFS_PREFIX_WIN) {
        (rel, true)
    } else if let Some(rel) = module_name.strip_prefix(BUNFS_PREFIX_WIN_PUBLIC) {
        (rel, true)
    } else {
        (module_name, false)
    };

    if is_bun_virtual {
        rel = rel
            .strip_prefix("root/")
            .or_else(|| rel.strip_prefix("root\\"))
            .unwrap_or(rel);
    } else if rel.starts_with('/') || rel.starts_with('\\') {
        return None;
    }

    let mut parts = Vec::new();
    for part in rel.split(['/', '\\']) {
        match part {
            "" | "." => {}
            ".." => {
                if parts.pop().is_none() && !is_bun_virtual {
                    return None;
                }
            }
            _ if part.contains(':') => return None,
            _ => parts.push(part),
        }
    }

    if parts.is_empty() {
        return None;
    }

    let mut path = PathBuf::new();
    for part in parts {
        path.push(part);
    }
    Some(path)
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::output_relative_path;

    #[test]
    fn strips_bun_root_prefix() {
        assert_eq!(
            output_relative_path("/$bunfs/root/src/index.js"),
            Some(PathBuf::from("src/index.js"))
        );
    }

    #[test]
    fn keeps_virtual_dependency_paths_inside_output_dir() {
        assert_eq!(
            output_relative_path(
                "/$bunfs/root/../../node_modules/.bun/pkg/node_modules/pkg/parser.worker.js"
            ),
            Some(PathBuf::from(
                "node_modules/.bun/pkg/node_modules/pkg/parser.worker.js"
            ))
        );
    }

    #[test]
    fn rejects_host_parent_escapes() {
        assert_eq!(output_relative_path("../../etc/passwd"), None);
    }

    #[test]
    fn rejects_host_absolute_paths() {
        assert_eq!(output_relative_path("/etc/passwd"), None);
    }
}
