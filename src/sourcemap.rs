//! Bun binary sourcemap decoder.
//!
//! Bun stores sourcemaps in a custom binary format (NOT standard JSON).
//! This module decodes that format into standard JSON sourcemaps.

use std::fs;
use std::io::Write;
use std::path::Path;

use crate::error::ExtractError;
use crate::format::StringPointer;

/// Header of a Bun binary sourcemap (8 bytes).
#[derive(Debug, Clone, Copy)]
pub struct SourceMapHeader {
    /// Number of source files in the sourcemap.
    pub source_files_count: u32,
    /// Length of the VLQ mappings section in bytes.
    pub map_bytes_length: u32,
}

impl SourceMapHeader {
    /// Parse header from an 8-byte little-endian slice.
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() < 8 {
            return None;
        }
        Some(Self {
            source_files_count: u32::from_le_bytes(data[0..4].try_into().ok()?),
            map_bytes_length: u32::from_le_bytes(data[4..8].try_into().ok()?),
        })
    }
}

/// A decoded Bun binary sourcemap.
#[derive(Debug)]
pub struct BunSourceMap {
    /// Source file names (relative paths).
    pub sources: Vec<String>,
    /// Decompressed source file contents.
    pub sources_content: Vec<String>,
    /// Raw VLQ-encoded mappings string.
    pub mappings: String,
}

impl BunSourceMap {
    /// Parse a Bun binary sourcemap blob.
    ///
    /// # Binary Format
    ///
    /// ```text
    /// Header (8 bytes):
    ///   source_files_count: u32 (LE)
    ///   map_bytes_length:   u32 (LE)
    ///
    /// source_files_count x StringPointer (8 bytes each):
    ///   -> file name pointers { offset: u32 LE, length: u32 LE }
    ///
    /// source_files_count x StringPointer (8 bytes each):
    ///   -> ZSTD-compressed source content pointers { offset: u32 LE, length: u32 LE }
    ///
    /// VLQ mappings (map_bytes_length bytes):
    ///   -> raw VLQ-encoded source mappings
    ///
    /// String payload:
    ///   -> file names (plain UTF-8)
    ///   -> compressed source file contents (ZSTD compressed)
    /// ```
    ///
    /// **CRITICAL**: StringPointer offsets are relative to the START of the entire
    /// sourcemap blob, not to the string payload section.
    pub fn parse(blob: &[u8]) -> Result<Self, ExtractError> {
        // Parse header
        let header =
            SourceMapHeader::from_bytes(blob).ok_or(ExtractError::SourceMapParseFailed {
                reason: "blob too small for header",
            })?;

        let count = header.source_files_count as usize;
        let map_len = header.map_bytes_length as usize;

        // Calculate offsets
        const HEADER_SIZE: usize = 8;
        const SP_SIZE: usize = 8;

        let names_ptrs_start = HEADER_SIZE;
        let names_ptrs_end =
            names_ptrs_start
                .checked_add(count.checked_mul(SP_SIZE).ok_or(
                    ExtractError::SourceMapParseFailed {
                        reason: "overflow computing names pointers size",
                    },
                )?)
                .ok_or(ExtractError::SourceMapParseFailed {
                    reason: "overflow computing names pointers end",
                })?;

        let contents_ptrs_start = names_ptrs_end;
        let contents_ptrs_end =
            contents_ptrs_start
                .checked_add(count.checked_mul(SP_SIZE).ok_or(
                    ExtractError::SourceMapParseFailed {
                        reason: "overflow computing contents pointers size",
                    },
                )?)
                .ok_or(ExtractError::SourceMapParseFailed {
                    reason: "overflow computing contents pointers end",
                })?;

        let mappings_start = contents_ptrs_end;
        let mappings_end =
            mappings_start
                .checked_add(map_len)
                .ok_or(ExtractError::SourceMapParseFailed {
                    reason: "overflow computing mappings end",
                })?;

        if mappings_end > blob.len() {
            return Err(ExtractError::SourceMapParseFailed {
                reason: "blob too small for declared structure",
            });
        }

        // Parse file name pointers
        let mut name_ptrs = Vec::with_capacity(count);
        for i in 0..count {
            let offset = names_ptrs_start + i * SP_SIZE;
            let sp = StringPointer::from_bytes(&blob[offset..offset + SP_SIZE]).ok_or(
                ExtractError::SourceMapParseFailed {
                    reason: "failed to parse name StringPointer",
                },
            )?;
            name_ptrs.push(sp);
        }

        // Parse content pointers
        let mut content_ptrs = Vec::with_capacity(count);
        for i in 0..count {
            let offset = contents_ptrs_start + i * SP_SIZE;
            let sp = StringPointer::from_bytes(&blob[offset..offset + SP_SIZE]).ok_or(
                ExtractError::SourceMapParseFailed {
                    reason: "failed to parse content StringPointer",
                },
            )?;
            content_ptrs.push(sp);
        }

        // Extract mappings (raw VLQ string)
        let mappings_bytes = &blob[mappings_start..mappings_end];
        let mappings = std::str::from_utf8(mappings_bytes)
            .map_err(|_| ExtractError::SourceMapParseFailed {
                reason: "mappings is not valid UTF-8",
            })?
            .to_string();

        // Extract source file names
        let mut sources = Vec::with_capacity(count);
        for sp in &name_ptrs {
            let start = sp.offset as usize;
            let end = start.checked_add(sp.length as usize).ok_or(
                ExtractError::SourceMapParseFailed {
                    reason: "overflow computing name slice",
                },
            )?;
            if end > blob.len() {
                return Err(ExtractError::SourceMapParseFailed {
                    reason: "name pointer out of bounds",
                });
            }
            let name = std::str::from_utf8(&blob[start..end])
                .map_err(|_| ExtractError::SourceMapParseFailed {
                    reason: "source name is not valid UTF-8",
                })?
                .to_string();
            sources.push(name);
        }

        // Extract and decompress source contents
        let mut sources_content = Vec::with_capacity(count);
        for sp in &content_ptrs {
            let start = sp.offset as usize;
            let end = start.checked_add(sp.length as usize).ok_or(
                ExtractError::SourceMapParseFailed {
                    reason: "overflow computing content slice",
                },
            )?;
            if end > blob.len() {
                return Err(ExtractError::SourceMapParseFailed {
                    reason: "content pointer out of bounds",
                });
            }
            let compressed = &blob[start..end];

            // Decompress with zstd
            let decompressed = zstd::decode_all(compressed)
                .map_err(|e| ExtractError::ZstdDecompressFailed(e.to_string()))?;

            let content = String::from_utf8(decompressed).map_err(|_| {
                ExtractError::SourceMapParseFailed {
                    reason: "decompressed content is not valid UTF-8",
                }
            })?;
            sources_content.push(content);
        }

        Ok(Self {
            sources,
            sources_content,
            mappings,
        })
    }

    /// Serialize to a standard JSON sourcemap.
    ///
    /// Returns a JSON object with:
    /// - `version`: 3
    /// - `sources`: array of source file names
    /// - `sourcesContent`: array of source file contents
    /// - `mappings`: VLQ-encoded mappings string
    pub fn to_json(&self) -> Result<String, ExtractError> {
        let json = serde_json::json!({
            "version": 3,
            "sources": self.sources,
            "sourcesContent": self.sources_content,
            "mappings": self.mappings
        });
        serde_json::to_string_pretty(&json).map_err(ExtractError::from)
    }

    /// Write the JSON sourcemap to a file.
    pub fn write_json(&self, path: &Path) -> Result<(), ExtractError> {
        let json = self.to_json()?;
        fs::write(path, json)?;
        Ok(())
    }

    /// Write individual source files to a directory.
    ///
    /// Path sanitization strips leading `../` and `/`, converts `\` to `/`,
    /// and skips paths with remaining `..` components.
    pub fn write_sources(
        &self,
        dir: &Path,
        preserve_paths: bool,
        filter: Option<&regex::Regex>,
    ) -> Result<usize, ExtractError> {
        fs::create_dir_all(dir)?;

        let mut written = 0;
        for (name, content) in self.sources.iter().zip(self.sources_content.iter()) {
            if let Some(re) = filter {
                if !re.is_match(name) {
                    continue;
                }
            }

            let relative_path = if preserve_paths {
                match sanitize_source_path(name) {
                    Some(p) => p,
                    None => continue,
                }
            } else {
                Path::new(name)
                    .file_name()
                    .map(|s| s.to_string_lossy().into_owned())
                    .unwrap_or_else(|| name.clone())
            };

            let file_path = dir.join(&relative_path);

            if let Some(parent) = file_path.parent() {
                fs::create_dir_all(parent)?;
            }

            let final_path = if file_path.exists() {
                let ext = Path::new(&relative_path)
                    .extension()
                    .map(|s| format!(".{}", s.to_string_lossy()))
                    .unwrap_or_default();

                let parent = file_path.parent().unwrap_or(dir);
                let basename_stem = Path::new(&relative_path)
                    .file_name()
                    .and_then(|f| Path::new(f).file_stem())
                    .map(|s| s.to_string_lossy().into_owned())
                    .unwrap_or_else(|| relative_path.clone());

                let mut idx = 1;
                loop {
                    let candidate = parent.join(format!("{basename_stem}_{idx}{ext}"));
                    if !candidate.exists() {
                        break candidate;
                    }
                    idx += 1;
                }
            } else {
                file_path
            };

            let mut file = fs::File::create(&final_path)?;
            file.write_all(content.as_bytes())?;
            written += 1;
        }

        Ok(written)
    }
}

/// Sanitize a sourcemap path: strip leading `../` and `/`, reject remaining `..` components.
fn sanitize_source_path(path: &str) -> Option<String> {
    let normalized = path.replace('\\', "/");
    let mut result = normalized.as_str();

    while result.starts_with('/') {
        result = &result[1..];
    }

    while result.starts_with("../") {
        result = &result[3..];
    }

    if result == ".." {
        return None;
    }

    for component in result.split('/') {
        if component == ".." {
            return None;
        }
    }

    if result.is_empty() {
        return None;
    }

    Some(result.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_header_parse() {
        let data = [
            0x02, 0x00, 0x00, 0x00, // source_files_count = 2
            0x10, 0x00, 0x00, 0x00, // map_bytes_length = 16
        ];
        let header = SourceMapHeader::from_bytes(&data).unwrap();
        assert_eq!(header.source_files_count, 2);
        assert_eq!(header.map_bytes_length, 16);
    }

    #[test]
    fn test_header_too_small() {
        let data = [0x02, 0x00, 0x00, 0x00];
        assert!(SourceMapHeader::from_bytes(&data).is_none());
    }
}
