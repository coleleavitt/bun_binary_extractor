//! Bun binary sourcemap decoder.
//!
//! Bun stores sourcemaps in a custom binary format (NOT standard JSON).
//! This module decodes that format into standard JSON sourcemaps.

use std::fs;
use std::io::Write;
use std::path::Path;

use crate::error::ExtractError;
use crate::format::{BUNFS_PREFIX_WIN_PUBLIC, MODULE_NAME_PREFIX, StringPointer};

const INTERNAL_SOURCEMAP_HEADER_SIZE: usize = 32;
const SYNC_ENTRY_SIZE: usize = 24;
const SYNC_INTERVAL: u8 = 64;
const STREAM_TAIL_PAD: usize = 1;

const FLAG_HAS_GEN_LINE_EXCEPTIONS: u8 = 1 << 2;
const FLAG_HAS_SRC_IDX: u8 = 1 << 3;

const BASE64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Header of a Bun binary sourcemap (8 bytes).
#[derive(Debug, Clone, Copy)]
pub struct SourceMapHeader {
    /// Number of source files in the sourcemap.
    pub source_files_count: u32,
    /// Length of Bun's internal source-map mapping blob in bytes.
    pub map_bytes_length: u32,
}

#[derive(Debug, Clone, Copy, Default)]
struct MapState {
    generated_line: i32,
    generated_column: i32,
    source_index: i32,
    original_line: i32,
    original_column: i32,
}

#[derive(Debug, Clone, Copy)]
struct SyncEntry {
    generated_line: i32,
    generated_column: i32,
    byte_offset: usize,
    original_line: i32,
    original_column: i32,
    source_index: i32,
}

impl SyncEntry {
    fn to_state(self) -> MapState {
        MapState {
            generated_line: self.generated_line,
            generated_column: self.generated_column,
            source_index: self.source_index,
            original_line: self.original_line,
            original_column: self.original_column,
        }
    }
}

struct InternalSourceMap<'a> {
    blob: &'a [u8],
    sync_count: usize,
    stream_offset: usize,
}

impl<'a> InternalSourceMap<'a> {
    fn parse(blob: &'a [u8]) -> Result<Self, ExtractError> {
        if blob.len() < INTERNAL_SOURCEMAP_HEADER_SIZE {
            return Err(ExtractError::SourceMapParseFailed {
                reason: "internal sourcemap blob too small",
            });
        }

        let total_len = read_u64(blob, 0)? as usize;
        if total_len != blob.len() {
            return Err(ExtractError::SourceMapParseFailed {
                reason: "internal sourcemap length mismatch",
            });
        }

        let sync_count = read_u32(blob, 24)? as usize;
        let stream_offset = read_u32(blob, 28)? as usize;
        let sync_end = INTERNAL_SOURCEMAP_HEADER_SIZE
            .checked_add(sync_count.checked_mul(SYNC_ENTRY_SIZE).ok_or(
                ExtractError::SourceMapParseFailed {
                    reason: "internal sourcemap sync table overflow",
                },
            )?)
            .ok_or(ExtractError::SourceMapParseFailed {
                reason: "internal sourcemap sync table overflow",
            })?;

        if stream_offset < sync_end || stream_offset > total_len {
            return Err(ExtractError::SourceMapParseFailed {
                reason: "internal sourcemap stream offset out of bounds",
            });
        }
        if total_len < stream_offset + STREAM_TAIL_PAD {
            return Err(ExtractError::SourceMapParseFailed {
                reason: "internal sourcemap missing stream tail pad",
            });
        }

        Ok(Self {
            blob,
            sync_count,
            stream_offset,
        })
    }

    fn sync_entry(&self, index: usize) -> Result<SyncEntry, ExtractError> {
        let off = INTERNAL_SOURCEMAP_HEADER_SIZE
            .checked_add(index.checked_mul(SYNC_ENTRY_SIZE).ok_or(
                ExtractError::SourceMapParseFailed {
                    reason: "internal sourcemap sync entry overflow",
                },
            )?)
            .ok_or(ExtractError::SourceMapParseFailed {
                reason: "internal sourcemap sync entry overflow",
            })?;
        Ok(SyncEntry {
            generated_line: read_i32(self.blob, off)?,
            generated_column: read_i32(self.blob, off + 4)?,
            byte_offset: read_u32(self.blob, off + 8)? as usize,
            original_line: read_i32(self.blob, off + 12)?,
            original_column: read_i32(self.blob, off + 16)?,
            source_index: read_i32(self.blob, off + 20)?,
        })
    }

    fn stream(&self) -> &'a [u8] {
        &self.blob[self.stream_offset..]
    }

    fn to_vlq(&self) -> Result<String, ExtractError> {
        let mut out = Vec::new();
        let mut previous = MapState::default();
        let mut generated_line = 0;

        for index in 0..self.sync_count {
            let entry = self.sync_entry(index)?;
            let mut state = entry.to_state();
            let mut reader = WindowReader::parse(self.stream(), entry.byte_offset)?;
            emit_vlq(&state, &mut previous, &mut generated_line, &mut out);
            while !reader.done() {
                reader.next(&mut state)?;
                emit_vlq(&state, &mut previous, &mut generated_line, &mut out);
            }
        }

        String::from_utf8(out).map_err(|_| ExtractError::SourceMapParseFailed {
            reason: "internal sourcemap re-encoded invalid UTF-8",
        })
    }
}

struct WindowReader<'a> {
    bytes: &'a [u8],
    base: usize,
    gen_col_pos: usize,
    orig_line_exc_pos: usize,
    orig_col_exc_pos: usize,
    gen_line_exc_pos: usize,
    src_idx_mask_pos: usize,
    src_idx_exc_pos: usize,
    count: u8,
    flags: u8,
    gen_line_exc_next_idx: u8,
    delta_idx: u8,
}

impl<'a> WindowReader<'a> {
    fn parse(bytes: &'a [u8], start: usize) -> Result<Self, ExtractError> {
        const COUNT_OFF: usize = 0;
        const FLAGS_OFF: usize = 1;
        const GEN_COL_LEN_OFF: usize = 2;
        const ORIG_LINE_LEN_OFF: usize = 4;
        const ORIG_COL_LEN_OFF: usize = 6;
        const GEN_COL_LANE_OFF: usize = 32;

        if start
            .checked_add(GEN_COL_LANE_OFF)
            .is_none_or(|end| end > bytes.len())
        {
            return Err(ExtractError::SourceMapParseFailed {
                reason: "internal sourcemap window header out of bounds",
            });
        }

        let count = bytes[start + COUNT_OFF].min(SYNC_INTERVAL);
        let flags = bytes[start + FLAGS_OFF];
        let gen_col_len = read_u16(bytes, start + GEN_COL_LEN_OFF)? as usize;
        let orig_line_len = read_u16(bytes, start + ORIG_LINE_LEN_OFF)? as usize;
        let orig_col_len = read_u16(bytes, start + ORIG_COL_LEN_OFF)? as usize;

        let gen_col_pos = start + GEN_COL_LANE_OFF;
        let orig_line_exc_pos =
            gen_col_pos
                .checked_add(gen_col_len)
                .ok_or(ExtractError::SourceMapParseFailed {
                    reason: "internal sourcemap window overflow",
                })?;
        let orig_col_exc_pos = orig_line_exc_pos.checked_add(orig_line_len).ok_or(
            ExtractError::SourceMapParseFailed {
                reason: "internal sourcemap window overflow",
            },
        )?;
        let mut pos = orig_col_exc_pos.checked_add(orig_col_len).ok_or(
            ExtractError::SourceMapParseFailed {
                reason: "internal sourcemap window overflow",
            },
        )?;

        if pos > bytes.len() {
            return Err(ExtractError::SourceMapParseFailed {
                reason: "internal sourcemap window sections out of bounds",
            });
        }

        let mut gen_line_exc_pos = pos;
        let mut gen_line_exc_next_idx = 0xFF;
        if flags & FLAG_HAS_GEN_LINE_EXCEPTIONS != 0 {
            gen_line_exc_pos = pos;
            gen_line_exc_next_idx = *bytes.get(pos).ok_or(ExtractError::SourceMapParseFailed {
                reason: "internal sourcemap gen-line exception missing terminator",
            })?;
            while pos < bytes.len() && bytes[pos] != 0xFF {
                pos += 1;
                read_varint(bytes, &mut pos)?;
            }
            pos = pos
                .checked_add(1)
                .ok_or(ExtractError::SourceMapParseFailed {
                    reason: "internal sourcemap gen-line exception overflow",
                })?;
        }

        let mut src_idx_mask_pos = 0;
        let mut src_idx_exc_pos = pos;
        if flags & FLAG_HAS_SRC_IDX != 0 {
            if pos.checked_add(8).is_none_or(|end| end > bytes.len()) {
                return Err(ExtractError::SourceMapParseFailed {
                    reason: "internal sourcemap source-index mask out of bounds",
                });
            }
            src_idx_mask_pos = pos;
            pos += 8;
            src_idx_exc_pos = pos;
        }

        Ok(Self {
            bytes,
            base: start,
            gen_col_pos,
            orig_line_exc_pos,
            orig_col_exc_pos,
            gen_line_exc_pos,
            src_idx_mask_pos,
            src_idx_exc_pos,
            count,
            flags,
            gen_line_exc_next_idx,
            delta_idx: 0,
        })
    }

    fn done(&self) -> bool {
        self.delta_idx + 1 >= self.count
    }

    fn next(&mut self, state: &mut MapState) -> Result<(), ExtractError> {
        const GEN_LINE_MASK_OFF: usize = 8;
        const ORIG_LINE_EQ_MASK_OFF: usize = 16;
        const ORIG_COL_EQ_MASK_OFF: usize = 24;

        let delta_idx = self.delta_idx;
        self.delta_idx += 1;

        let mut d_gen_line = if test_bit(
            self.bytes,
            self.base + GEN_LINE_MASK_OFF,
            delta_idx as usize,
        )? {
            1
        } else {
            0
        };
        let d_gen_col = read_varint(self.bytes, &mut self.gen_col_pos)?;
        let mut d_orig_line = if test_bit(
            self.bytes,
            self.base + ORIG_LINE_EQ_MASK_OFF,
            delta_idx as usize,
        )? {
            d_gen_line
        } else {
            read_varint(self.bytes, &mut self.orig_line_exc_pos)?
        };
        let d_orig_col = if test_bit(
            self.bytes,
            self.base + ORIG_COL_EQ_MASK_OFF,
            delta_idx as usize,
        )? {
            d_gen_col
        } else {
            read_varint(self.bytes, &mut self.orig_col_exc_pos)?
        };

        if self.gen_line_exc_next_idx == delta_idx {
            let mut p = self.gen_line_exc_pos + 1;
            d_gen_line = read_varint(self.bytes, &mut p)?;
            if test_bit(
                self.bytes,
                self.base + ORIG_LINE_EQ_MASK_OFF,
                delta_idx as usize,
            )? {
                d_orig_line = d_gen_line;
            }
            self.gen_line_exc_pos = p;
            self.gen_line_exc_next_idx =
                *self
                    .bytes
                    .get(p)
                    .ok_or(ExtractError::SourceMapParseFailed {
                        reason: "internal sourcemap gen-line exception cursor out of bounds",
                    })?;
        }

        if self.flags & FLAG_HAS_SRC_IDX != 0
            && !test_bit(self.bytes, self.src_idx_mask_pos, delta_idx as usize)?
        {
            state.source_index += read_varint(self.bytes, &mut self.src_idx_exc_pos)?;
        }

        if d_gen_line != 0 {
            state.generated_line += d_gen_line;
            state.generated_column = d_gen_col;
        } else {
            state.generated_column += d_gen_col;
        }
        state.original_line += d_orig_line;
        state.original_column += d_orig_col;
        Ok(())
    }
}

fn emit_vlq(
    state: &MapState,
    previous: &mut MapState,
    generated_line: &mut i32,
    out: &mut Vec<u8>,
) {
    while *generated_line < state.generated_line {
        out.push(b';');
        previous.generated_column = 0;
        *generated_line += 1;
    }

    let last = out.last().copied().unwrap_or(0);
    if last != 0 && last != b';' {
        out.push(b',');
    }

    push_vlq(out, state.generated_column - previous.generated_column);
    push_vlq(out, state.source_index - previous.source_index);
    push_vlq(out, state.original_line - previous.original_line);
    push_vlq(out, state.original_column - previous.original_column);

    *previous = *state;
}

fn push_vlq(out: &mut Vec<u8>, value: i32) {
    let mut vlq = if value >= 0 {
        (value << 1) as u32
    } else {
        (value.unsigned_abs() << 1) | 1
    };

    loop {
        let mut digit = vlq & 31;
        vlq >>= 5;
        if vlq != 0 {
            digit |= 32;
        }
        out.push(BASE64[digit as usize]);
        if vlq == 0 {
            break;
        }
    }
}

fn read_varint(bytes: &[u8], pos: &mut usize) -> Result<i32, ExtractError> {
    let first = *bytes.get(*pos).ok_or(ExtractError::SourceMapParseFailed {
        reason: "internal sourcemap varint out of bounds",
    })?;
    *pos += 1;
    if first < 0x80 {
        return Ok(zigzag_decode(first as u32));
    }

    let mut result = (first & 0x7f) as u32;
    let mut shift = 7;
    loop {
        if shift > 28 {
            return Err(ExtractError::SourceMapParseFailed {
                reason: "internal sourcemap varint too long",
            });
        }
        let byte = *bytes.get(*pos).ok_or(ExtractError::SourceMapParseFailed {
            reason: "internal sourcemap varint out of bounds",
        })?;
        *pos += 1;
        result |= ((byte & 0x7f) as u32) << shift;
        if byte & 0x80 == 0 {
            return Ok(zigzag_decode(result));
        }
        shift += 7;
    }
}

fn zigzag_decode(value: u32) -> i32 {
    (value >> 1) as i32 ^ (-((value & 1) as i32))
}

fn test_bit(bytes: &[u8], base: usize, idx: usize) -> Result<bool, ExtractError> {
    Ok((*bytes
        .get(base + (idx >> 3))
        .ok_or(ExtractError::SourceMapParseFailed {
            reason: "internal sourcemap bit mask out of bounds",
        })?
        >> (idx & 7))
        & 1
        != 0)
}

fn read_u16(data: &[u8], offset: usize) -> Result<u16, ExtractError> {
    let end = offset + 2;
    let bytes: [u8; 2] = data
        .get(offset..end)
        .ok_or(ExtractError::SourceMapParseFailed {
            reason: "internal sourcemap u16 out of bounds",
        })?
        .try_into()
        .map_err(|_| ExtractError::SourceMapParseFailed {
            reason: "internal sourcemap u16 out of bounds",
        })?;
    Ok(u16::from_le_bytes(bytes))
}

fn read_u32(data: &[u8], offset: usize) -> Result<u32, ExtractError> {
    let end = offset + 4;
    let bytes: [u8; 4] = data
        .get(offset..end)
        .ok_or(ExtractError::SourceMapParseFailed {
            reason: "internal sourcemap u32 out of bounds",
        })?
        .try_into()
        .map_err(|_| ExtractError::SourceMapParseFailed {
            reason: "internal sourcemap u32 out of bounds",
        })?;
    Ok(u32::from_le_bytes(bytes))
}

fn read_i32(data: &[u8], offset: usize) -> Result<i32, ExtractError> {
    Ok(read_u32(data, offset)? as i32)
}

fn read_u64(data: &[u8], offset: usize) -> Result<u64, ExtractError> {
    let end = offset + 8;
    let bytes: [u8; 8] = data
        .get(offset..end)
        .ok_or(ExtractError::SourceMapParseFailed {
            reason: "internal sourcemap u64 out of bounds",
        })?
        .try_into()
        .map_err(|_| ExtractError::SourceMapParseFailed {
            reason: "internal sourcemap u64 out of bounds",
        })?;
    Ok(u64::from_le_bytes(bytes))
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
    /// Standard VLQ-encoded mappings string.
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
    /// InternalSourceMap blob (map_bytes_length bytes):
    ///   -> Bun's compact binary mapping representation
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

        // Extract mappings. Bun now stores mappings as an InternalSourceMap
        // binary blob. Older binaries may contain a plain VLQ string, so keep a
        // fallback for legacy payloads.
        let mappings_bytes = &blob[mappings_start..mappings_end];
        let mappings = match InternalSourceMap::parse(mappings_bytes).and_then(|map| map.to_vlq()) {
            Ok(mappings) => mappings,
            Err(_) => std::str::from_utf8(mappings_bytes)
                .map_err(|_| ExtractError::SourceMapParseFailed {
                    reason: "mappings is neither a Bun InternalSourceMap nor valid UTF-8 VLQ",
                })?
                .to_string(),
        };

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

/// Sanitize a sourcemap path: strip Bun virtual roots, strip leading `../` and `/`
/// for ordinary paths, and keep the result inside the output directory.
fn sanitize_source_path(path: &str) -> Option<String> {
    let normalized = path.replace('\\', "/");
    let (mut result, is_bun_virtual) =
        if let Some(rel) = normalized.strip_prefix(MODULE_NAME_PREFIX) {
            (rel, true)
        } else if let Some(rel) = normalized.strip_prefix(BUNFS_PREFIX_WIN_PUBLIC) {
            (rel, true)
        } else {
            (normalized.as_str(), false)
        };

    if is_bun_virtual {
        result = result.strip_prefix("root/").unwrap_or(result);
    } else {
        while result.starts_with('/') {
            result = &result[1..];
        }

        while result.starts_with("../") {
            result = &result[3..];
        }
    }

    if result == ".." || result.is_empty() {
        return None;
    }

    let mut parts = Vec::new();
    for component in result.split('/') {
        match component {
            "" | "." => {}
            ".." if is_bun_virtual => {
                parts.pop();
            }
            ".." => return None,
            _ if component.contains(':') => return None,
            _ => parts.push(component),
        }
    }

    if parts.is_empty() {
        return None;
    }

    Some(parts.join("/"))
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

    #[test]
    fn sanitize_source_path_preserves_bun_virtual_dependencies() {
        assert_eq!(
            sanitize_source_path("/$bunfs/root/../../node_modules/pkg/parser.worker.js"),
            Some("node_modules/pkg/parser.worker.js".to_string())
        );
    }

    #[test]
    fn sanitize_source_path_accepts_windows_virtual_prefixes() {
        assert_eq!(
            sanitize_source_path("B:\\~BUN\\root\\src\\app.ts"),
            Some("src/app.ts".to_string())
        );
        assert_eq!(
            sanitize_source_path("B:/~BUN/root/src/app.ts"),
            Some("src/app.ts".to_string())
        );
    }

    #[test]
    fn sanitize_source_path_keeps_legacy_leading_parent_behavior() {
        assert_eq!(
            sanitize_source_path("../../src/app.ts"),
            Some("src/app.ts".to_string())
        );
        assert_eq!(sanitize_source_path("src/../app.ts"), None);
        assert_eq!(
            sanitize_source_path("/tmp/out.js"),
            Some("tmp/out.js".to_string())
        );
    }
}
