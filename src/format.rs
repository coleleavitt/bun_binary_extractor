use std::fmt;

/// The magic trailer that Bun appends to compiled binaries.
pub const TRAILER: &[u8; 16] = b"\n---- Bun! ----\n";

/// Virtual path prefix on Unix systems (stripped when extracting).
pub const BUNFS_PREFIX_UNIX: &str = "/$bunfs/root/";

/// Virtual path prefix on Windows systems.
pub const BUNFS_PREFIX_WIN: &str = "B:\\~BUN\\";

/// Module name prefix used to validate struct size detection.
pub const MODULE_NAME_PREFIX: &str = "/$bunfs/";

/// ELF magic bytes.
pub const ELF_MAGIC: &[u8; 4] = b"\x7fELF";

/// PE magic bytes (MZ header).
pub const PE_MAGIC: &[u8; 2] = b"MZ";

/// Mach-O 64-bit magic (little-endian).
pub const MACHO_MAGIC_64: u32 = 0xFEED_FACF;

/// Mach-O FAT magic.
pub const MACHO_FAT_MAGIC: u32 = 0xCAFE_BABE;

/// Bun section name in PE/ELF binaries.
pub const BUN_SECTION_NAME: &str = ".bun";

/// Mach-O segment name for Bun data.
pub const MACHO_SEGMENT_NAME: &[u8; 16] = b"__BUN\0\0\0\0\0\0\0\0\0\0\0";

/// Mach-O section name for Bun data.
pub const MACHO_SECTION_NAME: &[u8; 16] = b"__bun\0\0\0\0\0\0\0\0\0\0\0";

/// Candidate module struct sizes to try during auto-detection.
/// Includes sizes from all known Bun versions and Zig compiler outputs.
/// - 36: Bun <=1.1 (4 SPs + 4 enum bytes, packed)
/// - 52: Bun >=1.2 (6 SPs + 4 enum bytes, packed)
/// - 72: Bun 1.3.x on x86_64-linux (Zig non-extern struct with padding)
/// - Others: Various Zig compiler versions/targets may produce different padding.
pub const CANDIDATE_STRUCT_SIZES: &[usize] = &[
    72, 52, 36, 68, 64, 60, 56, 80, 84, 88, 76, 48, 40, 44, 96, 104, 112, 120, 128,
];

/// Possible Offsets struct sizes across Bun versions.
/// - 28: Bun <=1.3.x (no flags field, but C ABI pads to 32)
/// - 32: Bun 1.4+ (has flags field)
///   Both parse identically because the padding/flags occupy the same 4 bytes.
pub const OFFSETS_SIZE: usize = 32;

/// The Offsets struct found just before the trailer.
///
/// ## Bun version differences
/// - **Bun <=1.3.x**: 28 bytes (no `flags`), padded to 32 by C ABI alignment.
/// - **Bun 1.4+**: 32 bytes (explicit `flags: u32` field).
///
/// We always read 32 bytes; the `flags` field is zero on older versions.
#[derive(Debug, Clone, Copy)]
pub struct Offsets {
    /// Total payload size (NOT including Offsets and trailer).
    pub byte_count: u64,
    /// Offset within payload to the module array.
    pub modules_offset: u32,
    /// Total bytes of the module array.
    pub modules_length: u32,
    /// Index of the entry point module.
    pub entry_point_id: u32,
    /// Offset within payload to the argv string.
    pub argv_offset: u32,
    /// Length of the argv string.
    pub argv_length: u32,
    /// Feature flags bitfield (zero on Bun <=1.3.x).
    pub flags: u32,
}

impl Offsets {
    /// Parse Offsets from a 32-byte little-endian slice.
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() < OFFSETS_SIZE {
            return None;
        }
        Some(Offsets {
            byte_count: u64::from_le_bytes(data[0..8].try_into().ok()?),
            modules_offset: u32::from_le_bytes(data[8..12].try_into().ok()?),
            modules_length: u32::from_le_bytes(data[12..16].try_into().ok()?),
            entry_point_id: u32::from_le_bytes(data[16..20].try_into().ok()?),
            argv_offset: u32::from_le_bytes(data[20..24].try_into().ok()?),
            argv_length: u32::from_le_bytes(data[24..28].try_into().ok()?),
            flags: u32::from_le_bytes(data[28..32].try_into().ok()?),
        })
    }

    /// Decode feature flags.
    pub fn decoded_flags(&self) -> OffsetsFlags {
        OffsetsFlags {
            disable_default_env_files: self.flags & 1 != 0,
            disable_autoload_bunfig: self.flags & 2 != 0,
            disable_autoload_tsconfig: self.flags & 4 != 0,
            disable_autoload_package_json: self.flags & 8 != 0,
        }
    }
}

/// Decoded Offsets flags (Bun 1.4+ only; all false on older versions).
#[derive(Debug, Clone, Copy)]
pub struct OffsetsFlags {
    pub disable_default_env_files: bool,
    pub disable_autoload_bunfig: bool,
    pub disable_autoload_tsconfig: bool,
    pub disable_autoload_package_json: bool,
}

/// A pointer to a string within the payload (offset + length).
#[derive(Debug, Clone, Copy)]
pub struct StringPointer {
    pub offset: u32,
    pub length: u32,
}

impl StringPointer {
    /// Parse a StringPointer from an 8-byte little-endian slice.
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() < 8 {
            return None;
        }
        Some(StringPointer {
            offset: u32::from_le_bytes(data[0..4].try_into().ok()?),
            length: u32::from_le_bytes(data[4..8].try_into().ok()?),
        })
    }
}

/// How the payload was embedded in the binary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EmbedMethod {
    /// Appended after the original binary with a trailing u64 size.
    Appended,
    /// ELF `.bun` section (Bun 1.4+).
    ElfSection { section_offset: usize },
    /// PE `.bun` section (Windows).
    PeSection { section_offset: usize },
    /// Mach-O `__BUN,__bun` section (macOS).
    MachoSection { section_offset: usize },
}

impl fmt::Display for EmbedMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EmbedMethod::Appended => write!(f, "Appended (legacy)"),
            EmbedMethod::ElfSection { section_offset } => {
                write!(f, "ELF .bun section (offset {section_offset:#x})")
            }
            EmbedMethod::PeSection { section_offset } => {
                write!(f, "PE .bun section (offset {section_offset:#x})")
            }
            EmbedMethod::MachoSection { section_offset } => {
                write!(f, "Mach-O __BUN/__bun section (offset {section_offset:#x})")
            }
        }
    }
}

/// Heuristic Bun version range detected from the binary format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BunVersion {
    /// Bun <=1.1: 4 StringPointers, 36-byte module struct, no flags.
    V1_0_1_1,
    /// Bun 1.2-1.3: 6 StringPointers, 52-byte module struct (or Zig-padded), no flags.
    V1_2_1_3,
    /// Bun 1.4+: 6 StringPointers, 52-byte module struct, has flags, ELF section.
    V1_4Plus,
    /// Unknown version; auto-detection still worked.
    Unknown,
}

impl BunVersion {
    /// Heuristically detect the Bun version from format characteristics.
    pub fn detect(embed_method: &EmbedMethod, module_struct_size: usize, flags: u32) -> Self {
        match embed_method {
            EmbedMethod::ElfSection { .. }
            | EmbedMethod::PeSection { .. }
            | EmbedMethod::MachoSection { .. } => BunVersion::V1_4Plus,
            EmbedMethod::Appended => {
                if flags != 0 {
                    BunVersion::V1_4Plus
                } else if module_struct_size <= 36 {
                    BunVersion::V1_0_1_1
                } else {
                    BunVersion::V1_2_1_3
                }
            }
        }
    }
}

impl fmt::Display for BunVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BunVersion::V1_0_1_1 => write!(f, "Bun <=1.1"),
            BunVersion::V1_2_1_3 => write!(f, "Bun 1.2-1.3"),
            BunVersion::V1_4Plus => write!(f, "Bun 1.4+"),
            BunVersion::Unknown => write!(f, "Unknown"),
        }
    }
}

/// Module encoding type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Encoding {
    Binary,
    Latin1,
    Utf8,
    Unknown(u8),
}

impl Encoding {
    pub fn as_str(&self) -> &'static str {
        match self {
            Encoding::Binary => "binary",
            Encoding::Latin1 => "latin1",
            Encoding::Utf8 => "utf8",
            Encoding::Unknown(_) => "unknown",
        }
    }
}

impl From<u8> for Encoding {
    fn from(val: u8) -> Self {
        match val {
            0 => Encoding::Binary,
            1 => Encoding::Latin1,
            2 => Encoding::Utf8,
            other => Encoding::Unknown(other),
        }
    }
}

impl fmt::Display for Encoding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Bun file loader type (matches `bun.options.Loader` enum(u8) from Bun source).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Loader {
    Jsx,
    Js,
    Ts,
    Tsx,
    Css,
    File,
    Json,
    Jsonc,
    Toml,
    Wasm,
    Napi,
    Base64,
    DataUrl,
    Text,
    BunSh,
    Sqlite,
    SqliteEmbedded,
    Html,
    Yaml,
    Unknown(u8),
}

impl Loader {
    pub fn as_str(&self) -> &'static str {
        match self {
            Loader::Jsx => "jsx",
            Loader::Js => "js",
            Loader::Ts => "ts",
            Loader::Tsx => "tsx",
            Loader::Css => "css",
            Loader::File => "file",
            Loader::Json => "json",
            Loader::Jsonc => "jsonc",
            Loader::Toml => "toml",
            Loader::Wasm => "wasm",
            Loader::Napi => "napi",
            Loader::Base64 => "base64",
            Loader::DataUrl => "dataurl",
            Loader::Text => "text",
            Loader::BunSh => "bunsh",
            Loader::Sqlite => "sqlite",
            Loader::SqliteEmbedded => "sqlite_embedded",
            Loader::Html => "html",
            Loader::Yaml => "yaml",
            Loader::Unknown(_) => "unknown",
        }
    }

    pub fn is_javascript(&self) -> bool {
        matches!(self, Loader::Js | Loader::Jsx | Loader::Ts | Loader::Tsx)
    }
}

impl From<u8> for Loader {
    fn from(val: u8) -> Self {
        match val {
            0 => Loader::Jsx,
            1 => Loader::Js,
            2 => Loader::Ts,
            3 => Loader::Tsx,
            4 => Loader::Css,
            5 => Loader::File,
            6 => Loader::Json,
            7 => Loader::Jsonc,
            8 => Loader::Toml,
            9 => Loader::Wasm,
            10 => Loader::Napi,
            11 => Loader::Base64,
            12 => Loader::DataUrl,
            13 => Loader::Text,
            14 => Loader::BunSh,
            15 => Loader::Sqlite,
            16 => Loader::SqliteEmbedded,
            17 => Loader::Html,
            18 => Loader::Yaml,
            other => Loader::Unknown(other),
        }
    }
}

impl fmt::Display for Loader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Module format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModuleFormat {
    None,
    Esm,
    Cjs,
    Unknown(u8),
}

impl ModuleFormat {
    pub fn as_str(&self) -> &'static str {
        match self {
            ModuleFormat::None => "none",
            ModuleFormat::Esm => "esm",
            ModuleFormat::Cjs => "cjs",
            ModuleFormat::Unknown(_) => "unknown",
        }
    }
}

impl From<u8> for ModuleFormat {
    fn from(val: u8) -> Self {
        match val {
            0 => ModuleFormat::None,
            1 => ModuleFormat::Esm,
            2 => ModuleFormat::Cjs,
            other => ModuleFormat::Unknown(other),
        }
    }
}

impl fmt::Display for ModuleFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Module side (server vs client).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileSide {
    Server,
    Client,
    Unknown(u8),
}

impl FileSide {
    pub fn as_str(&self) -> &'static str {
        match self {
            FileSide::Server => "server",
            FileSide::Client => "client",
            FileSide::Unknown(_) => "unknown",
        }
    }
}

impl From<u8> for FileSide {
    fn from(val: u8) -> Self {
        match val {
            0 => FileSide::Server,
            1 => FileSide::Client,
            other => FileSide::Unknown(other),
        }
    }
}

impl fmt::Display for FileSide {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Extracted module information.
#[derive(Debug)]
pub struct Module {
    pub index: usize,
    pub name: String,
    pub contents: Vec<u8>,
    pub sourcemap: Option<Vec<u8>>,
    pub encoding: Encoding,
    pub loader: Loader,
    pub module_format: ModuleFormat,
    pub side: FileSide,
    pub is_entry_point: bool,
}

impl Module {
    /// Strip the virtual path prefix to get a relative filesystem path.
    pub fn relative_path(&self) -> &str {
        self.name
            .strip_prefix(BUNFS_PREFIX_UNIX)
            .or_else(|| self.name.strip_prefix(BUNFS_PREFIX_WIN))
            .or_else(|| self.name.strip_prefix("/$bunfs/"))
            .unwrap_or(&self.name)
    }

    /// Guess the file type from the extension and loader.
    pub fn file_type(&self) -> &'static str {
        if self.loader.is_javascript() {
            return match self.loader {
                Loader::Ts | Loader::Tsx => "TypeScript",
                _ => "JavaScript",
            };
        }

        let name = self.name.as_bytes();
        if name.ends_with(b".js") || name.ends_with(b".mjs") || name.ends_with(b".cjs") {
            "JavaScript"
        } else if name.ends_with(b".ts") || name.ends_with(b".mts") || name.ends_with(b".cts") {
            "TypeScript"
        } else if name.ends_with(b".json") {
            "JSON"
        } else if name.ends_with(b".wasm") {
            "WebAssembly"
        } else if name.ends_with(b".node") {
            "Native addon"
        } else if name.ends_with(b".css") {
            "CSS"
        } else if name.ends_with(b".html") {
            "HTML"
        } else if name.ends_with(b".txt") {
            "Text"
        } else if name.ends_with(b".toml") {
            "TOML"
        } else if name.ends_with(b".scm") {
            "Scheme/Query"
        } else if name.ends_with(b".sql") || name.ends_with(b".sqlite") {
            "SQLite"
        } else {
            "Unknown"
        }
    }
}
