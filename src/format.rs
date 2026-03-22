/// The magic trailer that Bun appends to compiled binaries.
pub const TRAILER: &[u8; 16] = b"\n---- Bun! ----\n";

/// Size of the Offsets struct in bytes.
pub const OFFSETS_SIZE: usize = 32;

/// Virtual path prefix on Unix systems (stripped when extracting).
pub const BUNFS_PREFIX_UNIX: &str = "/$bunfs/root/";

/// Virtual path prefix on Windows systems.
pub const BUNFS_PREFIX_WIN: &str = "B:\\~BUN\\";

/// Candidate module struct sizes to try during auto-detection.
/// Ordered by likelihood (72 is most common in Bun 1.x).
pub const CANDIDATE_STRUCT_SIZES: &[usize] = &[
    72, 68, 64, 60, 56, 52, 80, 84, 88, 76, 48, 96, 104, 112, 120, 128,
];

/// Module name prefix used to validate struct size detection.
pub const MODULE_NAME_PREFIX: &str = "/$bunfs/";

/// The 32-byte offsets structure found just before the trailer.
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
    /// Feature flags bitfield.
    pub flags: u32,
}

impl Offsets {
    /// Parse Offsets from a 32-byte slice (little-endian).
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
}

/// A pointer to a string within the payload (offset + length).
#[derive(Debug, Clone, Copy)]
pub struct StringPointer {
    pub offset: u32,
    pub length: u32,
}

impl StringPointer {
    /// Parse a StringPointer from an 8-byte slice (little-endian).
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
    /// Appended after the ELF (Bun ≤1.3.x).
    Appended,
    /// Stored in an ELF `.bun` section (Bun 1.4+).
    Section { section_offset: usize },
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
    pub fn from_u8(val: u8) -> Self {
        match val {
            0 => Encoding::Binary,
            1 => Encoding::Latin1,
            2 => Encoding::Utf8,
            other => Encoding::Unknown(other),
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Encoding::Binary => "binary",
            Encoding::Latin1 => "latin1",
            Encoding::Utf8 => "utf8",
            Encoding::Unknown(_) => "unknown",
        }
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
    pub fn from_u8(val: u8) -> Self {
        match val {
            0 => ModuleFormat::None,
            1 => ModuleFormat::Esm,
            2 => ModuleFormat::Cjs,
            other => ModuleFormat::Unknown(other),
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            ModuleFormat::None => "none",
            ModuleFormat::Esm => "esm",
            ModuleFormat::Cjs => "cjs",
            ModuleFormat::Unknown(_) => "unknown",
        }
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
    pub module_format: ModuleFormat,
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

    /// Guess the file type from the extension.
    pub fn file_type(&self) -> &'static str {
        let name = self.name.to_lowercase();
        if name.ends_with(".js") || name.ends_with(".mjs") || name.ends_with(".cjs") {
            "JavaScript"
        } else if name.ends_with(".ts") || name.ends_with(".mts") || name.ends_with(".cts") {
            "TypeScript"
        } else if name.ends_with(".json") {
            "JSON"
        } else if name.ends_with(".wasm") {
            "WebAssembly"
        } else if name.ends_with(".node") {
            "Native addon"
        } else if name.ends_with(".css") {
            "CSS"
        } else if name.ends_with(".html") {
            "HTML"
        } else if name.ends_with(".txt") {
            "Text"
        } else if name.ends_with(".toml") {
            "TOML"
        } else {
            "Unknown"
        }
    }
}
