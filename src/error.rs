use thiserror::Error;

#[derive(Debug, Error)]
pub enum ExtractError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("file too small ({size} bytes) to contain Bun payload")]
    FileTooSmall { size: usize },

    #[error("Bun trailer not found — this may not be a Bun-compiled binary")]
    TrailerNotFound,

    #[error("invalid offsets struct: byte_count={byte_count} exceeds available data")]
    InvalidOffsets { byte_count: u64 },

    #[error("could not auto-detect module struct size (modules_length={modules_length})")]
    ModuleSizeDetectionFailed { modules_length: u32 },

    #[error("string pointer out of bounds: offset={offset}, length={length}, payload_size={payload_size}")]
    StringOutOfBounds {
        offset: u32,
        length: u32,
        payload_size: usize,
    },

    #[error("invalid UTF-8 in module name at index {index}")]
    InvalidModuleName { index: usize },

    #[error("ELF .bun section not found")]
    BunSectionNotFound,

    #[error("invalid ELF header")]
    InvalidElf,
}
