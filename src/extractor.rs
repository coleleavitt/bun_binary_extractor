use std::fs;
use std::path::Path;

use crate::error::ExtractError;
use crate::format::{
    EmbedMethod, Encoding, Module, ModuleFormat, Offsets, StringPointer, CANDIDATE_STRUCT_SIZES,
    MODULE_NAME_PREFIX, OFFSETS_SIZE, TRAILER,
};

pub struct BunBinary {
    pub data: Vec<u8>,
    pub embed_method: EmbedMethod,
    pub offsets: Offsets,
    pub payload_base: usize,
    pub module_struct_size: usize,
    pub modules: Vec<Module>,
}

impl BunBinary {
    pub fn from_file(path: &Path) -> Result<Self, ExtractError> {
        let data = fs::read(path)?;
        Self::parse(data)
    }

    pub fn parse(data: Vec<u8>) -> Result<Self, ExtractError> {
        let file_size = data.len();
        // Minimum: 8 (total_byte_count) + 16 (trailer) + 32 (offsets) + some payload
        if file_size < 60 {
            return Err(ExtractError::FileTooSmall { size: file_size });
        }

        let embed_method = detect_embed_method(&data)?;

        let (offsets, payload_base) = match embed_method {
            EmbedMethod::Appended => {
                // Layout: [ELF][payload][Offsets(32)][trailer(16)][u64 total_byte_count(8)]
                let offsets_end = file_size - 8 - 16; // skip total_byte_count + trailer
                let offsets_start = offsets_end - OFFSETS_SIZE;
                let offsets = Offsets::from_bytes(&data[offsets_start..offsets_end])
                    .ok_or(ExtractError::TrailerNotFound)?;
                let pbase = offsets_start - offsets.byte_count as usize;
                (offsets, pbase)
            }
            EmbedMethod::Section { section_offset } => {
                // Section data: [u64 LE payload_len][payload_len bytes]
                // The payload ends with: [Offsets(32)][trailer(16)]
                let payload_len = u64::from_le_bytes(
                    data[section_offset..section_offset + 8]
                        .try_into()
                        .map_err(|_| ExtractError::InvalidElf)?,
                ) as usize;
                let section_payload_start = section_offset + 8;
                let section_payload_end = section_payload_start + payload_len;

                // Offsets are at end of section payload, before trailer
                let offsets_end = section_payload_end - 16; // skip trailer
                let offsets_start = offsets_end - OFFSETS_SIZE;
                let offsets = Offsets::from_bytes(&data[offsets_start..offsets_end])
                    .ok_or(ExtractError::TrailerNotFound)?;

                (offsets, section_payload_start)
            }
        };

        let module_struct_size = detect_module_struct_size(
            &data,
            payload_base,
            offsets.modules_offset,
            offsets.modules_length,
        )?;

        let modules = parse_modules(&data, payload_base, &offsets, module_struct_size)?;

        Ok(BunBinary {
            data,
            embed_method,
            offsets,
            payload_base,
            module_struct_size,
            modules,
        })
    }

    pub fn argv(&self) -> Option<&str> {
        let start = self.payload_base + self.offsets.argv_offset as usize;
        let end = start + self.offsets.argv_length as usize;
        if end <= self.data.len() {
            std::str::from_utf8(&self.data[start..end]).ok()
        } else {
            None
        }
    }
}

fn detect_embed_method(data: &[u8]) -> Result<EmbedMethod, ExtractError> {
    let len = data.len();

    // Check appended approach: last 8 bytes = u64 total_byte_count, then trailer before that
    if len >= 8 + 16 {
        let trailer_start = len - 8 - 16;
        let trailer_end = len - 8;
        if &data[trailer_start..trailer_end] == TRAILER.as_slice() {
            return Ok(EmbedMethod::Appended);
        }
    }

    // Check if trailer is at very end
    if len >= 16 && &data[len - 16..] == TRAILER.as_slice() {
        // This would be unusual but handle it — treat as section approach
        // Fall through to ELF parsing
    }

    // Parse ELF to find .bun section
    find_bun_elf_section(data)
}

fn find_bun_elf_section(data: &[u8]) -> Result<EmbedMethod, ExtractError> {
    // Verify ELF magic
    if data.len() < 64 || &data[0..4] != b"\x7fELF" {
        return Err(ExtractError::TrailerNotFound);
    }

    let is_64bit = data[4] == 2;
    if !is_64bit {
        return Err(ExtractError::InvalidElf);
    }

    // ELF64 header fields (little-endian assumed)
    let e_shoff = u64::from_le_bytes(
        data[40..48]
            .try_into()
            .map_err(|_| ExtractError::InvalidElf)?,
    ) as usize;
    let e_shentsize = u16::from_le_bytes(
        data[58..60]
            .try_into()
            .map_err(|_| ExtractError::InvalidElf)?,
    ) as usize;
    let e_shnum = u16::from_le_bytes(
        data[60..62]
            .try_into()
            .map_err(|_| ExtractError::InvalidElf)?,
    ) as usize;
    let e_shstrndx = u16::from_le_bytes(
        data[62..64]
            .try_into()
            .map_err(|_| ExtractError::InvalidElf)?,
    ) as usize;

    if e_shoff == 0 || e_shnum == 0 {
        return Err(ExtractError::BunSectionNotFound);
    }

    // Read section header string table
    let shstrtab_hdr_off = e_shoff + e_shstrndx * e_shentsize;
    if shstrtab_hdr_off + e_shentsize > data.len() {
        return Err(ExtractError::InvalidElf);
    }
    let shstrtab_offset = u64::from_le_bytes(
        data[shstrtab_hdr_off + 24..shstrtab_hdr_off + 32]
            .try_into()
            .map_err(|_| ExtractError::InvalidElf)?,
    ) as usize;
    let shstrtab_size = u64::from_le_bytes(
        data[shstrtab_hdr_off + 32..shstrtab_hdr_off + 40]
            .try_into()
            .map_err(|_| ExtractError::InvalidElf)?,
    ) as usize;

    if shstrtab_offset + shstrtab_size > data.len() {
        return Err(ExtractError::InvalidElf);
    }
    let shstrtab = &data[shstrtab_offset..shstrtab_offset + shstrtab_size];

    // Iterate sections to find ".bun"
    for i in 0..e_shnum {
        let hdr_off = e_shoff + i * e_shentsize;
        if hdr_off + e_shentsize > data.len() {
            break;
        }

        let sh_name = u32::from_le_bytes(
            data[hdr_off..hdr_off + 4]
                .try_into()
                .map_err(|_| ExtractError::InvalidElf)?,
        ) as usize;

        if sh_name < shstrtab.len() {
            let name_end = shstrtab[sh_name..]
                .iter()
                .position(|&b| b == 0)
                .map(|p| sh_name + p)
                .unwrap_or(shstrtab.len());
            let section_name = std::str::from_utf8(&shstrtab[sh_name..name_end]).unwrap_or("");

            if section_name == ".bun" {
                let sh_offset = u64::from_le_bytes(
                    data[hdr_off + 24..hdr_off + 32]
                        .try_into()
                        .map_err(|_| ExtractError::InvalidElf)?,
                ) as usize;
                return Ok(EmbedMethod::Section {
                    section_offset: sh_offset,
                });
            }
        }
    }

    Err(ExtractError::BunSectionNotFound)
}

fn detect_module_struct_size(
    data: &[u8],
    payload_base: usize,
    modules_offset: u32,
    modules_length: u32,
) -> Result<usize, ExtractError> {
    let mod_array_start = payload_base + modules_offset as usize;
    let mod_len = modules_length as usize;

    for &candidate in CANDIDATE_STRUCT_SIZES {
        if mod_len == 0 || !mod_len.is_multiple_of(candidate) {
            continue;
        }
        let n_modules = mod_len / candidate;
        if n_modules == 0 || n_modules > 10000 {
            continue;
        }

        let mut all_valid = true;
        for i in 0..n_modules {
            let entry_start = mod_array_start + i * candidate;
            if entry_start + 8 > data.len() {
                all_valid = false;
                break;
            }
            let name_ptr = match StringPointer::from_bytes(&data[entry_start..entry_start + 8]) {
                Some(sp) => sp,
                None => {
                    all_valid = false;
                    break;
                }
            };

            let name_start = payload_base + name_ptr.offset as usize;
            let name_end = name_start + name_ptr.length as usize;
            if name_end > data.len() || name_ptr.length == 0 {
                all_valid = false;
                break;
            }

            let name = match std::str::from_utf8(&data[name_start..name_end]) {
                Ok(s) => s,
                Err(_) => {
                    all_valid = false;
                    break;
                }
            };

            if !name.starts_with(MODULE_NAME_PREFIX) {
                all_valid = false;
                break;
            }
        }

        if all_valid {
            return Ok(candidate);
        }
    }

    Err(ExtractError::ModuleSizeDetectionFailed { modules_length })
}

fn read_string_pointer<'a>(
    data: &'a [u8],
    payload_base: usize,
    sp: &StringPointer,
    payload_size: usize,
) -> Result<&'a [u8], ExtractError> {
    let start = payload_base + sp.offset as usize;
    let end = start + sp.length as usize;
    if end > data.len() || (sp.offset as usize + sp.length as usize) > payload_size {
        return Err(ExtractError::StringOutOfBounds {
            offset: sp.offset,
            length: sp.length,
            payload_size,
        });
    }
    Ok(&data[start..end])
}

fn parse_modules(
    data: &[u8],
    payload_base: usize,
    offsets: &Offsets,
    struct_size: usize,
) -> Result<Vec<Module>, ExtractError> {
    let mod_array_start = payload_base + offsets.modules_offset as usize;
    let n_modules = offsets.modules_length as usize / struct_size;
    let payload_size = offsets.byte_count as usize;
    let mut modules = Vec::with_capacity(n_modules);

    for i in 0..n_modules {
        let base = mod_array_start + i * struct_size;

        let name_sp = StringPointer::from_bytes(&data[base..base + 8])
            .ok_or(ExtractError::TrailerNotFound)?;
        let contents_sp = StringPointer::from_bytes(&data[base + 8..base + 16])
            .ok_or(ExtractError::TrailerNotFound)?;

        let name_bytes = read_string_pointer(data, payload_base, &name_sp, payload_size)?;
        let name = std::str::from_utf8(name_bytes)
            .map_err(|_| ExtractError::InvalidModuleName { index: i })?
            .to_string();

        let contents = if contents_sp.length > 0 {
            read_string_pointer(data, payload_base, &contents_sp, payload_size)?.to_vec()
        } else {
            Vec::new()
        };

        // Sourcemap is the third StringPointer (offset 16)
        let sourcemap = if struct_size >= 24 {
            let sm_sp = StringPointer::from_bytes(&data[base + 16..base + 24])
                .ok_or(ExtractError::TrailerNotFound)?;
            if sm_sp.length > 0 {
                Some(read_string_pointer(data, payload_base, &sm_sp, payload_size)?.to_vec())
            } else {
                None
            }
        } else {
            None
        };

        // Try to read encoding and module_format from the enum fields at the end of the struct.
        // These are typically the last few bytes. The exact layout varies, but in the 72-byte
        // struct they're at offsets that follow all StringPointers.
        //
        // Known layout for 72-byte structs (Bun 1.x):
        // 0..8: name, 8..16: contents, 16..24: sourcemap,
        // 24..32: bytecode, 32..40: module_info, 40..48: bytecode_origin_path
        // Then 4 u32 fields (16 bytes) = 64 bytes, then 4 enum u8s + padding = 8 bytes → 72
        //
        // The 4 enum bytes are at struct_size - 8 .. struct_size - 4
        let (encoding, module_format) = if struct_size >= 48 {
            let enum_base = base + struct_size - 8;
            if enum_base + 4 <= data.len() {
                let enc = Encoding::from_u8(data[enum_base]);
                let _loader = data[enum_base + 1];
                let mfmt = ModuleFormat::from_u8(data[enum_base + 2]);
                (enc, mfmt)
            } else {
                (Encoding::Binary, ModuleFormat::None)
            }
        } else {
            (Encoding::Binary, ModuleFormat::None)
        };

        modules.push(Module {
            index: i,
            name,
            contents,
            sourcemap,
            encoding,
            module_format,
            is_entry_point: i == offsets.entry_point_id as usize,
        });
    }

    Ok(modules)
}
