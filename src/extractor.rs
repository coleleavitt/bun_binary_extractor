use std::fs;
use std::path::Path;

use crate::error::ExtractError;
use crate::format::{
    BUN_SECTION_NAME,
    BunVersion,
    CANDIDATE_STRUCT_SIZES,
    ELF_MAGIC,
    EmbedMethod,
    Encoding,
    FileSide,
    Loader,
    MACHO_MAGIC_64,
    MACHO_SECTION_NAME,
    MACHO_SEGMENT_NAME,
    MODULE_NAME_PREFIX,
    Module,
    ModuleFormat,
    OFFSETS_SIZE,
    Offsets,
    PE_MAGIC,
    StringPointer,
    TRAILER,
};

pub struct BunBinary {
    pub embed_method: EmbedMethod,
    pub offsets: Offsets,
    pub payload_base: usize,
    pub module_struct_size: usize,
    pub modules: Vec<Module>,
    pub version: BunVersion,
    pub argv: Option<String>,
}

impl BunBinary {
    pub fn from_file(path: &Path) -> Result<Self, ExtractError> {
        let data = fs::read(path)?;
        Self::parse(&data)
    }

    pub fn parse(data: &[u8]) -> Result<Self, ExtractError> {
        let file_size = data.len();
        if file_size < 60 {
            return Err(ExtractError::FileTooSmall { size: file_size });
        }

        let embed_method = detect_embed_method(data)?;

        let (offsets, payload_base) = match embed_method {
            EmbedMethod::Appended => {
                // file_size >= 60 guaranteed above, so these won't underflow.
                let offsets_end = file_size - 8 - 16;
                let offsets_start = offsets_end - OFFSETS_SIZE;
                let offsets = Offsets::from_bytes(&data[offsets_start..offsets_end])
                    .ok_or(ExtractError::TrailerNotFound)?;

                // Compare in u64 space to avoid truncation on 32-bit targets.
                if offsets.byte_count > file_size as u64 || offsets.byte_count < 32 {
                    return Err(ExtractError::InvalidOffsets {
                        byte_count: offsets.byte_count,
                    });
                }

                let total_byte_count = u64::from_le_bytes(
                    data[file_size - 8..file_size]
                        .try_into()
                        .map_err(|_| ExtractError::TrailerNotFound)?,
                );

                if offsets.byte_count >= total_byte_count {
                    return Err(ExtractError::InvalidOffsets {
                        byte_count: offsets.byte_count,
                    });
                }

                // Safe to cast: we verified byte_count <= file_size (which is usize).
                let pbase = offsets_start
                    .checked_sub(offsets.byte_count as usize)
                    .ok_or(ExtractError::InvalidOffsets {
                        byte_count: offsets.byte_count,
                    })?;
                (offsets, pbase)
            }
            EmbedMethod::ElfSection { section_offset }
            | EmbedMethod::PeSection { section_offset }
            | EmbedMethod::MachoSection { section_offset } => {
                let section_len_end = section_offset
                    .checked_add(8)
                    .ok_or(ExtractError::OffsetOverflow)?;
                if section_len_end > data.len() {
                    return Err(ExtractError::InvalidOffsets { byte_count: 0 });
                }

                let payload_len_u64 = u64::from_le_bytes(
                    data[section_offset..section_len_end]
                        .try_into()
                        .map_err(|_| ExtractError::OffsetOverflow)?,
                );

                let payload_len: usize =
                    usize::try_from(payload_len_u64).map_err(|_| ExtractError::OffsetOverflow)?;

                let section_payload_start = section_offset
                    .checked_add(8)
                    .ok_or(ExtractError::OffsetOverflow)?;
                let section_payload_end = section_payload_start
                    .checked_add(payload_len)
                    .ok_or(ExtractError::OffsetOverflow)?;

                if section_payload_end > data.len() {
                    return Err(ExtractError::InvalidOffsets {
                        byte_count: payload_len_u64,
                    });
                }

                let min_payload = 16usize
                    .checked_add(OFFSETS_SIZE)
                    .ok_or(ExtractError::OffsetOverflow)?;
                if payload_len < min_payload {
                    return Err(ExtractError::InvalidOffsets { byte_count: 0 });
                }
                let offsets_end = section_payload_end - 16;
                let offsets_start = offsets_end - OFFSETS_SIZE;
                let offsets = Offsets::from_bytes(&data[offsets_start..offsets_end])
                    .ok_or(ExtractError::TrailerNotFound)?;

                (offsets, section_payload_start)
            }
        };

        let module_struct_size = detect_module_struct_size(
            data,
            payload_base,
            offsets.modules_offset,
            offsets.modules_length,
        )?;

        let n_modules = offsets.modules_length as usize / module_struct_size;
        if offsets.entry_point_id as usize >= n_modules {
            return Err(ExtractError::InvalidOffsets {
                byte_count: offsets.byte_count,
            });
        }

        let argv = extract_argv(data, payload_base, &offsets);
        let modules = parse_modules(data, payload_base, &offsets, module_struct_size)?;
        let version = BunVersion::detect(&embed_method, module_struct_size, offsets.flags);

        Ok(BunBinary {
            embed_method,
            offsets,
            payload_base,
            module_struct_size,
            modules,
            version,
            argv,
        })
    }
}

fn extract_argv(data: &[u8], payload_base: usize, offsets: &Offsets) -> Option<String> {
    let start = payload_base.checked_add(offsets.argv_offset as usize)?;
    let end = start.checked_add(offsets.argv_length as usize)?;
    if end > data.len() {
        return None;
    }
    std::str::from_utf8(&data[start..end])
        .ok()
        .map(String::from)
}

fn checked_offset(base: usize, offset: usize) -> Result<usize, ExtractError> {
    base.checked_add(offset).ok_or(ExtractError::OffsetOverflow)
}

/// Read a little-endian u16 from `data` at `offset`, returning `err` on OOB.
fn read_u16_le(data: &[u8], offset: usize, err: ExtractError) -> Result<u16, ExtractError> {
    let end = offset.checked_add(2).ok_or(ExtractError::OffsetOverflow)?;
    let bytes: [u8; 2] = data
        .get(offset..end)
        .ok_or(err)?
        .try_into()
        .map_err(|_| ExtractError::OffsetOverflow)?;
    Ok(u16::from_le_bytes(bytes))
}

/// Read a little-endian u32 from `data` at `offset`, returning `err` on OOB.
fn read_u32_le(data: &[u8], offset: usize, err: ExtractError) -> Result<u32, ExtractError> {
    let end = offset.checked_add(4).ok_or(ExtractError::OffsetOverflow)?;
    let bytes: [u8; 4] = data
        .get(offset..end)
        .ok_or(err)?
        .try_into()
        .map_err(|_| ExtractError::OffsetOverflow)?;
    Ok(u32::from_le_bytes(bytes))
}

/// Read a little-endian u64 from `data` at `offset`, returning `err` on OOB.
fn read_u64_le(data: &[u8], offset: usize, err: ExtractError) -> Result<u64, ExtractError> {
    let end = offset.checked_add(8).ok_or(ExtractError::OffsetOverflow)?;
    let bytes: [u8; 8] = data
        .get(offset..end)
        .ok_or(err)?
        .try_into()
        .map_err(|_| ExtractError::OffsetOverflow)?;
    Ok(u64::from_le_bytes(bytes))
}

fn detect_embed_method(data: &[u8]) -> Result<EmbedMethod, ExtractError> {
    let len = data.len();

    if len >= 8 + 16 {
        let trailer_start = len - 8 - 16;
        let trailer_end = len - 8;
        if &data[trailer_start..trailer_end] == TRAILER.as_slice() {
            return Ok(EmbedMethod::Appended);
        }
    }

    if len >= 4 {
        if data.get(0..4) == Some(ELF_MAGIC.as_slice()) {
            if let Ok(method) = find_elf_bun_section(data) {
                return Ok(method);
            }
        }

        if len >= 2 && data.get(0..2) == Some(PE_MAGIC.as_slice()) {
            if let Ok(method) = find_pe_bun_section(data) {
                return Ok(method);
            }
        }

        let magic32 = u32::from_le_bytes(
            data.get(0..4)
                .ok_or(ExtractError::TrailerNotFound)?
                .try_into()
                .map_err(|_| ExtractError::TrailerNotFound)?,
        );
        if magic32 == MACHO_MAGIC_64 || magic32 == 0xFEED_FACE {
            if let Ok(method) = find_macho_bun_section(data) {
                return Ok(method);
            }
        }
    }

    Err(ExtractError::TrailerNotFound)
}

fn find_elf_bun_section(data: &[u8]) -> Result<EmbedMethod, ExtractError> {
    if data.len() < 64 || data.get(0..4) != Some(ELF_MAGIC.as_slice()) {
        return Err(ExtractError::TrailerNotFound);
    }

    let is_64bit = data[4] == 2;
    if !is_64bit {
        return Err(ExtractError::InvalidElf);
    }

    let e_shoff = usize::try_from(read_u64_le(data, 40, ExtractError::InvalidElf)?)
        .map_err(|_| ExtractError::InvalidElf)?;
    let e_shentsize = read_u16_le(data, 58, ExtractError::InvalidElf)? as usize;
    let e_shnum = read_u16_le(data, 60, ExtractError::InvalidElf)? as usize;
    let e_shstrndx = read_u16_le(data, 62, ExtractError::InvalidElf)? as usize;

    if e_shoff == 0 || e_shnum == 0 {
        return Err(ExtractError::BunSectionNotFound);
    }

    let shstrndx_offset = e_shstrndx
        .checked_mul(e_shentsize)
        .ok_or(ExtractError::InvalidElf)?;
    let shstrtab_hdr_off = e_shoff
        .checked_add(shstrndx_offset)
        .ok_or(ExtractError::InvalidElf)?;
    let shstrtab_hdr_end = shstrtab_hdr_off
        .checked_add(e_shentsize)
        .ok_or(ExtractError::InvalidElf)?;
    if shstrtab_hdr_end > data.len() {
        return Err(ExtractError::InvalidElf);
    }

    let shstrtab_sh_offset = shstrtab_hdr_off
        .checked_add(24)
        .ok_or(ExtractError::InvalidElf)?;
    let shstrtab_sh_size = shstrtab_hdr_off
        .checked_add(32)
        .ok_or(ExtractError::InvalidElf)?;

    let shstrtab_offset = usize::try_from(read_u64_le(
        data,
        shstrtab_sh_offset,
        ExtractError::InvalidElf,
    )?)
    .map_err(|_| ExtractError::InvalidElf)?;
    let shstrtab_size = usize::try_from(read_u64_le(
        data,
        shstrtab_sh_size,
        ExtractError::InvalidElf,
    )?)
    .map_err(|_| ExtractError::InvalidElf)?;

    let shstrtab_end = shstrtab_offset
        .checked_add(shstrtab_size)
        .ok_or(ExtractError::InvalidElf)?;
    if shstrtab_end > data.len() {
        return Err(ExtractError::InvalidElf);
    }
    let shstrtab = &data[shstrtab_offset..shstrtab_end];

    for i in 0..e_shnum {
        let hdr_off = i
            .checked_mul(e_shentsize)
            .and_then(|v| e_shoff.checked_add(v))
            .ok_or(ExtractError::InvalidElf)?;
        let hdr_end = hdr_off
            .checked_add(e_shentsize)
            .ok_or(ExtractError::InvalidElf)?;
        if hdr_end > data.len() {
            break;
        }

        let sh_name = read_u32_le(data, hdr_off, ExtractError::InvalidElf)? as usize;

        if sh_name < shstrtab.len() {
            let name_end = shstrtab[sh_name..]
                .iter()
                .position(|&b| b == 0)
                .map(|p| sh_name.saturating_add(p))
                .unwrap_or(shstrtab.len());
            let section_name = match std::str::from_utf8(&shstrtab[sh_name..name_end]) {
                Ok(s) => s,
                Err(_) => continue,
            };

            if section_name == BUN_SECTION_NAME {
                let sh_offset_pos = hdr_off.checked_add(24).ok_or(ExtractError::InvalidElf)?;
                let sh_offset =
                    usize::try_from(read_u64_le(data, sh_offset_pos, ExtractError::InvalidElf)?)
                        .map_err(|_| ExtractError::InvalidElf)?;
                return Ok(EmbedMethod::ElfSection {
                    section_offset: sh_offset,
                });
            }
        }
    }

    Err(ExtractError::BunSectionNotFound)
}

fn find_pe_bun_section(data: &[u8]) -> Result<EmbedMethod, ExtractError> {
    if data.len() < 0x40 || data.get(0..2) != Some(PE_MAGIC.as_slice()) {
        return Err(ExtractError::TrailerNotFound);
    }

    let pe_offset = read_u32_le(data, 0x3C, ExtractError::InvalidPe)? as usize;

    let pe_sig_end = pe_offset.checked_add(4).ok_or(ExtractError::InvalidPe)?;
    if pe_sig_end > data.len() || &data[pe_offset..pe_sig_end] != b"PE\0\0" {
        return Err(ExtractError::InvalidPe);
    }

    let num_sections_off = pe_offset.checked_add(6).ok_or(ExtractError::InvalidPe)?;
    let num_sections = read_u16_le(data, num_sections_off, ExtractError::InvalidPe)? as usize;

    let opt_hdr_size_off = pe_offset.checked_add(20).ok_or(ExtractError::InvalidPe)?;
    let opt_hdr_size = read_u16_le(data, opt_hdr_size_off, ExtractError::InvalidPe)? as usize;

    let section_table = pe_offset
        .checked_add(24)
        .and_then(|v| v.checked_add(opt_hdr_size))
        .ok_or(ExtractError::InvalidPe)?;

    for i in 0..num_sections {
        let sec_off = i
            .checked_mul(40)
            .and_then(|v| section_table.checked_add(v))
            .ok_or(ExtractError::InvalidPe)?;
        let sec_end = sec_off.checked_add(40).ok_or(ExtractError::InvalidPe)?;
        if sec_end > data.len() {
            break;
        }

        let name_off = sec_off;
        let name_end = sec_off.checked_add(8).ok_or(ExtractError::InvalidPe)?;
        let name = &data[name_off..name_end];
        let trimmed = std::str::from_utf8(&name[..name.iter().position(|&b| b == 0).unwrap_or(8)])
            .unwrap_or("");

        if trimmed == BUN_SECTION_NAME {
            let size_off = sec_off.checked_add(16).ok_or(ExtractError::InvalidPe)?;
            let ptr_off = sec_off.checked_add(20).ok_or(ExtractError::InvalidPe)?;
            let raw_size = read_u32_le(data, size_off, ExtractError::InvalidPe)? as usize;
            let raw_offset = read_u32_le(data, ptr_off, ExtractError::InvalidPe)? as usize;

            let section_end = raw_offset
                .checked_add(raw_size)
                .ok_or(ExtractError::InvalidPe)?;
            if section_end <= data.len() {
                return Ok(EmbedMethod::PeSection {
                    section_offset: raw_offset,
                });
            }
        }
    }

    Err(ExtractError::BunSectionNotFound)
}

fn find_macho_bun_section(data: &[u8]) -> Result<EmbedMethod, ExtractError> {
    if data.len() < 32 {
        return Err(ExtractError::TrailerNotFound);
    }

    let magic = read_u32_le(data, 0, ExtractError::InvalidMachO)?;
    let is_64 = magic == MACHO_MAGIC_64;
    if !is_64 && magic != 0xFEED_FACE {
        return Err(ExtractError::InvalidMachO);
    }

    let ncmds = read_u32_le(data, 16, ExtractError::InvalidMachO)? as usize;

    let header_size: usize = if is_64 { 32 } else { 28 };
    let mut cursor = header_size;

    for _ in 0..ncmds {
        let cmd_end = cursor.checked_add(8).ok_or(ExtractError::InvalidMachO)?;
        if cmd_end > data.len() {
            break;
        }

        let cmd = read_u32_le(data, cursor, ExtractError::InvalidMachO)?;
        let cmdsize_off = cursor.checked_add(4).ok_or(ExtractError::InvalidMachO)?;
        let cmdsize = read_u32_le(data, cmdsize_off, ExtractError::InvalidMachO)? as usize;

        if cmdsize < 8 {
            break;
        }
        let cmd_block_end = cursor
            .checked_add(cmdsize)
            .ok_or(ExtractError::InvalidMachO)?;
        if cmd_block_end > data.len() {
            break;
        }

        const LC_SEGMENT_64: u32 = 0x19;
        if cmd == LC_SEGMENT_64 && cmdsize >= 72 {
            let segname_off = cursor.checked_add(8).ok_or(ExtractError::InvalidMachO)?;
            let segname_end = segname_off
                .checked_add(16)
                .ok_or(ExtractError::InvalidMachO)?;
            if segname_end > data.len() {
                break;
            }
            let segname = &data[segname_off..segname_end];

            if segname == MACHO_SEGMENT_NAME.as_slice() {
                let nsects_off = cursor.checked_add(64).ok_or(ExtractError::InvalidMachO)?;
                let nsects_end = nsects_off
                    .checked_add(4)
                    .ok_or(ExtractError::InvalidMachO)?;
                if nsects_end > data.len() {
                    break;
                }
                let nsects = read_u32_le(data, nsects_off, ExtractError::InvalidMachO)? as usize;

                let mut sec_cursor = cursor.checked_add(72).ok_or(ExtractError::InvalidMachO)?;
                for _ in 0..nsects {
                    let sec_end = sec_cursor
                        .checked_add(80)
                        .ok_or(ExtractError::InvalidMachO)?;
                    if sec_end > data.len() {
                        break;
                    }

                    let sectname_end = sec_cursor
                        .checked_add(16)
                        .ok_or(ExtractError::InvalidMachO)?;
                    let sectname = &data[sec_cursor..sectname_end];
                    if sectname == MACHO_SECTION_NAME.as_slice() {
                        let offset_field = sec_cursor
                            .checked_add(48)
                            .ok_or(ExtractError::InvalidMachO)?;
                        let offset =
                            read_u32_le(data, offset_field, ExtractError::InvalidMachO)? as usize;
                        return Ok(EmbedMethod::MachoSection {
                            section_offset: offset,
                        });
                    }
                    sec_cursor = sec_cursor
                        .checked_add(80)
                        .ok_or(ExtractError::InvalidMachO)?;
                }
            }
        }

        cursor = cursor
            .checked_add(cmdsize)
            .ok_or(ExtractError::InvalidMachO)?;
    }

    Err(ExtractError::BunSectionNotFound)
}

fn detect_module_struct_size(
    data: &[u8],
    payload_base: usize,
    modules_offset: u32,
    modules_length: u32,
) -> Result<usize, ExtractError> {
    let mod_array_start = checked_offset(payload_base, modules_offset as usize)?;
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
            let entry_offset = match i.checked_mul(candidate) {
                Some(v) => v,
                None => {
                    all_valid = false;
                    break;
                }
            };
            let entry_start = match mod_array_start.checked_add(entry_offset) {
                Some(v) if v.checked_add(8).is_some_and(|end| end <= data.len()) => v,
                _ => {
                    all_valid = false;
                    break;
                }
            };
            let entry_end = entry_start.saturating_add(8);
            let name_ptr = match StringPointer::from_bytes(&data[entry_start..entry_end]) {
                Some(sp) => sp,
                None => {
                    all_valid = false;
                    break;
                }
            };

            let name_start = match payload_base.checked_add(name_ptr.offset as usize) {
                Some(v) => v,
                None => {
                    all_valid = false;
                    break;
                }
            };
            let name_end = match name_start.checked_add(name_ptr.length as usize) {
                Some(v) if v <= data.len() && name_ptr.length > 0 => v,
                _ => {
                    all_valid = false;
                    break;
                }
            };

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

fn extract_enum_fields(
    data: &[u8],
    base: usize,
    struct_size: usize,
) -> (Encoding, Loader, ModuleFormat, FileSide) {
    let defaults = (
        Encoding::Binary,
        Loader::File,
        ModuleFormat::None,
        FileSide::Server,
    );

    if struct_size < 36 {
        return defaults;
    }

    // v1.3.2 has 4 StringPointers (32 bytes), then 4 enum u8s at offset 32.
    // But Zig may pad the struct. Try known positions:
    //   - offset 32: right after 4 SPs (Bun <=1.3 Zig-padded layout)
    //   - struct_size - 4: last 4 bytes (packed layouts like 36-byte or 52-byte)
    //   - struct_size - 8: for structs where enums have 4 bytes padding after them
    let candidates: &[usize] = &[32, struct_size - 4, struct_size - 8];

    for &off in candidates {
        let pos = match base.checked_add(off) {
            Some(v) if v.checked_add(4).is_some_and(|end| end <= data.len()) => v,
            _ => continue,
        };

        let enum_bytes = &data[pos..pos.saturating_add(4)];
        let enc = enum_bytes[0];
        let ldr = enum_bytes[1];
        let fmt = enum_bytes[2];
        let sid = enum_bytes[3];

        let enc_valid = enc <= 2;
        let ldr_valid = ldr <= 18;
        let fmt_valid = fmt <= 2;
        let sid_valid = sid <= 1;

        if enc_valid && ldr_valid && fmt_valid && sid_valid {
            return (
                Encoding::from(enc),
                Loader::from(ldr),
                ModuleFormat::from(fmt),
                FileSide::from(sid),
            );
        }
    }

    defaults
}

fn read_string_pointer<'a>(
    data: &'a [u8],
    payload_base: usize,
    sp: &StringPointer,
    payload_size: usize,
) -> Result<&'a [u8], ExtractError> {
    let oob = || ExtractError::StringOutOfBounds {
        offset: sp.offset,
        length: sp.length,
        payload_size,
    };

    let sp_end = (sp.offset as usize)
        .checked_add(sp.length as usize)
        .ok_or_else(oob)?;
    if sp_end > payload_size {
        return Err(oob());
    }

    let start = payload_base
        .checked_add(sp.offset as usize)
        .ok_or_else(oob)?;
    let end = start.checked_add(sp.length as usize).ok_or_else(oob)?;
    if end > data.len() {
        return Err(oob());
    }
    Ok(&data[start..end])
}

fn parse_modules(
    data: &[u8],
    payload_base: usize,
    offsets: &Offsets,
    struct_size: usize,
) -> Result<Vec<Module>, ExtractError> {
    let mod_array_start = checked_offset(payload_base, offsets.modules_offset as usize)?;
    let n_modules = offsets.modules_length as usize / struct_size;
    let payload_size =
        usize::try_from(offsets.byte_count).map_err(|_| ExtractError::OffsetOverflow)?;
    let mut modules = Vec::with_capacity(n_modules);

    for i in 0..n_modules {
        let base = mod_array_start
            .checked_add(
                i.checked_mul(struct_size)
                    .ok_or(ExtractError::OffsetOverflow)?,
            )
            .ok_or(ExtractError::OffsetOverflow)?;
        let base_8 = base
            .checked_add(8)
            .ok_or(ExtractError::CorruptModuleGraph { index: i })?;
        let base_16 = base
            .checked_add(16)
            .ok_or(ExtractError::CorruptModuleGraph { index: i })?;
        if base_16 > data.len() {
            return Err(ExtractError::CorruptModuleGraph { index: i });
        }

        let name_sp = StringPointer::from_bytes(&data[base..base_8])
            .ok_or(ExtractError::CorruptModuleGraph { index: i })?;
        let contents_sp = StringPointer::from_bytes(&data[base_8..base_16])
            .ok_or(ExtractError::CorruptModuleGraph { index: i })?;

        let name_bytes = read_string_pointer(data, payload_base, &name_sp, payload_size)?;
        let name = std::str::from_utf8(name_bytes)
            .map_err(|_| ExtractError::InvalidModuleName { index: i })?
            .to_string();

        let contents = if contents_sp.length > 0 {
            read_string_pointer(data, payload_base, &contents_sp, payload_size)?.to_vec()
        } else {
            Vec::new()
        };

        let base_24 = base.checked_add(24);
        let sourcemap = if struct_size >= 24 && base_24.is_some_and(|v| v <= data.len()) {
            let sm_end = base_24.ok_or(ExtractError::CorruptModuleGraph { index: i })?;
            let sm_sp = StringPointer::from_bytes(&data[base_16..sm_end])
                .ok_or(ExtractError::CorruptModuleGraph { index: i })?;
            if sm_sp.length > 0 {
                Some(read_string_pointer(data, payload_base, &sm_sp, payload_size)?.to_vec())
            } else {
                None
            }
        } else {
            None
        };

        let (encoding, loader, module_format, side) = extract_enum_fields(data, base, struct_size);

        modules.push(Module {
            index: i,
            name,
            contents,
            sourcemap,
            encoding,
            loader,
            module_format,
            side,
            is_entry_point: i == offsets.entry_point_id as usize,
        });
    }

    Ok(modules)
}
