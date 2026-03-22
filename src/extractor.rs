use std::fs;
use std::path::Path;

use crate::error::ExtractError;
use crate::format::{
    BunVersion, EmbedMethod, Encoding, FileSide, Loader, Module, ModuleFormat, Offsets,
    StringPointer, CANDIDATE_STRUCT_SIZES, MODULE_NAME_PREFIX, OFFSETS_SIZE, TRAILER,
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
        Self::parse(data)
    }

    pub fn parse(data: Vec<u8>) -> Result<Self, ExtractError> {
        let file_size = data.len();
        if file_size < 60 {
            return Err(ExtractError::FileTooSmall { size: file_size });
        }

        let embed_method = detect_embed_method(&data)?;

        let (offsets, payload_base) = match embed_method {
            EmbedMethod::Appended => {
                let offsets_end = file_size - 8 - 16;
                let offsets_start = offsets_end - OFFSETS_SIZE;
                let offsets = Offsets::from_bytes(&data[offsets_start..offsets_end])
                    .ok_or(ExtractError::TrailerNotFound)?;

                if offsets.byte_count as usize > file_size || offsets.byte_count < 32 {
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
                let payload_len = u64::from_le_bytes(
                    data[section_offset..section_offset + 8]
                        .try_into()
                        .map_err(|_| ExtractError::InvalidElf)?,
                ) as usize;
                let section_payload_start = section_offset
                    .checked_add(8)
                    .ok_or(ExtractError::OffsetOverflow)?;
                let section_payload_end = section_payload_start
                    .checked_add(payload_len)
                    .ok_or(ExtractError::OffsetOverflow)?;

                if section_payload_end < 16 + OFFSETS_SIZE {
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
            &data,
            payload_base,
            offsets.modules_offset,
            offsets.modules_length,
        )?;

        let n_modules = offsets.modules_length as usize / module_struct_size;
        if offsets.entry_point_id as usize > n_modules {
            return Err(ExtractError::InvalidOffsets {
                byte_count: offsets.byte_count,
            });
        }

        let argv = extract_argv(&data, payload_base, &offsets);
        let modules = parse_modules(&data, payload_base, &offsets, module_struct_size)?;
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
        if &data[0..4] == b"\x7fELF" {
            if let Ok(method) = find_elf_bun_section(data) {
                return Ok(method);
            }
        }

        if len >= 2 && &data[0..2] == b"MZ" {
            if let Ok(method) = find_pe_bun_section(data) {
                return Ok(method);
            }
        }

        let magic32 = u32::from_le_bytes(data[0..4].try_into().unwrap());
        if magic32 == 0xFEED_FACF || magic32 == 0xFEED_FACE {
            if let Ok(method) = find_macho_bun_section(data) {
                return Ok(method);
            }
        }
    }

    Err(ExtractError::TrailerNotFound)
}

fn find_elf_bun_section(data: &[u8]) -> Result<EmbedMethod, ExtractError> {
    if data.len() < 64 || &data[0..4] != b"\x7fELF" {
        return Err(ExtractError::TrailerNotFound);
    }

    let is_64bit = data[4] == 2;
    if !is_64bit {
        return Err(ExtractError::InvalidElf);
    }

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
            let section_name = match std::str::from_utf8(&shstrtab[sh_name..name_end]) {
                Ok(s) => s,
                Err(_) => continue,
            };

            if section_name == ".bun" {
                let sh_offset = u64::from_le_bytes(
                    data[hdr_off + 24..hdr_off + 32]
                        .try_into()
                        .map_err(|_| ExtractError::InvalidElf)?,
                ) as usize;
                return Ok(EmbedMethod::ElfSection {
                    section_offset: sh_offset,
                });
            }
        }
    }

    Err(ExtractError::BunSectionNotFound)
}

fn find_pe_bun_section(data: &[u8]) -> Result<EmbedMethod, ExtractError> {
    if data.len() < 0x40 || &data[0..2] != b"MZ" {
        return Err(ExtractError::TrailerNotFound);
    }

    let pe_offset = u32::from_le_bytes(
        data[0x3C..0x40]
            .try_into()
            .map_err(|_| ExtractError::TrailerNotFound)?,
    ) as usize;

    if pe_offset + 24 > data.len() || &data[pe_offset..pe_offset + 4] != b"PE\0\0" {
        return Err(ExtractError::TrailerNotFound);
    }

    let num_sections = u16::from_le_bytes(
        data[pe_offset + 6..pe_offset + 8]
            .try_into()
            .map_err(|_| ExtractError::TrailerNotFound)?,
    ) as usize;
    let opt_hdr_size = u16::from_le_bytes(
        data[pe_offset + 20..pe_offset + 22]
            .try_into()
            .map_err(|_| ExtractError::TrailerNotFound)?,
    ) as usize;
    let section_table = pe_offset + 24 + opt_hdr_size;

    for i in 0..num_sections {
        let sec_off = section_table + i * 40;
        if sec_off + 40 > data.len() {
            break;
        }

        let name = &data[sec_off..sec_off + 8];
        let trimmed = std::str::from_utf8(&name[..name.iter().position(|&b| b == 0).unwrap_or(8)])
            .unwrap_or("");

        if trimmed == ".bun" {
            let raw_size = u32::from_le_bytes(
                data[sec_off + 16..sec_off + 20]
                    .try_into()
                    .map_err(|_| ExtractError::TrailerNotFound)?,
            ) as usize;
            let raw_offset = u32::from_le_bytes(
                data[sec_off + 20..sec_off + 24]
                    .try_into()
                    .map_err(|_| ExtractError::TrailerNotFound)?,
            ) as usize;

            if raw_offset + raw_size <= data.len() {
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

    let magic = u32::from_le_bytes(
        data[0..4]
            .try_into()
            .map_err(|_| ExtractError::TrailerNotFound)?,
    );
    let is_64 = magic == 0xFEED_FACF;
    if !is_64 && magic != 0xFEED_FACE {
        return Err(ExtractError::TrailerNotFound);
    }

    let ncmds = u32::from_le_bytes(
        data[16..20]
            .try_into()
            .map_err(|_| ExtractError::TrailerNotFound)?,
    ) as usize;

    let header_size: usize = if is_64 { 32 } else { 28 };
    let mut cursor = header_size;

    for _ in 0..ncmds {
        if cursor + 8 > data.len() {
            break;
        }

        let cmd = u32::from_le_bytes(data[cursor..cursor + 4].try_into().unwrap());
        let cmdsize = u32::from_le_bytes(data[cursor + 4..cursor + 8].try_into().unwrap()) as usize;

        if cmdsize < 8 || cursor + cmdsize > data.len() {
            break;
        }

        const LC_SEGMENT_64: u32 = 0x19;
        if cmd == LC_SEGMENT_64 && cmdsize >= 72 {
            let segname = &data[cursor + 8..cursor + 24];
            if segname.starts_with(b"__BUN\0") {
                if cursor + 68 > data.len() {
                    break;
                }
                let nsects =
                    u32::from_le_bytes(data[cursor + 64..cursor + 68].try_into().unwrap()) as usize;

                let mut sec_cursor = cursor + 72;
                for _ in 0..nsects {
                    if sec_cursor + 80 > data.len() {
                        break;
                    }

                    let sectname = &data[sec_cursor..sec_cursor + 16];
                    if sectname.starts_with(b"__bun\0") {
                        let offset = u32::from_le_bytes(
                            data[sec_cursor + 48..sec_cursor + 52].try_into().unwrap(),
                        ) as usize;
                        return Ok(EmbedMethod::MachoSection {
                            section_offset: offset,
                        });
                    }
                    sec_cursor += 80;
                }
            }
        }

        cursor += cmdsize;
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
            let entry_start = match mod_array_start.checked_add(i * candidate) {
                Some(v) if v + 8 <= data.len() => v,
                _ => {
                    all_valid = false;
                    break;
                }
            };
            let name_ptr = match StringPointer::from_bytes(&data[entry_start..entry_start + 8]) {
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
            Some(v) if v + 4 <= data.len() => v,
            _ => continue,
        };

        let enc = data[pos];
        let ldr = data[pos + 1];
        let fmt = data[pos + 2];
        let sid = data[pos + 3];

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
    let payload_size = offsets.byte_count as usize;
    let mut modules = Vec::with_capacity(n_modules);

    for i in 0..n_modules {
        let base = mod_array_start
            .checked_add(i * struct_size)
            .ok_or(ExtractError::OffsetOverflow)?;
        if base + 16 > data.len() {
            return Err(ExtractError::CorruptModuleGraph { index: i });
        }

        let name_sp = StringPointer::from_bytes(&data[base..base + 8])
            .ok_or(ExtractError::CorruptModuleGraph { index: i })?;
        let contents_sp = StringPointer::from_bytes(&data[base + 8..base + 16])
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

        let sourcemap = if struct_size >= 24 && base + 24 <= data.len() {
            let sm_sp = StringPointer::from_bytes(&data[base + 16..base + 24])
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
