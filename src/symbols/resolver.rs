use std::collections::HashMap;
use std::fs;
use std::path::Path;

use anyhow::Result;

use crate::util::procfs::{self, MemoryMapping};

pub struct SymbolResolver {
    mappings: Vec<MemoryMapping>,
    cache: HashMap<u64, Option<ResolvedSymbol>>,
}

#[derive(Debug, Clone)]
pub struct ResolvedSymbol {
    pub function: String,
    pub file: Option<String>,
    pub line: Option<u32>,
    pub module: String,
    pub offset: u64,
}

impl SymbolResolver {
    pub fn new() -> Self {
        Self {
            mappings: Vec::new(),
            cache: HashMap::new(),
        }
    }

    pub fn load_maps_for_pid(&mut self, pid: i32) -> Result<()> {
        self.mappings = procfs::read_maps(pid)?;
        self.cache.clear();
        Ok(())
    }

    pub fn load_maps(&mut self, mappings: Vec<MemoryMapping>) {
        self.mappings = mappings;
        self.cache.clear();
    }

    pub fn resolve(&mut self, addr: u64) -> Option<ResolvedSymbol> {
        if let Some(cached) = self.cache.get(&addr) {
            return cached.clone();
        }

        let result = self.resolve_uncached(addr);
        self.cache.insert(addr, result.clone());
        result
    }

    fn resolve_uncached(&self, addr: u64) -> Option<ResolvedSymbol> {
        let mapping = self.mappings.iter().find(|m| {
            addr >= m.start && addr < m.end && m.permissions.contains('x')
        })?;

        let module_path = mapping.path.as_ref()?;

        if module_path.starts_with('[') {
            return Some(ResolvedSymbol {
                function: format!("{:#x}", addr),
                file: None,
                line: None,
                module: module_path.clone(),
                offset: addr - mapping.start,
            });
        }

        let file_offset = addr - mapping.start + mapping.offset;

        let resolved = resolve_from_elf(module_path, file_offset, addr);
        if resolved.is_some() {
            return resolved;
        }

        Some(ResolvedSymbol {
            function: format!("{:#x}", addr),
            file: None,
            line: None,
            module: module_path.clone(),
            offset: file_offset,
        })
    }

    pub fn resolve_many(&mut self, addrs: &[u64]) -> Vec<Option<ResolvedSymbol>> {
        addrs.iter().map(|&addr| self.resolve(addr)).collect()
    }
}

fn resolve_from_elf(elf_path: &str, file_offset: u64, addr: u64) -> Option<ResolvedSymbol> {
    let data = fs::read(elf_path).ok()?;

    let module = Path::new(elf_path)
        .file_name()
        .map(|f| f.to_string_lossy().into_owned())
        .unwrap_or_else(|| elf_path.to_string());

    resolve_elf_symbol(&data, file_offset, addr, &module)
}

fn resolve_elf_symbol(
    elf_data: &[u8],
    file_offset: u64,
    addr: u64,
    module: &str,
) -> Option<ResolvedSymbol> {
    if elf_data.len() < 16 || &elf_data[0..4] != b"\x7fELF" {
        return None;
    }

    let is_64 = elf_data[4] == 2;
    let is_le = elf_data[5] == 1;

    if !is_64 || !is_le {
        return None;
    }

    let e_shoff = u64::from_le_bytes(elf_data.get(40..48)?.try_into().ok()?);
    let e_shentsize = u16::from_le_bytes(elf_data.get(58..60)?.try_into().ok()?) as usize;
    let e_shnum = u16::from_le_bytes(elf_data.get(60..62)?.try_into().ok()?) as usize;
    let _e_shstrndx = u16::from_le_bytes(elf_data.get(62..64)?.try_into().ok()?) as usize;

    let mut symtab_offset = 0u64;
    let mut symtab_size = 0u64;
    let mut symtab_entsize = 0u64;
    let mut strtab_offset = 0u64;
    let mut _strtab_size = 0u64;
    let mut found_symtab = false;

    for i in 0..e_shnum {
        let sh_start = e_shoff as usize + i * e_shentsize;
        if sh_start + e_shentsize > elf_data.len() {
            break;
        }

        let sh_type = u32::from_le_bytes(
            elf_data.get(sh_start + 4..sh_start + 8)?.try_into().ok()?
        );

        if sh_type == 2 || sh_type == 11 {
            symtab_offset = u64::from_le_bytes(
                elf_data.get(sh_start + 24..sh_start + 32)?.try_into().ok()?
            );
            symtab_size = u64::from_le_bytes(
                elf_data.get(sh_start + 32..sh_start + 40)?.try_into().ok()?
            );
            symtab_entsize = u64::from_le_bytes(
                elf_data.get(sh_start + 56..sh_start + 64)?.try_into().ok()?
            );

            let strtab_idx = u32::from_le_bytes(
                elf_data.get(sh_start + 40..sh_start + 44)?.try_into().ok()?
            ) as usize;

            let str_sh_start = e_shoff as usize + strtab_idx * e_shentsize;
            strtab_offset = u64::from_le_bytes(
                elf_data.get(str_sh_start + 24..str_sh_start + 32)?.try_into().ok()?
            );
            _strtab_size = u64::from_le_bytes(
                elf_data.get(str_sh_start + 32..str_sh_start + 40)?.try_into().ok()?
            );

            found_symtab = true;
            if sh_type == 2 {
                break;
            }
        }
    }

    if !found_symtab || symtab_entsize == 0 {
        return None;
    }

    let e_type = u16::from_le_bytes(elf_data.get(16..18)?.try_into().ok()?);
    let lookup_addr = if e_type == 2 { addr } else { file_offset };

    let num_syms = (symtab_size / symtab_entsize) as usize;
    let mut best_match: Option<(u64, String)> = None;

    for i in 0..num_syms {
        let sym_start = symtab_offset as usize + i * symtab_entsize as usize;
        if sym_start + symtab_entsize as usize > elf_data.len() {
            break;
        }

        let st_name = u32::from_le_bytes(
            elf_data.get(sym_start..sym_start + 4)?.try_into().ok()?
        ) as usize;
        let st_info = elf_data.get(sym_start + 4)?;
        let st_value = u64::from_le_bytes(
            elf_data.get(sym_start + 8..sym_start + 16)?.try_into().ok()?
        );
        let st_size = u64::from_le_bytes(
            elf_data.get(sym_start + 16..sym_start + 24)?.try_into().ok()?
        );

        let sym_type = st_info & 0xf;
        if sym_type != 1 && sym_type != 2 {
            continue;
        }

        if st_value == 0 {
            continue;
        }

        if lookup_addr >= st_value && lookup_addr < st_value + st_size.max(1) {
            let name_start = strtab_offset as usize + st_name;
            if name_start < elf_data.len() {
                let name_end = elf_data[name_start..]
                    .iter()
                    .position(|&b| b == 0)
                    .unwrap_or(0);
                let name = String::from_utf8_lossy(&elf_data[name_start..name_start + name_end])
                    .into_owned();

                let distance = lookup_addr - st_value;
                if best_match.as_ref().map_or(true, |(d, _)| distance < *d) {
                    best_match = Some((distance, name));
                }
            }
        }
    }

    best_match.map(|(offset, function)| ResolvedSymbol {
        function,
        file: None,
        line: None,
        module: module.to_string(),
        offset,
    })
}

pub fn format_frame(sym: &Option<ResolvedSymbol>, addr: u64) -> String {
    match sym {
        Some(s) => {
            let loc = match (&s.file, s.line) {
                (Some(f), Some(l)) => format!(" at {}:{}", f, l),
                (Some(f), None) => format!(" at {}", f),
                _ => String::new(),
            };
            if s.offset > 0 {
                format!("{:#x}: {}+{:#x} [{}]{}", addr, s.function, s.offset, s.module, loc)
            } else {
                format!("{:#x}: {} [{}]{}", addr, s.function, s.module, loc)
            }
        }
        None => format!("{:#x}: ???", addr),
    }
}
