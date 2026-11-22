use spectre_elf_btf::{
    apply_core_relocations, Btf, BtfExt, CoreReloKind, CoreReloRec, Elf64Object, ElfBtfError,
    ParsedBpfObject,
};

struct SplitMix64(u64);

impl SplitMix64 {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    fn fill_bytes(&mut self, buf: &mut [u8]) {
        for chunk in buf.chunks_mut(8) {
            let v = self.next().to_le_bytes();
            let n = chunk.len();
            chunk.copy_from_slice(&v[..n]);
        }
    }
}

fn build_synthetic_btf(types_raw: &[u8], strs: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&0xEB9Fu16.to_le_bytes());
    out.push(1); // version
    out.push(0); // flags
    out.extend_from_slice(&24u32.to_le_bytes()); // hdr_len
    out.extend_from_slice(&0u32.to_le_bytes()); // type_off
    out.extend_from_slice(&(types_raw.len() as u32).to_le_bytes());
    out.extend_from_slice(&(types_raw.len() as u32).to_le_bytes()); // str_off
    out.extend_from_slice(&(strs.len() as u32).to_le_bytes());
    out.extend_from_slice(types_raw);
    out.extend_from_slice(strs);
    out
}

fn push_btf_type(buf: &mut Vec<u8>, name_off: u32, info: u32, size_or_type: u32) {
    buf.extend_from_slice(&name_off.to_le_bytes());
    buf.extend_from_slice(&info.to_le_bytes());
    buf.extend_from_slice(&size_or_type.to_le_bytes());
}

#[test]
fn fuzz_10000_hostile_elf64_and_btf_inputs_zero_panics() {
    let mut rng = SplitMix64(0x5EED_CAFE_BABE_0001);

    // Build a valid minimal ELF64 seed + valid minimal BTF seed for structural mutation
    let mut elf_seed = [0u8; 128];
    elf_seed[0..4].copy_from_slice(&[0x7F, b'E', b'L', b'F']);
    elf_seed[4] = 2; // ELFCLASS64
    elf_seed[5] = 1; // ELFDATA2LSB
    elf_seed[16..18].copy_from_slice(&1u16.to_le_bytes());
    elf_seed[18..20].copy_from_slice(&247u16.to_le_bytes());
    elf_seed[52..54].copy_from_slice(&64u16.to_le_bytes());
    elf_seed[58..60].copy_from_slice(&64u16.to_le_bytes());

    let mut btf_types = Vec::new();
    // ID 1: INT "u32" (4 bytes)
    push_btf_type(&mut btf_types, 1, 1 << 24, 4);
    btf_types.extend_from_slice(&32u32.to_le_bytes());
    let btf_seed = build_synthetic_btf(&btf_types, b"\0u32\0");

    for i in 0..10_000usize {
        let len = (rng.next() as usize % 512).max(1);
        let mut buf = vec![0u8; len];
        if i % 4 == 0 {
            let copy = len.min(elf_seed.len());
            buf[..copy].copy_from_slice(&elf_seed[..copy]);
            for _ in 0..6 {
                let idx = (rng.next() as usize) % len;
                buf[idx] ^= (rng.next() & 0xFF) as u8;
            }
        } else if i % 4 == 1 {
            let copy = len.min(btf_seed.len());
            buf[..copy].copy_from_slice(&btf_seed[..copy]);
            for _ in 0..6 {
                let idx = (rng.next() as usize) % len;
                buf[idx] ^= (rng.next() & 0xFF) as u8;
            }
        } else {
            rng.fill_bytes(&mut buf);
        }

        let _ = Elf64Object::parse(&buf);
        let _ = ParsedBpfObject::parse(&buf);
        if let Ok(btf) = Btf::parse(&buf) {
            let _ = btf.extract_btf_maps();
            for id in 0..(btf.types.len() as u32).min(16) {
                let _ = btf.type_size(id);
                let _ = btf.resolve_modifiers(id);
            }
            let _ = BtfExt::parse(&buf, &btf);
        }
    }
}

#[test]
fn btf_cyclic_type_graph_rejected_cleanly() {
    let mut types = Vec::new();
    // ID 1: typedef "A" -> ID 2
    push_btf_type(&mut types, 1, 8 << 24, 2);
    // ID 2: typedef "B" -> ID 1 (cycle!)
    push_btf_type(&mut types, 3, 8 << 24, 1);

    let raw = build_synthetic_btf(&types, b"\0A\0B\0");
    let btf = Btf::parse(&raw).expect("valid syntactic BTF");
    assert!(matches!(
        btf.type_size(1),
        Err(ElfBtfError::CyclicBtfGraph(_))
    ));
    assert!(matches!(
        btf.resolve_modifiers(1),
        Err(ElfBtfError::CyclicBtfGraph(_))
    ));
}

#[test]
fn core_relocation_resolves_flavor_and_anonymous_union() {
    // Local BTF:
    // str: \0u32\0task_struct___old\0pid\0tgid\00:0\00:1\0
    let mut strs = Vec::new();
    let off_zero = 0u32;
    let off_u32 = strs.len() as u32 + 1;
    strs.extend_from_slice(b"\0u32\0");
    let off_task_old = strs.len() as u32;
    strs.extend_from_slice(b"task_struct___old\0");
    let off_pid = strs.len() as u32;
    strs.extend_from_slice(b"pid\0");
    let off_tgid = strs.len() as u32;
    strs.extend_from_slice(b"tgid\0");
    let off_acc = strs.len() as u32;
    strs.extend_from_slice(b"0:1\0");

    let mut l_types = Vec::new();
    // ID 1: int u32 (4B)
    push_btf_type(&mut l_types, off_u32, 1 << 24, 4);
    l_types.extend_from_slice(&32u32.to_le_bytes());
    // ID 2: struct task_struct___old (size 8, 2 members: pid @ 0, tgid @ 4*8)
    push_btf_type(&mut l_types, off_task_old, (4 << 24) | 2, 8);
    l_types.extend_from_slice(&off_pid.to_le_bytes());
    l_types.extend_from_slice(&1u32.to_le_bytes());
    l_types.extend_from_slice(&0u32.to_le_bytes());
    l_types.extend_from_slice(&off_tgid.to_le_bytes());
    l_types.extend_from_slice(&1u32.to_le_bytes());
    l_types.extend_from_slice(&(4u32 * 8).to_le_bytes());
    let local_btf = Btf::parse(&build_synthetic_btf(&l_types, &strs)).unwrap();

    // Target BTF: task_struct has anonymous struct wrapping tgid at byte offset 24!
    let mut t_strs = Vec::new();
    t_strs.push(0);
    let t_u32 = t_strs.len() as u32;
    t_strs.extend_from_slice(b"u32\0");
    let t_task = t_strs.len() as u32;
    t_strs.extend_from_slice(b"task_struct\0");
    let t_tgid = t_strs.len() as u32;
    t_strs.extend_from_slice(b"tgid\0");

    let mut t_types = Vec::new();
    // ID 1: u32
    push_btf_type(&mut t_types, t_u32, 1 << 24, 4);
    t_types.extend_from_slice(&32u32.to_le_bytes());
    // ID 2: anonymous struct { u32 tgid @ bit 64 (byte 8) }
    push_btf_type(&mut t_types, off_zero, (4 << 24) | 1, 12);
    t_types.extend_from_slice(&t_tgid.to_le_bytes());
    t_types.extend_from_slice(&1u32.to_le_bytes());
    t_types.extend_from_slice(&(8u32 * 8).to_le_bytes());
    // ID 3: struct task_struct { anon @ byte 16 } -> total tgid offset = 16 + 8 = 24!
    push_btf_type(&mut t_types, t_task, (4 << 24) | 1, 32);
    t_types.extend_from_slice(&off_zero.to_le_bytes());
    t_types.extend_from_slice(&2u32.to_le_bytes());
    t_types.extend_from_slice(&(16u32 * 8).to_le_bytes());
    let target_btf = Btf::parse(&build_synthetic_btf(&t_types, &t_strs)).unwrap();

    // LDX W r0, [r1 + 4] -> code=0x61 (LDX|W|MEM), off=4 -> patched to off=24!
    let mut insn_bytes = [0u8; 8];
    insn_bytes[0] = 0x61;
    insn_bytes[1] = 0x10;
    insn_bytes[2..4].copy_from_slice(&4i16.to_le_bytes());
    let mut insns = [u64::from_le_bytes(insn_bytes)];

    let relos = [CoreReloRec {
        insn_off: 0,
        type_id: 2,
        access_str_off: off_acc,
        kind: CoreReloKind::FieldByteOffset,
    }];

    let applied = apply_core_relocations(&mut insns, &local_btf, &target_btf, &relos).unwrap();
    assert_eq!(applied, 1);
    let patched = insns[0].to_le_bytes();
    assert_eq!(i16::from_le_bytes([patched[2], patched[3]]), 24);
}
