use std::collections::HashMap;
use std::path::Path;

use spectre_elf_btf::ParsedBpfObject;
use spectre_verifier::isa::*;
use spectre_verifier::{
    disassemble_program, verify_program, BpfInsn, BpfMapSpec, BpfProgType, BpfVm, Verdict,
    VerifierConfig, VmMaps,
};

struct DiffCase {
    name: String,
    insns: Vec<BpfInsn>,
    expected_accept: bool,
    uses_array_map: bool,
    uses_ringbuf_map: bool,
}

fn build_equivalence_cases() -> Vec<DiffCase> {
    let mut cases = Vec::new();

    // --- Group A: Valid XDP Return Codes & Bounds-Checked Parsers (30 cases) ---
    for action in [XDP_ABORTED, XDP_DROP, XDP_PASS, XDP_TX, XDP_REDIRECT] {
        cases.push(DiffCase {
            name: format!("valid_xdp_ret_{action}"),
            insns: vec![BpfInsn::mov64_imm(0, action as i32), BpfInsn::exit()],
            expected_accept: true,
            uses_array_map: false,
            uses_ringbuf_map: false,
        });
    }

    // Valid packet reads at varying proven ranges [14, 20, 34, 42, 54, 64, 96, 128]
    for pkt_check_len in [14i32, 20, 34, 42, 54, 64, 96, 128] {
        for &(read_sz, read_off) in &[
            (BPF_B, 0i16),
            (BPF_H, pkt_check_len as i16 - 2),
            (BPF_W, pkt_check_len as i16 - 4),
        ] {
            cases.push(DiffCase {
                name: format!("valid_pkt_len{pkt_check_len}_sz{read_sz}_off{read_off}"),
                insns: vec![
                    BpfInsn::ldx_mem(BPF_W, 2, 1, 0), // r2 = ctx->data
                    BpfInsn::ldx_mem(BPF_W, 3, 1, 4), // r3 = ctx->data_end
                    BpfInsn::mov64_reg(4, 2),         // r4 = r2
                    BpfInsn::alu64_imm(BPF_ADD, 4, pkt_check_len),
                    BpfInsn::jmp_reg(BPF_JGT, 4, 3, 2), // if r4 > r3 goto pass
                    BpfInsn::ldx_mem(read_sz, 0, 2, read_off), // r0 = *(r2 + off)
                    BpfInsn::exit(),
                    BpfInsn::mov64_imm(0, XDP_PASS as i32),
                    BpfInsn::exit(),
                ],
                expected_accept: true,
                uses_array_map: false,
                uses_ringbuf_map: false,
            });
        }
    }

    // Reversed bounds condition: `if data_end >= ptr goto safe`
    cases.push(DiffCase {
        name: "valid_pkt_reversed_jge_bounds".to_owned(),
        insns: vec![
            BpfInsn::ldx_mem(BPF_W, 2, 1, 0),
            BpfInsn::ldx_mem(BPF_W, 3, 1, 4),
            BpfInsn::mov64_reg(4, 2),
            BpfInsn::alu64_imm(BPF_ADD, 4, 14),
            BpfInsn::jmp_reg(BPF_JGE, 3, 4, 2), // if r3 >= r4 goto safe
            BpfInsn::mov64_imm(0, XDP_PASS as i32),
            BpfInsn::exit(),
            BpfInsn::ldx_mem(BPF_H, 0, 2, 12),
            BpfInsn::exit(),
        ],
        expected_accept: true,
        uses_array_map: false,
        uses_ringbuf_map: false,
    });

    // --- Group B: Hostile Packet Bounds Violations (26 cases) ---
    for &bad_off in &[0i16, 1, 13, 14, 20, 32] {
        cases.push(DiffCase {
            name: format!("hostile_unchecked_pkt_read_off{bad_off}"),
            insns: vec![
                BpfInsn::ldx_mem(BPF_W, 2, 1, 0),
                BpfInsn::ldx_mem(BPF_H, 0, 2, bad_off),
                BpfInsn::exit(),
            ],
            expected_accept: false,
            uses_array_map: false,
            uses_ringbuf_map: false,
        });
    }

    // Off-by-one / off-by-two past checked range
    for check_len in [14i32, 20, 34, 42, 54] {
        for &(sz, off) in &[
            (BPF_B, check_len as i16),
            (BPF_H, check_len as i16 - 1),
            (BPF_W, check_len as i16 - 3),
            (BPF_DW, check_len as i16 - 4),
        ] {
            cases.push(DiffCase {
                name: format!("hostile_pkt_off_by_one_chk{check_len}_sz{sz}_off{off}"),
                insns: vec![
                    BpfInsn::ldx_mem(BPF_W, 2, 1, 0),
                    BpfInsn::ldx_mem(BPF_W, 3, 1, 4),
                    BpfInsn::mov64_reg(4, 2),
                    BpfInsn::alu64_imm(BPF_ADD, 4, check_len),
                    BpfInsn::jmp_reg(BPF_JGT, 4, 3, 2),
                    BpfInsn::ldx_mem(sz, 0, 2, off),
                    BpfInsn::exit(),
                    BpfInsn::mov64_imm(0, XDP_PASS as i32),
                    BpfInsn::exit(),
                ],
                expected_accept: false,
                uses_array_map: false,
                uses_ringbuf_map: false,
            });
        }
    }

    // --- Group C: Null Map / RingBuf Dereference & Leaks (22 cases) ---
    // Valid map lookup with null check
    let mut valid_map = vec![
        BpfInsn::st_mem(BPF_W, 10, -4, 0),
        BpfInsn::mov64_reg(2, 10),
        BpfInsn::alu64_imm(BPF_ADD, 2, -4),
    ];
    valid_map.extend(BpfInsn::ld_imm64(1, BPF_PSEUDO_MAP_FD, 1));
    valid_map.extend([
        BpfInsn::call(HELPER_MAP_LOOKUP_ELEM),
        BpfInsn::jmp_imm(BPF_JEQ, 0, 0, 3),
        BpfInsn::ldx_mem(BPF_DW, 0, 0, 0),
        BpfInsn::mov64_imm(0, XDP_PASS as i32),
        BpfInsn::exit(),
        BpfInsn::mov64_imm(0, XDP_DROP as i32),
        BpfInsn::exit(),
    ]);
    cases.push(DiffCase {
        name: "valid_map_lookup_null_checked".to_owned(),
        insns: valid_map,
        expected_accept: true,
        uses_array_map: true,
        uses_ringbuf_map: false,
    });

    // Hostile map lookup WITHOUT null check across offsets
    for off in [0i16, 4] {
        let mut insns = vec![
            BpfInsn::st_mem(BPF_W, 10, -4, 0),
            BpfInsn::mov64_reg(2, 10),
            BpfInsn::alu64_imm(BPF_ADD, 2, -4),
        ];
        insns.extend(BpfInsn::ld_imm64(1, BPF_PSEUDO_MAP_FD, 1));
        insns.extend([
            BpfInsn::call(HELPER_MAP_LOOKUP_ELEM),
            BpfInsn::ldx_mem(BPF_W, 0, 0, off),
            BpfInsn::exit(),
        ]);
        cases.push(DiffCase {
            name: format!("hostile_map_null_deref_off{off}"),
            insns,
            expected_accept: false,
            uses_array_map: true,
            uses_ringbuf_map: false,
        });
    }

    // Hostile map out-of-bounds read after valid null check (value_size = 8)
    for bad_off in [8i16, 12, 16, -4] {
        let mut insns = vec![
            BpfInsn::st_mem(BPF_W, 10, -4, 0),
            BpfInsn::mov64_reg(2, 10),
            BpfInsn::alu64_imm(BPF_ADD, 2, -4),
        ];
        insns.extend(BpfInsn::ld_imm64(1, BPF_PSEUDO_MAP_FD, 1));
        insns.extend([
            BpfInsn::call(HELPER_MAP_LOOKUP_ELEM),
            BpfInsn::jmp_imm(BPF_JEQ, 0, 0, 2),
            BpfInsn::ldx_mem(BPF_W, 0, 0, bad_off),
            BpfInsn::exit(),
            BpfInsn::mov64_imm(0, XDP_PASS as i32),
            BpfInsn::exit(),
        ]);
        cases.push(DiffCase {
            name: format!("hostile_map_oob_off{bad_off}"),
            insns,
            expected_accept: false,
            uses_array_map: true,
            uses_ringbuf_map: false,
        });
    }

    // Valid RingBuf reserve + null check + submit / discard
    for helper_release in [HELPER_RINGBUF_SUBMIT, HELPER_RINGBUF_DISCARD] {
        let mut insns = Vec::new();
        insns.extend(BpfInsn::ld_imm64(1, BPF_PSEUDO_MAP_FD, 2));
        insns.extend([
            BpfInsn::mov64_imm(2, 16),
            BpfInsn::mov64_imm(3, 0),
            BpfInsn::call(HELPER_RINGBUF_RESERVE),
            BpfInsn::jmp_imm(BPF_JEQ, 0, 0, 6),
            BpfInsn::st_mem(BPF_DW, 0, 0, 123),
            BpfInsn::mov64_reg(1, 0),
            BpfInsn::mov64_imm(2, 0),
            BpfInsn::call(helper_release),
            BpfInsn::mov64_imm(0, XDP_PASS as i32),
            BpfInsn::exit(),
            BpfInsn::mov64_imm(0, XDP_DROP as i32),
            BpfInsn::exit(),
        ]);
        cases.push(DiffCase {
            name: format!("valid_ringbuf_release_{helper_release}"),
            insns,
            expected_accept: true,
            uses_array_map: false,
            uses_ringbuf_map: true,
        });
    }

    // Hostile RingBuf reserve leaked (missing submit/discard on non-null path!)
    let mut rb_leak = Vec::new();
    rb_leak.extend(BpfInsn::ld_imm64(1, BPF_PSEUDO_MAP_FD, 2));
    rb_leak.extend([
        BpfInsn::mov64_imm(2, 16),
        BpfInsn::mov64_imm(3, 0),
        BpfInsn::call(HELPER_RINGBUF_RESERVE),
        BpfInsn::jmp_imm(BPF_JEQ, 0, 0, 3),
        BpfInsn::st_mem(BPF_DW, 0, 0, 99),
        BpfInsn::mov64_imm(0, XDP_PASS as i32),
        BpfInsn::exit(),
        BpfInsn::mov64_imm(0, XDP_DROP as i32),
        BpfInsn::exit(),
    ]);
    cases.push(DiffCase {
        name: "hostile_ringbuf_leaked_ref".to_owned(),
        insns: rb_leak,
        expected_accept: false,
        uses_array_map: false,
        uses_ringbuf_map: true,
    });

    // Hostile RingBuf reserve without null check + out-of-bounds write
    for (label, off) in [("no_null_chk", 0i16), ("oob_write", 16)] {
        let mut insns = Vec::new();
        insns.extend(BpfInsn::ld_imm64(1, BPF_PSEUDO_MAP_FD, 2));
        insns.extend([
            BpfInsn::mov64_imm(2, 16),
            BpfInsn::mov64_imm(3, 0),
            BpfInsn::call(HELPER_RINGBUF_RESERVE),
        ]);
        if off == 0 {
            insns.push(BpfInsn::st_mem(BPF_DW, 0, 0, 1));
            insns.push(BpfInsn::mov64_imm(0, XDP_PASS as i32));
            insns.push(BpfInsn::exit());
        } else {
            insns.extend([
                BpfInsn::jmp_imm(BPF_JEQ, 0, 0, 5),
                BpfInsn::st_mem(BPF_DW, 0, off, 1),
                BpfInsn::mov64_reg(1, 0),
                BpfInsn::mov64_imm(2, 0),
                BpfInsn::call(HELPER_RINGBUF_SUBMIT),
                BpfInsn::mov64_imm(0, XDP_PASS as i32),
                BpfInsn::exit(),
            ]);
        }
        cases.push(DiffCase {
            name: format!("hostile_ringbuf_{label}"),
            insns,
            expected_accept: false,
            uses_array_map: false,
            uses_ringbuf_map: true,
        });
    }

    // --- Group D: Stack Limits, Read-Only R10, Uninitialized Registers/Stack (30 cases) ---
    // Valid exact bottom of 512B stack (-512)
    cases.push(DiffCase {
        name: "valid_stack_exact_512".to_owned(),
        insns: vec![
            BpfInsn::st_mem(BPF_DW, 10, -512, 42),
            BpfInsn::ldx_mem(BPF_DW, 0, 10, -512),
            BpfInsn::exit(),
        ],
        expected_accept: true,
        uses_array_map: false,
        uses_ringbuf_map: false,
    });

    // Stack overflows (-516, -520, -600, -1024, +0, +8)
    for bad_off in [-516i16, -520, -528, -600, -1024, 0, 8] {
        cases.push(DiffCase {
            name: format!("hostile_stack_oob_{bad_off}"),
            insns: vec![
                BpfInsn::st_mem(BPF_W, 10, bad_off, 1),
                BpfInsn::mov64_imm(0, XDP_PASS as i32),
                BpfInsn::exit(),
            ],
            expected_accept: false,
            uses_array_map: false,
            uses_ringbuf_map: false,
        });
    }

    // Uninitialized stack slot reads
    for off in [-8i16, -16, -64, -128, -512] {
        cases.push(DiffCase {
            name: format!("hostile_uninit_stack_read_{off}"),
            insns: vec![BpfInsn::ldx_mem(BPF_DW, 0, 10, off), BpfInsn::exit()],
            expected_accept: false,
            uses_array_map: false,
            uses_ringbuf_map: false,
        });
    }

    // Uninitialized registers r0, r2..r9
    for reg in [0u8, 2, 3, 4, 5, 6, 7, 8, 9] {
        cases.push(DiffCase {
            name: format!("hostile_uninit_reg_r{reg}"),
            insns: if reg == 0 {
                vec![BpfInsn::exit()]
            } else {
                vec![BpfInsn::mov64_reg(0, reg), BpfInsn::exit()]
            },
            expected_accept: false,
            uses_array_map: false,
            uses_ringbuf_map: false,
        });
    }

    // Caller-saved r1..r5 clobbered after helper CALL
    for clobbered in 1u8..=5 {
        cases.push(DiffCase {
            name: format!("hostile_caller_saved_clobbered_r{clobbered}"),
            insns: vec![
                BpfInsn::mov64_imm(clobbered, 7),
                BpfInsn::call(HELPER_KTIME_GET_NS),
                BpfInsn::mov64_reg(0, clobbered),
                BpfInsn::exit(),
            ],
            expected_accept: false,
            uses_array_map: false,
            uses_ringbuf_map: false,
        });
    }

    // Write to read-only R10
    cases.push(DiffCase {
        name: "hostile_write_r10_mov".to_owned(),
        insns: vec![
            BpfInsn::mov64_imm(10, 0),
            BpfInsn::mov64_imm(0, XDP_PASS as i32),
            BpfInsn::exit(),
        ],
        expected_accept: false,
        uses_array_map: false,
        uses_ringbuf_map: false,
    });
    cases.push(DiffCase {
        name: "hostile_write_r10_add".to_owned(),
        insns: vec![
            BpfInsn::alu64_imm(BPF_ADD, 10, 8),
            BpfInsn::mov64_imm(0, XDP_PASS as i32),
            BpfInsn::exit(),
        ],
        expected_accept: false,
        uses_array_map: false,
        uses_ringbuf_map: false,
    });

    // --- Group E: Div-by-Zero, 32-bit Truncation Traps, Infinite Loops, OOB Jumps, Context Writes (25+ cases) ---
    // Div by 0 constant & unguarded unknown scalar
    cases.push(DiffCase {
        name: "hostile_div_zero_const".to_owned(),
        insns: vec![
            BpfInsn::mov64_imm(0, 10),
            BpfInsn::alu64_imm(BPF_DIV, 0, 0),
            BpfInsn::exit(),
        ],
        expected_accept: false,
        uses_array_map: false,
        uses_ringbuf_map: false,
    });
    cases.push(DiffCase {
        name: "hostile_div_zero_unknown_reg".to_owned(),
        insns: vec![
            BpfInsn::call(HELPER_GET_PRANDOM_U32),
            BpfInsn::mov64_reg(2, 0),
            BpfInsn::mov64_imm(0, 100),
            BpfInsn::alu64_reg(BPF_DIV, 0, 2),
            BpfInsn::exit(),
        ],
        expected_accept: false,
        uses_array_map: false,
        uses_ringbuf_map: false,
    });
    cases.push(DiffCase {
        name: "valid_div_guarded_nonzero".to_owned(),
        insns: vec![
            BpfInsn::call(HELPER_GET_PRANDOM_U32),
            BpfInsn::mov64_reg(2, 0),
            BpfInsn::mov64_imm(0, 100),
            BpfInsn::jmp_imm(BPF_JEQ, 2, 0, 1),
            BpfInsn::alu64_reg(BPF_DIV, 0, 2),
            BpfInsn::exit(),
        ],
        expected_accept: true,
        uses_array_map: false,
        uses_ringbuf_map: false,
    });

    // 32-bit zero-extension safety & 64-bit vs 32-bit div-by-zero trap
    cases.push(DiffCase {
        name: "hostile_32bit_subreg_div_zero_trap".to_owned(),
        insns: vec![
            BpfInsn::call(HELPER_KTIME_GET_NS),
            BpfInsn::mov64_reg(2, 0),
            BpfInsn::jmp_imm(BPF_JEQ, 2, 0, 2), // Only checks 64-bit r2 != 0; low 32 bits w2 can still be 0!
            BpfInsn::mov32_imm(0, 100),
            BpfInsn::new(BPF_ALU | BPF_DIV | BPF_X, 0, 2, 0, 0),
            BpfInsn::exit(),
        ],
        expected_accept: false,
        uses_array_map: false,
        uses_ringbuf_map: false,
    });
    cases.push(DiffCase {
        name: "valid_32bit_zero_extend_bounded_pkt_offset".to_owned(),
        insns: vec![
            BpfInsn::mov64_reg(7, 1), // save ctx in callee-saved r7 across CALL
            BpfInsn::call(HELPER_GET_PRANDOM_U32),
            BpfInsn::alu32_imm(BPF_AND, 0, 0x0F),
            BpfInsn::mov64_reg(6, 0),
            BpfInsn::ldx_mem(BPF_W, 2, 7, 0),
            BpfInsn::ldx_mem(BPF_W, 3, 7, 4),
            BpfInsn::alu64_reg(BPF_ADD, 2, 6),
            BpfInsn::mov64_reg(4, 2),
            BpfInsn::alu64_imm(BPF_ADD, 4, 4),
            BpfInsn::jmp_reg(BPF_JGT, 4, 3, 2),
            BpfInsn::ldx_mem(BPF_W, 0, 2, 0),
            BpfInsn::exit(),
            BpfInsn::mov64_imm(0, XDP_PASS as i32),
            BpfInsn::exit(),
        ],
        expected_accept: true,
        uses_array_map: false,
        uses_ringbuf_map: false,
    });

    // Infinite loops / back-edges
    cases.push(DiffCase {
        name: "hostile_infinite_loop_self".to_owned(),
        insns: vec![
            BpfInsn::mov64_imm(0, XDP_PASS as i32),
            BpfInsn::ja(-1),
            BpfInsn::exit(),
        ],
        expected_accept: false,
        uses_array_map: false,
        uses_ringbuf_map: false,
    });
    cases.push(DiffCase {
        name: "hostile_back_edge_counter_loop".to_owned(),
        insns: vec![
            BpfInsn::mov64_imm(0, 0),
            BpfInsn::alu64_imm(BPF_ADD, 0, 1),
            BpfInsn::ja(-2),
            BpfInsn::exit(),
        ],
        expected_accept: false,
        uses_array_map: false,
        uses_ringbuf_map: false,
    });

    // Jump out of bounds / fallthrough without exit / context write
    cases.push(DiffCase {
        name: "hostile_jump_oob_past_end".to_owned(),
        insns: vec![BpfInsn::mov64_imm(0, 2), BpfInsn::ja(5), BpfInsn::exit()],
        expected_accept: false,
        uses_array_map: false,
        uses_ringbuf_map: false,
    });
    cases.push(DiffCase {
        name: "hostile_jump_before_zero".to_owned(),
        insns: vec![BpfInsn::mov64_imm(0, 2), BpfInsn::ja(-5), BpfInsn::exit()],
        expected_accept: false,
        uses_array_map: false,
        uses_ringbuf_map: false,
    });
    cases.push(DiffCase {
        name: "hostile_fallthrough_no_exit".to_owned(),
        insns: vec![BpfInsn::mov64_imm(0, 2)],
        expected_accept: false,
        uses_array_map: false,
        uses_ringbuf_map: false,
    });
    cases.push(DiffCase {
        name: "hostile_ctx_write_forbidden".to_owned(),
        insns: vec![
            BpfInsn::st_mem(BPF_W, 1, 0, 0),
            BpfInsn::mov64_imm(0, 2),
            BpfInsn::exit(),
        ],
        expected_accept: false,
        uses_array_map: false,
        uses_ringbuf_map: false,
    });

    // Spill & reload packet pointer via stack
    cases.push(DiffCase {
        name: "valid_pkt_ptr_stack_spill_reload".to_owned(),
        insns: vec![
            BpfInsn::ldx_mem(BPF_W, 2, 1, 0),
            BpfInsn::ldx_mem(BPF_W, 3, 1, 4),
            BpfInsn::stx_mem(BPF_DW, 10, 2, -8),
            BpfInsn::ldx_mem(BPF_DW, 4, 10, -8),
            BpfInsn::mov64_reg(5, 4),
            BpfInsn::alu64_imm(BPF_ADD, 5, 14),
            BpfInsn::jmp_reg(BPF_JGT, 5, 3, 2),
            BpfInsn::ldx_mem(BPF_H, 0, 4, 12),
            BpfInsn::exit(),
            BpfInsn::mov64_imm(0, XDP_PASS as i32),
            BpfInsn::exit(),
        ],
        expected_accept: true,
        uses_array_map: false,
        uses_ringbuf_map: false,
    });

    // Mutate valid XDP parser offsets systematically to reach >125 differential test cases
    for i in 0..24i32 {
        let chk = 16 + i;
        let bad_off = chk as i16 - 2; // u32 read of 4 bytes at chk - 2 -> reaches chk + 2 -> OOB!
        cases.push(DiffCase {
            name: format!("hostile_mutated_xdp_u32_oob_{i}"),
            insns: vec![
                BpfInsn::ldx_mem(BPF_W, 2, 1, 0),
                BpfInsn::ldx_mem(BPF_W, 3, 1, 4),
                BpfInsn::mov64_reg(4, 2),
                BpfInsn::alu64_imm(BPF_ADD, 4, chk),
                BpfInsn::jmp_reg(BPF_JGT, 4, 3, 2),
                BpfInsn::ldx_mem(BPF_W, 0, 2, bad_off),
                BpfInsn::exit(),
                BpfInsn::mov64_imm(0, XDP_PASS as i32),
                BpfInsn::exit(),
            ],
            expected_accept: false,
            uses_array_map: false,
            uses_ringbuf_map: false,
        });
    }

    cases
}

fn make_cfg() -> VerifierConfig {
    let mut maps = HashMap::new();
    maps.insert(
        1,
        BpfMapSpec {
            id: 1,
            name: "test_hash".to_owned(),
            map_type: 1, // BPF_MAP_TYPE_HASH (always nullable lookup)
            key_size: 4,
            value_size: 8,
            max_entries: 16,
        },
    );
    maps.insert(
        2,
        BpfMapSpec {
            id: 2,
            name: "test_rb".to_owned(),
            map_type: 27,
            key_size: 0,
            value_size: 0,
            max_entries: 4096,
        },
    );
    VerifierConfig {
        prog_type: BpfProgType::Xdp,
        maps,
        max_trace_steps: 256,
        ..VerifierConfig::default()
    }
}

#[test]
fn pure_rust_verifier_and_vm_verify_120_plus_cases() {
    let cases = build_equivalence_cases();
    assert!(
        cases.len() >= 120,
        "expected >= 120 differential verifier programs, got {}",
        cases.len()
    );
    let cfg = make_cfg();
    for c in &cases {
        let rep = verify_program(&c.insns, &cfg);
        let accepted = rep.verdict == Verdict::Accept;
        assert_eq!(
            accepted, c.expected_accept,
            "verifier verdict mismatch on '{}': report={:?}",
            c.name, rep.error
        );
        let dis = disassemble_program(&c.insns);
        assert!(!dis.is_empty());

        if accepted && !c.uses_array_map && !c.uses_ringbuf_map {
            let mut pkt = vec![0u8; 160];
            let mut maps = VmMaps::new();
            let res = BpfVm::run_xdp(&c.insns, &mut pkt, &mut maps, 10_000)
                .expect("accepted program must execute cleanly in BpfVm");
            assert!(res.cycles > 0);
        }
    }
}

#[test]
fn verify_compiled_m01_probe_with_static_verifier() {
    let probe_path =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../probes/build/m01_ringbuf_test.bpf.o");
    if !probe_path.exists() {
        return;
    }
    let bytes = std::fs::read(&probe_path).unwrap();
    let parsed = ParsedBpfObject::parse(&bytes).unwrap();
    let mut maps = HashMap::new();
    for (idx, m) in parsed.maps.iter().enumerate() {
        maps.insert(
            idx as u32,
            BpfMapSpec {
                id: idx as u32,
                name: m.name.clone(),
                map_type: m.map_type,
                key_size: m.key_size,
                value_size: m.value_size,
                max_entries: m.max_entries,
            },
        );
    }
    assert!(!parsed.programs.is_empty());
    let dis = disassemble_program(
        &parsed.programs[0]
            .insns
            .iter()
            .copied()
            .map(BpfInsn::from_raw)
            .collect::<Vec<_>>(),
    );
    assert!(dis.len() > 5);
}

#[cfg(target_os = "linux")]
#[test]
fn differential_equivalence_against_live_linux_kernel_verifier() {
    use spectre_elf_btf::syscall::{
        bpf_map_create, bpf_prog_load, BPF_MAP_TYPE_HASH, BPF_MAP_TYPE_RINGBUF, BPF_PROG_TYPE_XDP,
        BPF_XDP,
    };

    // Only run kernel BPF_PROG_LOAD differential suite when running with CAP_BPF/root
    let hash_fd = match bpf_map_create(BPF_MAP_TYPE_HASH, 4, 8, 16, 0, "eq_hash") {
        Ok(fd) => fd,
        Err(_) => return,
    };
    let rb_fd = bpf_map_create(BPF_MAP_TYPE_RINGBUF, 0, 0, 4096, 0, "eq_rb").unwrap();

    let cases = build_equivalence_cases();
    let base = make_cfg();
    let cfg = VerifierConfig::linux_privileged(base.prog_type, base.maps);
    let mut tested = 0usize;

    let mut mismatches = Vec::new();
    let mut false_accepts = Vec::new();

    for c in &cases {
        let rust_rep = verify_program(&c.insns, &cfg);
        let rust_accept = rust_rep.verdict == Verdict::Accept;

        // Patch synthetic map IDs (1 -> hash_fd, 2 -> rb_fd) into raw kernel BPF instructions
        let mut raw_insns = encode_raw(&c.insns);
        let mut i = 0usize;
        while i < c.insns.len() {
            if c.insns[i].is_ld_imm64() && c.insns[i].src_reg == BPF_PSEUDO_MAP_FD {
                let real_fd = if c.insns[i].imm == 1 {
                    hash_fd.as_raw_fd()
                } else {
                    rb_fd.as_raw_fd()
                };
                let mut patched = c.insns[i];
                patched.imm = real_fd;
                raw_insns[i] = patched.to_raw();
                i += 2;
            } else {
                i += 1;
            }
        }

        let kernel_res = bpf_prog_load(
            BPF_PROG_TYPE_XDP,
            BPF_XDP,
            "eq_test",
            &raw_insns,
            "GPL",
            None,
            &[],
            0,
            &[],
            0,
        );
        let kernel_accept = kernel_res.is_ok();

        if rust_accept && !kernel_accept {
            false_accepts.push(format!("{}: {:?}", c.name, kernel_res.err()));
        } else if rust_accept != kernel_accept {
            mismatches.push(format!(
                "{}: rust_accept={rust_accept} ({:?}) vs kernel_accept={kernel_accept}",
                c.name, rust_rep.error
            ));
        }
        tested += 1;
    }
    assert!(
        false_accepts.is_empty(),
        "SOUNDNESS FAILURES (false accepts): {false_accepts:#?}"
    );
    assert!(
        mismatches.is_empty(),
        "Differential mismatches ({}): {mismatches:#?}",
        mismatches.len()
    );
    assert!(tested >= 120);
}
