//! Tristate Number (`Tnum`) abstract domain matching Linux `kernel/bpf/tnum.c`.
//!
//! Invariant: `value & mask == 0`.
//! - Bit `i` in `mask == 1`: bit `i` is unknown (`?`).
//! - Bit `i` in `mask == 0`: bit `i` is definitely `(value >> i) & 1`.

use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Tnum {
    pub value: u64,
    pub mask: u64,
}

impl Tnum {
    pub const UNKNOWN: Self = Self {
        value: 0,
        mask: u64::MAX,
    };

    pub const ZERO: Self = Self { value: 0, mask: 0 };

    #[must_use]
    pub const fn from_const(v: u64) -> Self {
        Self { value: v, mask: 0 }
    }

    #[must_use]
    pub const fn new(value: u64, mask: u64) -> Self {
        Self {
            value: value & !mask,
            mask,
        }
    }

    #[must_use]
    pub const fn is_const(self) -> bool {
        self.mask == 0
    }

    #[must_use]
    pub const fn equals_const(self, v: u64) -> bool {
        self.mask == 0 && self.value == v
    }

    /// Construct a `Tnum` capturing the common known prefix of `[min, max]`.
    #[must_use]
    pub const fn from_range(min: u64, max: u64) -> Self {
        let chi = min ^ max;
        let bits = 64 - chi.leading_zeros();
        if bits >= 64 {
            Self::UNKNOWN
        } else {
            let delta = (1u64 << bits) - 1;
            Self {
                value: min & !delta,
                mask: delta,
            }
        }
    }

    #[must_use]
    pub const fn umin(self) -> u64 {
        self.value
    }

    #[must_use]
    pub const fn umax(self) -> u64 {
        self.value | self.mask
    }

    #[must_use]
    pub const fn subreg(self) -> Self {
        Self::new(self.value as u32 as u64, self.mask as u32 as u64)
    }

    #[must_use]
    pub const fn clear_subreg(self) -> Self {
        Self::new(self.value & !0xFFFF_FFFF, self.mask & !0xFFFF_FFFF)
    }

    #[must_use]
    pub const fn with_subreg(self, sub: Self) -> Self {
        Self::new(
            (self.value & !0xFFFF_FFFF) | (sub.value & 0xFFFF_FFFF),
            (self.mask & !0xFFFF_FFFF) | (sub.mask & 0xFFFF_FFFF),
        )
    }

    #[must_use]
    pub const fn cast_u8(self) -> Self {
        Self::new(self.value & 0xFF, self.mask & 0xFF)
    }

    #[must_use]
    pub const fn cast_u16(self) -> Self {
        Self::new(self.value & 0xFFFF, self.mask & 0xFFFF)
    }

    #[must_use]
    pub const fn lshift(self, shift: u32) -> Self {
        if shift >= 64 {
            Self::ZERO
        } else {
            Self::new(self.value << shift, self.mask << shift)
        }
    }

    #[must_use]
    pub const fn rshift(self, shift: u32) -> Self {
        if shift >= 64 {
            Self::ZERO
        } else {
            Self::new(self.value >> shift, self.mask >> shift)
        }
    }

    #[must_use]
    pub const fn arshift(self, min_shift: u32, insn_bitness: u8) -> Self {
        let shift = if min_shift > 63 { 63 } else { min_shift };
        match insn_bitness {
            32 => {
                let s32 = if shift > 31 { 31 } else { shift };
                let v = ((self.value as i32) >> s32) as u32 as u64;
                let m = ((self.mask as i32) >> s32) as u32 as u64;
                Self::new(v, m)
            }
            _ => {
                let v = ((self.value as i64) >> shift) as u64;
                let m = ((self.mask as i64) >> shift) as u64;
                Self::new(v, m)
            }
        }
    }

    /// Exact bit-carry propagation addition from `kernel/bpf/tnum.c` (`tnum_add`).
    #[must_use]
    pub const fn add(self, b: Self) -> Self {
        let sm = self.mask.wrapping_add(b.mask);
        let sv = self.value.wrapping_add(b.value);
        let sigma = sm.wrapping_add(sv);
        let chi = sigma ^ sv;
        let mu = chi | self.mask | b.mask;
        Self::new(sv & !mu, mu)
    }

    /// Exact subtraction from `kernel/bpf/tnum.c` (`tnum_sub`).
    #[must_use]
    pub const fn sub(self, b: Self) -> Self {
        let dv = self.value.wrapping_sub(b.value);
        let alpha = dv.wrapping_add(self.mask);
        let beta = dv.wrapping_sub(b.mask);
        let chi = alpha ^ beta;
        let mu = chi | self.mask | b.mask;
        Self::new(dv & !mu, mu)
    }

    #[must_use]
    pub const fn and(self, b: Self) -> Self {
        let alpha = self.value | self.mask;
        let beta = b.value | b.mask;
        let v = self.value & b.value;
        Self::new(v, alpha & beta & !v)
    }

    #[must_use]
    pub const fn or(self, b: Self) -> Self {
        let v = self.value | b.value;
        let mu = self.mask | b.mask;
        Self::new(v, mu & !v)
    }

    #[must_use]
    pub const fn xor(self, b: Self) -> Self {
        let v = self.value ^ b.value;
        let mu = self.mask | b.mask;
        Self::new(v, mu)
    }

    /// Intersect two `Tnum` knowledge domains (`tnum_intersect`).
    #[must_use]
    pub const fn intersect(self, b: Self) -> Self {
        let v = self.value | b.value;
        let mu = self.mask & b.mask;
        Self::new(v, mu)
    }

    /// Join (least upper bound) of two `Tnum` states.
    #[must_use]
    pub const fn join(self, b: Self) -> Self {
        let diff = self.value ^ b.value;
        let mu = self.mask | b.mask | diff;
        Self::new(self.value & !mu, mu)
    }

    /// Returns true if every concrete value allowed by `other` is also allowed by `self`.
    #[must_use]
    pub const fn subsumes(self, other: Self) -> bool {
        let known = !self.mask;
        (known & self.value) == (known & other.value) && (other.mask & known) == 0
    }

    #[must_use]
    pub fn format_bits(&self) -> String {
        if self.mask == 0 {
            return format!("{:#x}", self.value);
        }
        if self.mask == u64::MAX {
            return "unknown(64b)".to_owned();
        }
        format!("(val={:#x}, mask={:#x})", self.value, self.mask)
    }
}

impl fmt::Display for Tnum {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.format_bits())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tnum_arithmetic_preserves_soundness() {
        let a = Tnum::from_range(0, 7); // mask = 0b111, value = 0
        let b = Tnum::from_const(8);
        let sum = a.add(b);
        for x in 0..=7u64 {
            let concrete = x + 8;
            assert_eq!(concrete & !sum.mask, sum.value);
        }

        let masked = Tnum::UNKNOWN.and(Tnum::from_const(0x0F));
        assert_eq!(masked.value, 0);
        assert_eq!(masked.mask, 0x0F);
        assert_eq!(masked.umax(), 0x0F);

        let sub = Tnum::from_const(0xFFFF_FFFF_0000_0005).subreg();
        assert_eq!(sub, Tnum::from_const(5));
    }
}
