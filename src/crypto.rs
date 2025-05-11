use std::ops::{BitAnd, Shr};

fn bit<T: Shr<i32, Output = T> + BitAnd<Output = T> + From<u8>>(x: T, b: i32) -> T {
	(x >> b) & 1.into()
}

fn stage1(addr: u32, param: u8) -> u16 {
	let swap = |x: u16, s| if s { x.swap_bytes() } else { x };
	let part = |b| swap((addr >> (16 * b)) as u16, bit(param, b) != 0);
	let addr = (0..2).fold(0, |x, b| x ^ part(b)) as u32;
	let x = ((addr >> 5) & 0xf) * 0x1111;
	(addr.rotate_right(7) ^ (0x6371 & x)) as u16
}

fn stage2(addr: u32, param: u8) -> u16 {
	let addr = (addr >> param) & 0x1FFFF;
	let x = (0..4).fold(0, |x, b| (x << 1) | bit(addr, 1 + b * 4)) * 0x1111;
	(addr.rotate_right(10) ^ (0x3659 & x)) as u16
}

fn stage3(addr: u32, param: u8) -> u32 {
	let addr = addr.rotate_right(8 * param as u32);
	let x = ((addr >> 2) & 0xf) * 0x1111_1111;
	addr.rotate_right(15) ^ (0xE519A4F1 & x)
}

pub fn encrypt(addr: u32, selectors: [Option<u8>; 3]) -> u32 {
	let mut out = 0;
	out ^= selectors[0].map_or(0, |sel| (stage1(addr, sel) as u32) << 16);
	out ^= selectors[1].map_or(0, |sel| (stage2(addr, sel) as u32));
	out ^= selectors[2].map_or(0, |sel| stage3(addr, sel));
	out
}

pub fn keystream(selectors: [Option<u8>; 3], addr: u32) -> impl Iterator<Item = u32> {
	(addr..).step_by(4).map(move |x| encrypt(x, selectors))
}

pub fn format_settings_word(selectors: [Option<u8>; 3]) -> u32 {
	let mut out = 0b0101_0101 << 24;
	for (i, &selector) in selectors.iter().enumerate() {
		out |= match selector {
			None => 1 << i,
			Some(selector) => (selector as u32) << (5 + i*3),
		}
	}
	out
}
