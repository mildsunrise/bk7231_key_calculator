// This search algorithm is clearly overoptimized. But hey, I had fun.

mod crypto;
mod utils;

use std::{
	cell::RefCell,
	io::{stdin, BufReader, Read},
};
use utils::{PeekRead, RollingXor};

/// keeps RollingXor buffers of the input and stage keystreams
struct Bk7231RollingXor<Reader> {
	stream: RefCell<PeekRead<Reader>>,
	addr: u32,
	input: RollingXor<u32>,
	s12out: [RollingXor<u32>; 4],
	s3out: [RollingXor<u32>; 4],
}

impl<Reader: Read> Bk7231RollingXor<Reader> {
	fn new(image: PeekRead<Reader>, base_addr: u32) -> Self {
		let mut this = Self {
			stream: RefCell::new(image),
			addr: base_addr,
			input: Default::default(),
			s12out: Default::default(),
			s3out: Default::default(),
		};
		// fill buffers
		this.update().unwrap();
		this.update().unwrap();
		this
	}

	#[must_use]
	fn update(&mut self) -> Option<u32> {
		let mut block = [0; 4];
		match self
			.stream
			.borrow_mut()
			.read(&mut block)
			.expect("error reading from image")
		{
			0 => return None,
			4 => (),
			_ => panic!("dump ends with incomplete block"),
		}
		let block = u32::from_le_bytes(block);

		let addr = self.addr;
		self.input.update(block);
		for selector in 0..4 {
			self.s12out[selector].update(crypto::stage12(addr, selector as _));
			self.s3out[selector].update(crypto::stage3(addr, selector as _));
		}
		self.addr += 4;
		Some(addr)
	}
}

fn all_selectors<'a, const I: usize>(
	buffers: &'a [RollingXor<u32>; 4],
	block: u32,
) -> impl Iterator<Item = (Option<u8>, u32)> + use<'a, I> {
	buffers
		.iter()
		.enumerate()
		.map(move |(i, buffer)| (Some(i as u8), block ^ buffer.0[I]))
		.chain([(None, block)])
}

fn search(stream: &mut Bk7231RollingXor<impl Read>, search: &[u8]) {
	// preprocess search string to derive, for each of the 4 offsets it can
	// occur in relative to an encryption block:
	//  - a 16-bit word to be matched first (on the first or second half of
	//    the 32-bit block, for the first and last 2 entries respectively)
	//  - a 16-bit word to be matched to the preceding 16 bits of stream
	//  - offset of the second matched word in the search string
	let mut matchers: [(u16, u16, u8); 4] = Default::default();
	for offset in 0..4 {
		let stream_offset = (offset + 4 + 1) & !1;
		let offset = stream_offset - offset;
		let word_at = |x| u16::from_le_bytes(search[x..][..2].try_into().unwrap());
		let diff_word_at = |x| word_at(x) ^ word_at(x - 4);
		matchers[(stream_offset & 2) + (offset & 1)] =
			(diff_word_at(offset + 2), diff_word_at(offset), offset as u8);
	}

	// the actual search
	while let Some(addr) = stream.update() {
		let block = stream.input.0[1];
		for (s3sel, block) in all_selectors::<1>(&stream.s3out, block) {
			for (s12sel, block) in all_selectors::<1>(&stream.s12out, block) {
				let word = block as u16;
				for &(m1, m2, offset) in &matchers[0..2] {
					if m1 == word {
						verify_preliminary_match::<0, 2>(
							stream,
							search,
							addr,
							(m2, offset),
							[s3sel, s12sel],
						);
					}
				}
				let word = (block >> 16) as u16;
				for &(m1, m2, offset) in &matchers[2..4] {
					if m1 == word {
						verify_preliminary_match::<1, 1>(
							stream,
							search,
							addr,
							(m2, offset),
							[s3sel, s12sel],
						);
					}
				}
			}
		}
	}
}

fn verify_preliminary_match<const HALF: usize, const BLOCK: usize>(
	stream: &Bk7231RollingXor<impl Read>,
	search: &[u8],

	addr: u32,
	matcher: (u16, u8),
	selectors: [Option<u8>; 2],
) {
	// 1. get the block containing the previous word, with only stage3 applied
	let mut block = stream.input.0[BLOCK];
	block ^= selectors[0].map_or(0, |x| stream.s3out[x as usize].0[BLOCK]);
	// 2. apply all stage12 selectors to the other word
	for (s12sel, block) in all_selectors::<BLOCK>(&stream.s12out, block) {
		if matcher.0 != (block >> ((1 - HALF) * 16)) as u16 {
			continue;
		}
		let match_addr = addr + (HALF as u32 * 2) - 2 - (matcher.1 as u32);
		let selectors = match HALF {
			0 => [s12sel, selectors[1], selectors[0]],
			_ => [selectors[1], s12sel, selectors[0]],
		};
		// obtain the bytes of input belonging to the occurrence
		let mut input = [stream.input.0[1] ^ stream.input.0[0], stream.input.0[0]]
			.iter()
			.flat_map(|x| x.to_le_bytes())
			.skip((match_addr - (addr - 4)) as usize)
			.collect::<Vec<_>>();
		let prefix_len = input.len().min(search.len());
		input.resize(search.len(), 0);
		let read = stream
			.stream
			.borrow_mut()
			.peek(&mut input[prefix_len..])
			.expect("Failed to read from input image");
		if read < input.len() - prefix_len {
			continue;
		}
		// calculate/verify the key
		let keystream: Vec<_> = input.iter().zip(search).map(|(a, b)| a ^ b).collect();
		if let Some(key) = calculate_key(match_addr, selectors, &keystream) {
			let settings = crypto::format_settings_word(selectors);
			println!("Found match at {match_addr:#x} with key: 0 0 {key:x} {settings:x}")
		}
	}
}

fn calculate_key(addr: u32, selectors: [Option<u8>; 3], keystream: &[u8]) -> Option<u32> {
	let offset = addr & 3;
	let addr = addr & !3;
	let zero_keystream = (0..(offset + keystream.len() as u32 + 3) / 4)
		.flat_map(|x| crypto::encrypt(addr + 4 * x, selectors).to_le_bytes());
	let key_bytes = zero_keystream
		.skip(offset as usize)
		.zip(keystream)
		.map(|(a, b)| a ^ b);

	assert!(keystream.len() >= 4);
	let mut key = [0; 4];
	for (i, k) in key_bytes.enumerate() {
		if i >= 4 && key[(offset as usize + i) % 4] != k {
			return None;
		}
		key[(offset as usize + i) % 4] = k;
	}

	Some(u32::from_le_bytes(key))
}

fn main() {
	let args: Vec<_> = std::env::args().skip(1).collect();
	if args.len() != 3 {
		eprintln!("Usage: bk7231-calculator <image file> <base address in hex> <search string>");
		eprintln!("See the gist's README for more info.");
		std::process::exit(2);
	}
	let (image, base_addr, search_str) = (&args[0], &args[1], &args[2]);

	let base_addr = u32::from_str_radix(base_addr, 16).expect("invalid hex number");
	assert!(base_addr % 4 == 0, "base address is not aligned");

	let search_str = search_str.as_bytes();
	assert!(
		search_str.len() >= 9,
		"search string must be at least 9 bytes"
	);

	let image: Box<dyn Read> = if image == "-" {
		Box::new(stdin().lock())
	} else {
		let image = std::fs::OpenOptions::new().read(true).open(image);
		let image = image.expect("Failed to open image file");
		Box::new(BufReader::new(image))
	};

	let mut state = Bk7231RollingXor::new(PeekRead::new(image), base_addr);
	search(&mut state, search_str);
}
