mod crypto;
mod utils;

use std::io::Read;
use utils::*;

fn search(image: Vec<u8>, addr: u32, search: &[u8]) {
	if image.len() % 4 != 0 {
		eprintln!("Warning: leftover block in image");
	}
	let image = u8_to_u32(&image);

	let (head, matcher) = search.split_at(4);
	let matcher: Vec<u8> = xor_iter(matcher, search);

	let selector_values = (0..4).map(Some).chain([None]).collect::<Vec<_>>();

	for &sel1 in &selector_values {
		for &sel2 in &selector_values {
			for &sel3 in &selector_values {
				let selectors = [sel1, sel2, sel3];
				let image = xor_iter(&image, crypto::keystream(selectors, addr));

				let preproc_image = u32_to_u8(&xor_iter(&image, &image[1..]));
				let image = u32_to_u8(&image);

				let settings = crypto::format_settings_word(selectors);
				for hit in memchr::memmem::find_iter(&preproc_image, &matcher) {
					let key = xor_iter(&image[hit..], head);
					let key = u32::from_le_bytes(key.try_into().unwrap());
					let key = key.rotate_left((hit % 4) as u32 * 8);
					println!("Found match at {hit:#x} with key: 0 0 {key:x} {settings:x}")
				}
			}
		}
	}
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
		search_str.len() >= 8,
		"search string must be at least 8 bytes"
	);

	let image = (if image == "-" {
		let mut buf = vec![];
		std::io::stdin().read_to_end(&mut buf).and(Ok(buf))
	} else {
		std::fs::read(image)
	})
	.expect("failed to read image to memory");

	search(image, base_addr, search_str);
}
