use std::{borrow::Borrow, ops::BitXor};

pub fn u8_to_u32(xs: &[u8]) -> Vec<u32> {
	xs.chunks_exact(4)
		.map(|x| u32::from_le_bytes(x.try_into().unwrap()))
		.collect()
}

pub fn u32_to_u8(xs: &[u32]) -> Vec<u8> {
	xs.iter().flat_map(|&x| x.to_le_bytes()).collect()
}

pub fn xor_iter<T, Xs, Ys>(xs: Xs, ys: Ys) -> Vec<T>
where
	T: BitXor<Output = T> + Copy,
	Xs: IntoIterator,
	Ys: IntoIterator,
	Xs::Item: Borrow<T>,
	Ys::Item: Borrow<T>,
{
	xs.into_iter()
		.zip(ys)
		.map(|(x, y)| (*x.borrow()) ^ (*y.borrow()))
		.collect()
}
