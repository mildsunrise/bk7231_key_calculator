use std::{collections::VecDeque, io::{Read, Write}, ops::BitXor};

/// Offers peek functionality on top of a reader.
/// (I can do away with this once [BufReader::peek] stabilises)
pub struct PeekRead<R> {
	inner: R,
	buffer: VecDeque<u8>,
}

impl<R: Read> PeekRead<R> {
	pub fn new(inner: R) -> Self {
		Self { inner, buffer: VecDeque::new() }
	}

	pub fn peek(&mut self, mut buf: &mut [u8]) -> std::io::Result<usize> {
		let mut written = 0;
		written += buf.write(self.buffer.as_slices().0).unwrap();
		written += buf.write(self.buffer.as_slices().1).unwrap();
		let read = self.inner.read(buf)?;
		self.buffer.write(&buf[..read]).unwrap();
		Ok(written + read)
	}
}

impl<R: Read> Read for PeekRead<R> {
	fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
		let read = self.buffer.read(buf).unwrap();
		Ok(read + self.inner.read(&mut buf[read..])?)
	}
}

/// takes a stream of words X(i) and provides the last two words of the stream Y(i) = X(i) ⊕ X(i-1)
#[derive(Clone, Copy, Default, PartialEq, Eq)]
pub struct RollingXor<T>(pub [T; 3]);

impl<T: Copy + BitXor<Output = T>> RollingXor<T> {
	pub fn update(&mut self, x: T) {
		self.0[2] = self.0[1];
		self.0[1] = self.0[0] ^ x;
		self.0[0] = x;
	}
}
