use std::fs::File;
use std::io::{Read, Result};

pub struct ChunkedFileReader<'file> {
	file: &'file mut File,
	file_len: u64,
	bytes_read: u64,
	chunk_size: u64,
}

// Body => 1 or more chunks to go;
// Final => This is the last chunk. Contains bytes read, which is likely less
// than chunk size
// Err => Error containing error message
pub enum ChunkStatus {
	Body,
	Final(u64),
	Err(&'static str),
}

impl<'file> ChunkedFileReader<'file> {
	pub fn new(file: &'file mut File, chunk_size: u64, file_len: Option<u64>) -> Self {
		// If the file_length is specified, then use that. Otherwise calculate
		// it from the file itself.
		let file_len = match file_len {
			Some(len) => len,
			None => file.metadata().unwrap().len(),
		};
		ChunkedFileReader {
			file,
			file_len,
			bytes_read: 0,
			chunk_size,
		}
	}
	// buff must be >= chunk size
	pub fn read_chunk(&mut self, buff: &mut [u8]) -> Result<ChunkStatus> {
		if self.bytes_read > self.file_len {
			Ok(ChunkStatus::Err("Trying to read past final file chunk."))
		} else if self.chunk_size > buff.len() as u64 {
			Ok(ChunkStatus::Err("Buffer is too small to fit a file chunk."))
		} else {
			let bytes_to_read = self.file_len - self.bytes_read;
			// Check if there are CHUNK_SIZE bytes left within the file. If
			// there isn't set chunk_size to whatever is left.
			let (chunk_size, result) = if bytes_to_read > self.chunk_size as u64 {
				(self.chunk_size, ChunkStatus::Body)
			} else {
				(bytes_to_read, ChunkStatus::Final(bytes_to_read))
			};
			// Read in chunk_size bytes
			self.file.read_exact(&mut buff[..chunk_size as usize])?;
			// Add chunk_size bytes to the bytes_read counter for the next call
			self.bytes_read += chunk_size;
			match result {
				// Make sure we have read in all the bytes we are supposed to.
				ChunkStatus::Final(_) => {
					assert_eq!(self.bytes_read, self.file_len);
				}
				_ => (),
			}
			Ok(result)
		}
	}
}
