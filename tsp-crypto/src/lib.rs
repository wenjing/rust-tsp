use std::io::Write;

#[derive(Debug, PartialEq, Eq)]
pub struct Message<'a> {
    pub sender: &'a [u8; 32],
    pub receiver: &'a [u8; 32],
    pub header: &'a [u8],
    pub secret_message: &'a [u8],
}

impl Message<'_> {
    pub fn serialize_header(&self) -> Vec<u8> {
        let mut result = Vec::<u8>::with_capacity(64);

        result
            .write_all(&(self.header.len() as u16).to_be_bytes())
            .unwrap();
        result.write_all(self.sender).unwrap();
        result.write_all(self.receiver).unwrap();
        result.write_all(self.header).unwrap();

        result
    }
}

pub mod hpke;
pub mod nacl;
