use std::io::Write;

#[derive(Debug, PartialEq, Eq)]
pub struct Message<'a> {
    pub sender: &'a [u8; 32],
    pub receiver: &'a [u8; 32],
    pub header: &'a [u8],
    pub secret_message: Vec<u8>,
}

impl Message<'_> {
    #[allow(dead_code)]
    fn serialize_header(&self) -> Vec<u8> {
        let mut result = Vec::<u8>::with_capacity(64);

        result
            .write_all(&(self.header.len() as u16).to_be_bytes())
            .unwrap();
        result.write_all(self.sender).unwrap();
        result.write_all(self.receiver).unwrap();
        result.write_all(self.header).unwrap();

        result
    }

    fn cesr_header(&self) -> Vec<u8> {
        use tsp_cesr::*;
        let mut result = Vec::with_capacity(64);
        encode_envelope(
            Envelope {
                sender: self.sender,
                receiver: self.receiver,
                nonconfidential_header: Some(self.header),
            },
            &mut result,
        )
        .expect("error encoding the envelope");

        result
    }
}

pub mod hpke;
pub mod nacl;
