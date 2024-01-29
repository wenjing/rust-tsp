static BASE64_ENCODE: [u8; 64] =
    *b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
static BASE64_DECODE: [u8; 124] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 62, 0, 0, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 0, 0,
    0, 0, 0, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21,
    22, 23, 24, 25, 0, 0, 0, 0, 63, 0, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
    41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52,
];

fn encode_bytes(data: &[u8]) -> Vec<u8> {
    let len = data.len().next_multiple_of(3);
    let padding = len - data.len();
    let mut result = Vec::with_capacity(len + 3);
    let [len1, len2] = ((len / 3) as u16).to_be_bytes();

    match padding {
        0 => result.extend_from_slice(&[0xe0, 0x10 ^ len1, len2]),
        1 => result.extend_from_slice(&[0xe4, 0x10 ^ len1, len2, 0x00]),
        2 => result.extend_from_slice(&[0xe8, 0x10 ^ len1, len2, 0x00, 0x00]),
        _ => unreachable!(),
    }

    result.extend_from_slice(data);

    result
}

fn decode_bytes(data: &[u8]) -> Vec<u8> {
    let padding = match (data[0], data[1]) {
        _ if (data[0] == 0xe0) && (data[1] >> 4) == 0x1 => 0,
        _ if (data[0] == 0xe4) && (data[1] >> 4) == 0x1 => 1,
        _ if (data[0] == 0xe8) && (data[1] >> 4) == 0x1 => 2,
        _ => unreachable!(),
    };

    let len = (u16::from_be_bytes([data[1] & 0x0f, data[2]]) * 3) as usize;

    data[(3 + padding)..(3 + len)].to_vec()
}

#[cfg(test)]
mod tests {
    use crate::cesr::{decode_bytes, encode_bytes, BASE64_DECODE, BASE64_ENCODE};

    #[test]
    fn roundtrip() {
        for i in 0..64 {
            assert_eq!(i, BASE64_DECODE[BASE64_ENCODE[i] as usize] as usize);
        }

        for b in [
            "d".as_bytes(),
            "Hq".as_bytes(),
            "8Cv".as_bytes(),
            "uhP1".as_bytes(),
            "A7j1v".as_bytes(),
            "ghPyDb".as_bytes(),
            "2BXB2wQ".as_bytes(),
            "teMdKy9gOEhbn".as_bytes(),
            "izvVT11bMWZBzzos".as_bytes(),
            "0S9QuhaDWc0PayFlNsr2".as_bytes(),
            "lol".repeat(100).as_bytes(),
            "lol".repeat(200).as_bytes(),
            "lol".repeat(500).as_bytes(),
            "lol".repeat(1000).as_bytes(),
        ] {
            assert_eq!(b, decode_bytes(&encode_bytes(&b)));
        }
    }

    #[test]
    fn encode_binary() {
        assert_eq!(
            encode_bytes(b"1337"),
            [0xe8, 0x10, 0x02, 0x00, 0x00, 0x31, 0x33, 0x33, 0x37]
        );
    }
}
