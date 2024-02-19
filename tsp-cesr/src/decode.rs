use super::{bits, extract_triplet, header_match, mask};

/// Decode fixed size data with a known identifier
pub fn decode_fixed_data<'a, const N: usize>(
    identifier: u32,
    stream: &mut &'a [u8],
) -> Option<&'a [u8; N]> {
    let total_size = (N + 1).next_multiple_of(3);
    let hdr_bytes = total_size - N;

    let word = match hdr_bytes {
        1 => bits(identifier, 6) << 18,
        2 => 52 << 18 | bits(identifier, 6) << 12,
        3 => 53 << 18 | bits(identifier, 18),
        _ => unreachable!("unsigned integer arithmetic is broken"),
    };

    if header_match(
        stream.get(0..hdr_bytes)?,
        &u32::to_be_bytes(word)[1..=hdr_bytes],
    ) {
        let slice = stream.get(hdr_bytes..total_size)?;
        *stream = &stream[total_size..];

        Some(slice.try_into().unwrap())
    } else {
        None
    }
}

/// Decode variable size data with a known identifier
pub fn decode_variable_data<'a>(identifier: u32, stream: &mut &'a [u8]) -> Option<&'a [u8]> {
    let input = extract_triplet(stream.get(0..=2)?.try_into().unwrap());
    let selector = input >> 18;

    let size;
    let found_id;

    match selector {
        56..=58 => {
            found_id = input >> 12 & mask(6);
            size = input & mask(12);
        }
        59..=61 => {
            found_id = input & mask(18);
            size = extract_triplet(stream.get(3..6)?.try_into().unwrap());
        }
        _ => return None,
    };

    if found_id == identifier {
        let offset = (selector - 56) as usize;
        let data_begin = offset + 3;
        let data_end = (offset + 1).next_multiple_of(3) + 3 * size as usize;
        let slice = stream.get(data_begin..data_end)?;
        *stream = &stream[data_end..];

        Some(slice)
    } else {
        None
    }
}

/// Decode indexed data with a known identifier
pub fn decode_indexed_data<'a, const N: usize>(
    identifier: u32,
    stream: &mut &'a [u8],
) -> Option<(u16, &'a [u8; N])> {
    let total_size = (N + 1).next_multiple_of(3);
    let hdr_bytes = total_size - N;

    let input = extract_triplet(stream.get(0..=2)?.try_into().unwrap());
    let word;
    let index;

    match hdr_bytes {
        1 => panic!("an indexed type can only have 0 or 2 lead bytes"),
        2 => {
            index = input >> 12 & mask(6);
            word = bits(identifier, 6) << 18 | bits(index, 6) << 12;
        }
        3 => {
            index = input & mask(12);
            word = 52 << 18 | bits(identifier, 6) << 12 | bits(index, 12);
        }
        _ => unreachable!("unsigned integer arithmetic is broken"),
    };

    if header_match(
        stream.get(0..hdr_bytes)?,
        &u32::to_be_bytes(word)[1..=hdr_bytes],
    ) {
        let slice = stream.get(hdr_bytes..total_size)?;
        *stream = &stream[total_size..];

        Some((index as u16, slice.try_into().unwrap()))
    } else {
        None
    }
}

/// Decode a frame with known identifier and size
pub fn decode_count(identifier: u16, stream: &mut &[u8]) -> Option<u16> {
    let word = extract_triplet(stream.get(0..=2)?.try_into().unwrap());
    let index = word & mask(12);

    let expected = 62 << 18 | bits(identifier, 6) << 12 | bits(index, 12);
    if word == expected {
        *stream = &stream[3..];

        Some(index as u16)
    } else {
        None
    }
}

/// Decode a genus with known identifier and version
pub fn decode_genus(
    genus: [u8; 3],
    (major, minor, patch): (u8, u8, u8),
    stream: &mut &[u8],
) -> Option<()> {
    let version = bits(major, 6) << 12 | bits(minor, 6) << 6 | bits(patch, 6);
    let word1 = 62 << 18 | 62 << 12 | bits(genus[0], 6) << 6 | bits(genus[1], 6);
    let word2 = bits(genus[2], 6) << 18 | version;

    (extract_triplet(stream.get(0..3)?.try_into().unwrap()) == word1).then_some(())?;
    (extract_triplet(stream.get(3..6)?.try_into().unwrap()) == word2).then_some(())?;
    *stream = &stream[6..];

    Some(())
}
