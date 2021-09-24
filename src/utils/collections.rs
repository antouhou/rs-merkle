fn byte_to_hex(byte: &u8) -> String {
    format!("{:02x}", byte)
}

pub fn to_hex_string(bytes: &Vec<u8>) -> String {
    let hex_vec: Vec<String> = bytes
        .iter()
        .map(byte_to_hex)
        .collect();

    hex_vec.join("")
}

// IMPORTANT! This function doesn't use HashSet because for the tree
// it is important to maintain original order
pub fn difference(a: &Vec<usize>, b: &Vec<usize>) -> Vec<usize> {
    a.iter().cloned().filter(|x| !b.contains(x)).collect()
}
