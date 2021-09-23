use std::collections::HashSet;

pub fn to_hex_string(bytes: &Vec<u8>) -> String {
    let hex_vec: Vec<String> = bytes
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect();

    hex_vec.join("")
}

pub fn difference(a: &Vec<usize>, b: &Vec<usize>) -> Vec<usize> {
    let a: HashSet<usize> = a.iter().cloned().collect();
    let b: HashSet<usize> = b.iter().cloned().collect();

    a.difference(&b).cloned().collect()
}
