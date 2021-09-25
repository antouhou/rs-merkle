fn byte_to_hex(byte: &u8) -> String {
    format!("{:02x}", byte)
}

pub fn to_hex_string<T: Clone + Into<Vec<u8>>>(bytes: &T) -> String {
    // let keks: Vec<u8> = bytes.clone().into();

    let hex_vec: Vec<String> = bytes.clone().into()
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

fn combine<T: Clone>(active: Vec<T>, rest: Vec<T>, mut combinations: Vec<Vec<T>>) -> Vec<Vec<T>> {
    return if rest.is_empty() {
        if active.is_empty() {
            combinations
        } else {
            combinations.push(active);
            combinations
        }
    } else {
        let mut next = active.clone();
        next.push(rest.get(0).unwrap().clone());

        combinations = combine(next, rest.clone().drain(1..).collect(), combinations);
        combinations = combine(active, rest.clone().drain(1..).collect(), combinations);
        combinations
    }
}

pub fn combinations<T: Clone>(vec: Vec<T>) -> Vec<Vec<T>> {
    combine(Vec::new(), vec, Vec::new())
}
