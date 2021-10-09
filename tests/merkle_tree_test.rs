mod common;

pub mod root {
    use crate::common;
    use rs_merkle::{algorithms::Sha256, MerkleTree};

    #[test]
    pub fn should_return_a_correct_root() {
        let test_data = common::setup();

        let merkle_tree = MerkleTree::<Sha256>::from_leaves(&test_data.leaf_hashes);
        let hex_root = merkle_tree.root_hex().unwrap();

        assert_eq!(hex_root, test_data.expected_root_hex);
    }
}

pub mod tree_depth {
    use crate::common;
    use rs_merkle::{algorithms::Sha256, MerkleTree};

    #[test]
    pub fn should_return_a_correct_tree_depth() {
        let test_data = common::setup();

        let merkle_tree = MerkleTree::<Sha256>::from_leaves(&test_data.leaf_hashes);

        let depth = merkle_tree.depth();
        assert_eq!(depth, 3)
    }
}

pub mod proof {
    use crate::common;
    use rs_merkle::{algorithms::Sha256, MerkleTree};

    #[test]
    pub fn should_return_a_correct_proof() {
        let test_data = common::setup();
        let indices_to_prove = vec![3, 4];
        let expected_proof_hashes = [
            "2e7d2c03a9507ae265ecf5b5356885a53393a2029d241394997265a1a25aefc6",
            "252f10c83610ebca1a059c0bae8255eba2f95be4d1d7bcfa89d7248a82d9f111",
            "e5a01fee14e0ed5c48714f22180f25ad8365b53f9779f79dc4a3d7e93963f94a",
        ];

        let merkle_tree = MerkleTree::<Sha256>::from_leaves(&test_data.leaf_hashes);
        let proof = merkle_tree.proof(&indices_to_prove);
        let proof_hashes = proof.hex_proof_hashes();

        assert_eq!(proof_hashes, expected_proof_hashes)
    }
}

pub mod commit {
    use crate::common;
    use rs_merkle::{algorithms::Sha256, Hasher, MerkleTree};

    #[test]
    pub fn should_give_correct_root_after_commit() {
        let test_data = common::setup();
        let expected_root = test_data.expected_root_hex.clone();
        let leaf_hashes = &test_data.leaf_hashes;
        // let indices_to_prove = vec![3, 4];
        // let leaves_to_prove = indices_to_prove.iter().cloned().map(|i| leaf_hashes.get(i).unwrap().clone()).collect();
        let vec = Vec::<[u8; 32]>::new();

        // Passing empty vec to create an empty tree
        let mut merkle_tree = MerkleTree::<Sha256>::from_leaves(&vec);
        let mut merkle_tree2 = MerkleTree::<Sha256>::from_leaves(&leaf_hashes);
        // Adding leaves
        merkle_tree.append(leaf_hashes.clone().as_mut());
        let root = merkle_tree.uncommitted_root_hex().unwrap();

        assert_eq!(merkle_tree2.root_hex().unwrap(), expected_root);
        assert_eq!(root, expected_root);

        let expected_root = "e2a80e0e872a6c6eaed37b4c1f220e1935004805585b5f99617e48e9c8fe4034";
        let leaf = Sha256::hash("g".as_bytes().to_vec().as_ref());
        merkle_tree.insert(leaf);

        assert_eq!(
            merkle_tree.uncommitted_root_hex().unwrap(),
            String::from(expected_root)
        );

        // No changes were committed just yet, tree is empty
        assert_eq!(merkle_tree.root(), None);

        merkle_tree.commit();

        let mut new_leaves = vec![
            Sha256::hash("h".as_bytes().to_vec().as_ref()),
            Sha256::hash("k".as_bytes().to_vec().as_ref()),
        ];
        merkle_tree.append(&mut new_leaves);

        assert_eq!(
            merkle_tree.root_hex().unwrap(),
            String::from("e2a80e0e872a6c6eaed37b4c1f220e1935004805585b5f99617e48e9c8fe4034")
        );
        assert_eq!(
            merkle_tree.uncommitted_root_hex().unwrap(),
            String::from("09b6890b23e32e607f0e5f670ab224e36af8f6599cbe88b468f4b0f761802dd6")
        );

        merkle_tree.commit();
        let leaves = merkle_tree.leaves().unwrap();
        let reconstructed_tree = MerkleTree::<Sha256>::from_leaves(&leaves);

        // Check that the commit is applied correctly
        assert_eq!(
            reconstructed_tree.root_hex().unwrap(),
            String::from("09b6890b23e32e607f0e5f670ab224e36af8f6599cbe88b468f4b0f761802dd6")
        );
        assert_eq!(reconstructed_tree.layers(), merkle_tree.layers());
    }
}

pub mod rollback {
    use crate::common;
    use rs_merkle::{algorithms::Sha256, Hasher, MerkleTree};

    pub fn should_rollback_previous_commit() {
        let leaf_values = ["a", "b", "c", "d", "e", "f"];
        let expected_root_hex = "1f7379539707bcaea00564168d1d4d626b09b73f8a2a365234c62d763f854da2";
        let leaves: Vec<[u8; 32]> = leaf_values
            .iter()
            .map(|x| Sha256::hash(x.as_bytes().to_vec().as_ref()))
            .collect();

        let mut merkle_tree: MerkleTree<Sha256> = MerkleTree::new();
        merkle_tree.append(leaves.clone().as_mut());
        // No changes were committed just yet, tree is empty
        assert_eq!(merkle_tree.root(), None);

        merkle_tree.commit();

        assert_eq!(
            merkle_tree.uncommitted_root_hex().unwrap(),
            String::from("1f7379539707bcaea00564168d1d4d626b09b73f8a2a365234c62d763f854da2")
        );

        // Adding a new leaf
        merkle_tree.insert(Sha256::hash("g".as_bytes().to_vec().as_ref()));

        // Uncommitted root must reflect the insert
        assert_eq!(
            merkle_tree.uncommitted_root_hex().unwrap(),
            String::from("e2a80e0e872a6c6eaed37b4c1f220e1935004805585b5f99617e48e9c8fe4034")
        );

        merkle_tree.commit();

        // After calling commit, uncommitted root will become committed
        assert_eq!(
            merkle_tree.root_hex().unwrap(),
            String::from("e2a80e0e872a6c6eaed37b4c1f220e1935004805585b5f99617e48e9c8fe4034")
        );

        // Adding some more leaves
        merkle_tree.append(
            vec![
                Sha256::hash("h".as_bytes().to_vec().as_ref()),
                Sha256::hash("k".as_bytes().to_vec().as_ref()),
            ]
            .as_mut(),
        );

        // Checking that the uncommitted root has changed, but the committed one hasn't
        assert_eq!(
            merkle_tree.uncommitted_root_hex().unwrap(),
            String::from("09b6890b23e32e607f0e5f670ab224e36af8f6599cbe88b468f4b0f761802dd6")
        );
        assert_eq!(
            merkle_tree.root_hex().unwrap(),
            String::from("e2a80e0e872a6c6eaed37b4c1f220e1935004805585b5f99617e48e9c8fe4034")
        );

        merkle_tree.commit();

        // Checking committed changes again
        assert_eq!(
            merkle_tree.root_hex().unwrap(),
            String::from("09b6890b23e32e607f0e5f670ab224e36af8f6599cbe88b468f4b0f761802dd6")
        );

        merkle_tree.rollback();

        // Check that we rolled one commit back
        assert_eq!(
            merkle_tree.root_hex().unwrap(),
            String::from("e2a80e0e872a6c6eaed37b4c1f220e1935004805585b5f99617e48e9c8fe4034")
        );

        merkle_tree.rollback();

        // Rolling back to the state after the very first commit
        assert_eq!(merkle_tree.root_hex().unwrap(), expected_root_hex);
    }
}
