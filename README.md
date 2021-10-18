# rs-merkle

[![Rayon crate](https://img.shields.io/crates/v/rs_merkle.svg)](https://crates.io/crates/rs_merkle)
[![Rayon documentation](https://docs.rs/rs_merkle/badge.svg)](https://docs.rs/rs_merkle)
[![Build and test](https://github.com/antouhou/rs-merkle/actions/workflows/test.yml/badge.svg?branch=master)](https://github.com/antouhou/rs-merkle/actions)

`rs-merkle` is the most advanced Merkle tree library for Rust. Basic features 
include building a Merkle tree, creation, and verification of Merkle proofs for 
single and several elements, i.e. multi-proofs. Advanced features include making 
transactional changes to the tree and rolling back to any previously committed 
tree state, similarly to Git.

The library is highly customizable. Hashing function and the way how the tree 
is built can be easily configured through a special trait.

`rs-merkle` is
[available on crates.io](https://crates.io/crates/rs_merkle), and 
[API Documentation is available on docs.rs](https://docs.rs/rs_merkle/).

## About Merkle trees

Merkle trees, also known as hash trees, are used to verify that two or more 
parties have the same data without exchanging the entire data collection.

Merkle trees are used in Git, Mercurial, ZFS, IPFS, Bitcoin, Ethereum, Cassandra,
and many more. In Git, for example, Merkle trees are used to find a delta 
between the local and remote repository states to transfer only the difference 
between them over the network. In Bitcoin, Merkle trees are used to verify that 
a transaction was included in the block without downloading the whole block 
contents. ZFS uses Merkle trees to quickly verify data integrity, offering 
protection from silent data corruption caused by phantom writes, bugs in disk 
firmware, power surges, and other causes.

## Usage

Add the following to your `Cargo.toml`:

```toml
[dependencies]
rs_merkle = "0.2"
```

## Documentation

[Documentation is available on docs.rs](https://docs.rs/rs_merkle/).

## Contributing

Everyone is welcome to contribute in any way or form! For further details, 
please read [CONTRIBUTING.md](./CONTRIBUTING.md)

## Authors
- [Anton Suprunchuk](https://github.com/antouhou) - [Website](https://antouhou.com)

Also, see the list of contributors who participated in this project.

## License

This project is licensed under the MIT License - see the 
[LICENSE.md](./LICENSE.md) file for details