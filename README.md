# rs-merkle

[![Rayon crate](https://img.shields.io/crates/v/rs_merkle.svg)](https://crates.io/crates/rs_merkle)
[![Rayon documentation](https://docs.rs/rs_merkle/badge.svg)](https://docs.rs/rs_merkle)
[![Build and test](https://github.com/antouhou/rs-merkle/actions/workflows/test.yml/badge.svg?branch=master)](https://github.com/antouhou/rs-merkle/actions)

rs-merkle is the most advanced Merkle Tree library for Rust.
Basic features include building a merkle tree, 
creation and verification of merkle proofs, including multi-proofs.
Advanced features include making transactional changes to a tree and rolling 
back to any previous committed tree state. 
This scenario is similar to Git and can be found in databases and file systems.

Rs-merkle is
[available on crates.io](https://crates.io/crates/rs_merkle), and 
[API Documentation is available on docs.rs](https://docs.rs/rs_merkle/).

## About merkle trees

Merkle Trees, also known as Hash Trees, are used to verify that two or more 
parties have the same data without exchanging the entire data collection.

Merkle Trees are used in Git, Mercurial, ZFS, IPFS, Bitcoin, Ethereum, Cassandra 
and many more. In Git, for example, Merkle Trees are used to find a delta 
between the local and remote repository states to transfer only the difference 
between them over the network. In Bitcoin, Merkle Trees are used to verify that 
a transaction was included into the block without downloading the whole block 
contents.

## Usage

Add the following to your `Cargo.toml`:

```toml
[dependencies]
rs_merkle = "0.2"
```

## Documentation

[Documentation is available on docs.rs](https://docs.rs/rs_merkle/).

## Contributing

Everyone is welcome to contribute in any way of form! For the further details, please read [CONTRIBUTING.md](./CONTRIBUTING.md)

## Authors
- [Anton Suprunchuk](https://github.com/antouhou) - [Website](https://antouhou.com)

Also, see the list of contributors who participated in this project.

## License

This project is licensed under the MIT License - see the [LICENSE.md](./LICENSE.md) file for details