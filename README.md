# rs_merkle

`rs_merkle` is the most advanced Merkle Tree library for Rust.

Basic features include creation and verification of merkle proofs from a set of leaves.
This is often done in various cryptocurrencies.

Advanced features include being able to make transactional changes to a tree with
being able to roll back to any previous committed state of tree. This scenario is similar
to Git and can be found in databases and file systems.

Merkle Trees, also known as Hash Trees, are used to verify that two or more parties have
the same data without exchanging the entire data collection.

Merkle Trees are used in Git, Mercurial,ZFS, IPFS, Bitcoin, Ethereum, Cassandra and many more.
In Git, for example, Merkle Trees are used to find a delta between the local and remote states,
and transfer only the delta. In Bitcoin, Merkle Trees are used to verify that a transaction was
included into the block without downloading the whole block contents.