# RSA related files can be safe deleted

Currently the implementation is not working, it's a POC for RSA verification using syscall and rsa crate.

- The big_mod_exp syscall it's not available on mainnet/devnet.
- The rsa_crate implementation run out of CU
- Running the rsa_verification over multiple transacions exceeds solana memory limit.

- See: https://github.com/Pessina/solana-aa/issues/13
