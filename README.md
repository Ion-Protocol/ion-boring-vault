## Foundry

**Foundry is a blazing fast, portable and modular toolkit for Ethereum application development written in Rust.**

Foundry consists of:

- **Forge**: Ethereum testing framework (like Truffle, Hardhat and DappTools).
- **Cast**: Swiss army knife for interacting with EVM smart contracts, sending transactions and getting chain data.
- **Anvil**: Local Ethereum node, akin to Ganache, Hardhat Network.
- **Chisel**: Fast, utilitarian, and verbose solidity REPL.

## Documentation

https://book.getfoundry.sh/

## Usage

### Build

```shell
$ forge build
```

### Test

```shell
$ forge test
```

### Format

```shell
$ forge fmt
```

### Gas Snapshots

```shell
$ forge snapshot
```

### Anvil

```shell
$ anvil
```

### Deploy

```shell
$ forge script script/Counter.s.sol:CounterScript --rpc-url <your_rpc_url> --private-key <your_private_key>
```

### Cast

```shell
$ cast <subcommand>
```

### Help

```shell
$ forge --help
$ anvil --help
$ cast --help
```

### Zokrates

To update manage verifier

```shell
$ zokrates compile -i zokrates/manage_verifier.zok -o zokrates/output/manage_verifier -r zokrates/output/manage_verifier.r1cs -s zokrates/output/manage_verifier.json
$ zokrates setup -i zokrates/output/manage_verifier -p zokrates/output/manage_verifier_proving.key -v zokrates/output/manage_verifier_verification.key
$ zokrates export-verifier -i zokrates/output/manage_verifier_verification.key -o zokrates/output/ManagerVerifier.sol
```

To update shuffled tree verifier

```shell
zokrates compile -i zokrates/shuffled_tree_verifier.zok -o zokrates/output/shuffled_tree_verifier -r zokrates/output/shuffled_tree_verifier.r1cs -s zokrates/output/shuffled_tree_verifier.json
$ zokrates setup -i zokrates/output/shuffled_tree_verifier -p zokrates/output/shuffled_tree_verifier_proving.key -v zokrates/output/shuffled_tree_verifier_verification.key
$ zokrates export-verifier -i zokrates/output/shuffled_tree_verifier_verification.key -o zokrates/output/Root64Verifier.sol
```
