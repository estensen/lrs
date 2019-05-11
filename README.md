# linkable-ring-signatures
Implementation of linkable ring signatures using elliptic curve cryptography in Go

## Getting Started

### Installing
To use start using the linkable ring signatures, install Go 1.10 or above and run `go get`:
```sh
$ go get https://github.com/estensen/linkable-ring-signatures/...
```

### Create keys
Before starting you have to generate the signers public and private keys and a folder with public keys. Create key pairs:
```sh
$ go run . --gen
```

### Sign a message
```sh
$ go run . --sign /path/to/pubkey/dir /path/to/privkey.priv message.txt
```

### Check if signature is valid
```sh
$ go run . --verify /path/to/signature.sig
```

### Check if signatures are created by the same private key
```sh
$ go run . --link /path/to/signature1.sig /path/to/signature2.sig
```

### Benchmark 1000 public keys
```sh
$ go run . --benchmark 1000
It took 792.335683ms to sign a ring with 1000 public keys
It took 788.610137ms to verify a ring with 1000 public keys
```

## References
This implementation is based on [ring-go](https://github.com/noot/ring-go) and the Monero paper [Ring Confidential Transactions](https://eprint.iacr.org/2015/1098.pdf)
