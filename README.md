# lrs
Implementation of linkable ring signatures using elliptic curve cryptography in Go. This prototype is research code and should not be used with sensitive data. It definitely has bugs!

## Getting Started

### Installing
To use start using the linkable ring signatures, install Go 1.12 or above and run `go get`:
```sh
$ go get ./...
$ go build
```

### Run all tests
```sh
$ go test ./...
```

### Create keys
Before starting you have to generate the signers public and private keys and a folder with public keys. Create key pairs:
```sh
$ lrs --gen
```

### Sign a message
```sh
$ lrs --sign /path/to/pubkey/dir /path/to/privkey.priv message.txt
```

### Check if signature is valid
```sh
$ lrs --verify /path/to/signature.sig
```

### Check if signatures are created by the same private key
```sh
$ lrs --link /path/to/signature1.sig /path/to/signature2.sig
```

### Benchmark 1000 public keys
```sh
$ lrs --benchmark 10
Linked ring signature:
Total avg sign time was 0.009010(0.000303)
Total avg verify time was 0.008033(0.000261)
Simple ECC signature:
Total avg sign time was 0.0001060737(0.0000261440)
Total avg verify time was 0.0000000465(0.0000000083)
```

## References
This implementation is based on [ring-go](https://github.com/noot/ring-go) and the Monero paper [Ring Confidential Transactions](https://eprint.iacr.org/2015/1098.pdf)
