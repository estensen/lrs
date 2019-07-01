package main

import (
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"math"
	"math/big"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/estensen/lrs/ring"

	"github.com/ethereum/go-ethereum/crypto"
	"golang.org/x/crypto/blake2b"
)

func main() {
	genPtr := flag.Bool("gen", false, "generate a new public-private keypair")
	signPtr := flag.Bool("sign", false, "sign a message with a ring signature")
	verifyPtr := flag.Bool("verify", false, "verify a ring signature")
	linkablePtr := flag.Bool("linkable", false, "check if signatures are linkable")
	benchmarkPtr := flag.Bool("benchmark", false, "benchmark sign, verify and storage space")

	if len(os.Args) < 2 {
		flag.PrintDefaults()
		os.Exit(0)
	}

	flag.Parse()

	if *genPtr {
		gen()
	} else if *signPtr {
		sign()
	} else if *verifyPtr {
		verify()
	} else if *linkablePtr {
		linkable()
	} else if *benchmarkPtr {
		benchmark()
	}
}

// Generate a new public-private keypair and save in ./keystore directory
func gen() {
	priv, err := crypto.GenerateKey()
	if err != nil {
		log.Fatal(err)
	}

	pub := priv.Public().(*ecdsa.PublicKey)

	fp, err := filepath.Abs("./keystore")
	if _, err := os.Stat(fp); os.IsNotExist(err) {
		os.Mkdir("./keystore", os.ModePerm)
	}

	fp, err = filepath.Abs(fmt.Sprintf("./keystore/%d.priv", time.Now().Unix()))
	if err != nil {
		log.Fatal(err)
	}
	err = ioutil.WriteFile(fp, []byte(fmt.Sprintf("%x", priv.D.Bytes())), 0644)
	if err != nil {
		log.Fatal(err)
	}

	name := time.Now().Unix()
	fp, err = filepath.Abs(fmt.Sprintf("./keystore/%d.pub", name))
	if err != nil {
		log.Fatal(err)
	}
	err = ioutil.WriteFile(fp, []byte(fmt.Sprintf("%x%x", pub.X, pub.Y)), 0644)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("output saved to ./keystore/%d\n", name)
	os.Exit(0)
}

func sign() {
	if len(os.Args) < 2 {
		fmt.Println("need to supply path to public key directory: go run . --sign /path/to/pubkey/dir /path/to/privkey.priv message.txt")
		os.Exit(0)
	}

	if len(os.Args) < 3 {
		fmt.Println("need to supply path to private key file: go run . --sign /path/to/pubkey/dir /path/to/privkey.priv message.txt")
		os.Exit(0)
	}

	if len(os.Args) < 4 {
		fmt.Println("need to supply path to message file: go run . --sign /path/to/pubkey/dir /path/to/privkey.priv message.txt")
		os.Exit(0)
	}

	// Read public keys and put them in a ring
	fp, err := filepath.Abs(os.Args[2])
	if err != nil {
		log.Fatal("could not read key from ", os.Args[2], "\n", err)
	}
	files, err := ioutil.ReadDir(fp)
	if err != nil {
		log.Fatal(err)
	}

	if len(files) == 0 {
		log.Fatalf("no public keys from in %s", os.Args[2])
	}

	pubkeys := make([]*ecdsa.PublicKey, len(files))

	for i, file := range files {
		fp, err = filepath.Abs(fmt.Sprintf("%s/%s", os.Args[2], file.Name()))
		key, err := ioutil.ReadFile(fp)
		if err != nil {
			log.Fatal("could not read key from ", fp, "\n", err)
		}

		keyStr := string(key)

		fmt.Printf("%s:%s\n", file.Name(), keyStr)

		if len(keyStr) < 128 {
			log.Fatalf("public key %s invalid", file.Name())
		}

		var ok bool
		pub := new(ecdsa.PublicKey)
		pub.Curve = crypto.S256()
		pub.X, ok = new(big.Int).SetString(keyStr[0:64], 16)
		if !ok {
			log.Fatalf("could not convert string to public key")
		}
		pub.Y, ok = new(big.Int).SetString(keyStr[64:128], 16)
		if !ok {
			log.Fatalf("could not convert string to public key")
		}

		fmt.Printf("%s.X:%x\n", file.Name(), pub.X)
		fmt.Printf("%s.Y:%x\n", file.Name(), pub.Y)

		pubkeys[i] = pub
	}

	// Handle secret key and generate ring of pubkeys
	fp, err = filepath.Abs(os.Args[3])
	privBytes, err := ioutil.ReadFile(fp)
	if err != nil {
		log.Fatal("could not read key from ", fp, "\n", err)
	}

	priv := new(ecdsa.PrivateKey)
	priv.Curve = crypto.S256()
	priv.D = big.NewInt(0).SetBytes(privBytes[0:32])

	priv.PublicKey.Curve = priv.Curve
	priv.PublicKey.X, priv.PublicKey.Y = priv.Curve.ScalarBaseMult(priv.D.Bytes())

	fmt.Printf("secret.pub:%x%x\n", priv.X, priv.Y)

	// Create a random index for the signer
	sb, err := rand.Int(rand.Reader, new(big.Int).SetInt64(int64(len(pubkeys))))
	if err != nil {
		log.Fatal(err)
	}
	s := int(sb.Int64())

	r, err := ring.GenKeyRing(pubkeys, priv, s)
	if err != nil {
		log.Fatal(err)
	}

	fp, err = filepath.Abs(os.Args[4])
	msgBytes, err := ioutil.ReadFile(fp)
	if err != nil {
		log.Fatal("could not read key from ", fp, "\n", err)
	}

	msgHash := blake2b.Sum256(msgBytes)

	sig, err := ring.Sign(msgHash, r, priv, s)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("signature successfully generated!")

	fp, err = filepath.Abs("./signatures")
	if _, err := os.Stat(fp); os.IsNotExist(err) {
		os.Mkdir("./signatures", os.ModePerm)
	}

	name := time.Now().Unix()
	fp, err = filepath.Abs(fmt.Sprintf("./signatures/%d.sig", name))
	if err != nil {
		log.Fatal(err)
	}

	serializedSig, err := sig.Serialize()
	if err != nil {
		log.Fatal(err)
	}

	err = ioutil.WriteFile(fp, []byte(fmt.Sprintf("%x", serializedSig)), 0644)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("output saved to ./signatures/%d.sig\n", name)
	os.Exit(0)
}

func verify() {
	if len(os.Args) < 3 {
		fmt.Println("need to supply path to signature: go run . --verify /path/to/signature.sig")
		os.Exit(0)
	}

	fp, err := filepath.Abs(os.Args[2])
	file, err := ioutil.ReadFile(fp)
	if err != nil {
		log.Fatal("could not read sigature from ", fp, "\n", err)
	}

	sigBytes, err := hex.DecodeString(string(file))
	if err != nil {
		log.Fatal(err)
	}

	sig, err := ring.Deserialize(sigBytes)
	if err != nil {
		log.Fatal(err)
	}

	ver := ring.Verify(sig)
	fmt.Println("verified?", ver)
	os.Exit(0)
}

func linkable() {
	if len(os.Args) < 4 {
		fmt.Println("need to supply path to signatures: go run . --linkable /path/to/signature1.sign /path/to/signature2.sign")
		os.Exit(0)
	}

	fp1, err := filepath.Abs(os.Args[2])
	file1, err := ioutil.ReadFile(fp1)
	if err != nil {
		log.Fatal("Could not read signature from ", fp1, "\n", err)
	}

	fp2, err := filepath.Abs(os.Args[3])
	file2, err := ioutil.ReadFile(fp2)
	if err != nil {
		log.Fatal("Could not read signature from ", fp2, "\n", err)
	}

	sigBytes1, err := hex.DecodeString(string(file1))
	if err != nil {
		log.Fatal(err)
	}

	sigBytes2, err := hex.DecodeString(string(file2))
	if err != nil {
		log.Fatal(err)
	}

	sig1, err := ring.Deserialize(sigBytes1)
	if err != nil {
		log.Fatal(err)
	}

	sig2, err := ring.Deserialize(sigBytes2)
	if err != nil {
		log.Fatal(err)
	}

	link := ring.Link(sig1, sig2)
	fmt.Println("linkable?", link)
	os.Exit(0)
}

func benchmark() {
	// TODO: Use testing.Benchmark
	if len(os.Args) < 3 {
		fmt.Println("need to supply size of ring: go run . --benchmark 10")
		os.Exit(0)
	}

	fmt.Println("Linked ring signature:")

	var timesSign []float64
	var timesVerify []float64
	var numRuns int

	for i := 0; i < 10; i++ {

		privkey, err := crypto.GenerateKey()
		if err != nil {
			log.Fatal("Could not generate key-pair", err)
		}

		file, err := ioutil.ReadFile("./message.txt")
		if err != nil {
			log.Fatal("could not read message from message.txt", err)
		}
		msgHash := blake2b.Sum256(file)

		size, err := strconv.Atoi(os.Args[2])
		if err != nil {
			log.Fatal(err)
		}

		sb, err := rand.Int(rand.Reader, new(big.Int).SetInt64(int64(size)))
		if err != nil {
			log.Fatal(err)
		}
		s := int(sb.Int64())

		keyring, err := ring.GenNewKeyRing(size, privkey, s)
		if err != nil {
			log.Fatal(err)
		}

		tStart := time.Now()
		sig, err := ring.Sign(msgHash, keyring, privkey, s)
		if err != nil {
			log.Fatal(err)
		}
		tEnd := time.Since(tStart)
		timesSign = append(timesSign, tEnd.Seconds())

		tStart = time.Now()
		ring.Verify(sig)
		tEnd = time.Since(tStart)
		timesVerify = append(timesVerify, tEnd.Seconds())

		numRuns += 1
	}

	var meanSign float64
	for _, v := range timesSign {
		meanSign += v
	}
	meanSign /= float64(numRuns)
	stdDevSign := stdDev(timesSign, meanSign)

	var meanVerify float64
	for _, v := range timesVerify {
		meanVerify += v
	}
	meanVerify /= float64(numRuns)
	stdDevVerify := stdDev(timesVerify, meanVerify)

	fmt.Printf("Total avg sign time was %.6f(%.6f)\n", meanSign, stdDevSign)
	fmt.Printf("Total avg verify time was %.6f(%.6f)\n", meanVerify, stdDevVerify)


	var timesSignSingle []float64
	var timesVerifySingle []float64
	var numRunsSingle int
	msg := []byte("Hello World")
	msgHash := blake2b.Sum256(msg)
	hash := msgHash[:]

	for i := 0; i < 10; i++ {
		privkey, err := crypto.GenerateKey()
		if err != nil {
			log.Fatal(err)
		}
		tStart := time.Now()
		signature, err := crypto.Sign(hash, privkey)
		if err != nil {
			log.Fatal(err)
		}
		tEnd := time.Since(tStart)
		timesSignSingle = append(timesSignSingle, tEnd.Seconds())


		pubkey, _ := crypto.Ecrecover(hash, signature)
		if err != nil {
			log.Fatal(err)
		}

		tStart = time.Now()
		crypto.VerifySignature(pubkey, hash, signature)
		tEnd = time.Since(tStart)
		timesVerifySingle = append(timesVerifySingle, tEnd.Seconds())

		numRunsSingle += 1
	}

	var meanSignSingle float64
	for _, v := range timesSignSingle {
		meanSignSingle += v
	}
	meanSignSingle /= float64(numRunsSingle)
	stdDevSignSingle := stdDev(timesSignSingle, meanSignSingle)

	var meanVerifySingle float64
	for _, v := range timesVerifySingle {
		meanVerifySingle += v
	}
	meanVerifySingle /= float64(numRunsSingle)
	stdDevVerifySingle := stdDev(timesVerifySingle, meanVerifySingle)

	fmt.Println("Simple ECC signature:")
	fmt.Printf("Total avg sign time was %.10f(%.10f)\n", meanSignSingle, stdDevSignSingle)
	fmt.Printf("Total avg verify time was %.10f(%.10f)\n", meanVerifySingle, stdDevVerifySingle)



	os.Exit(0)
}

func stdDev(numbers []float64, mean float64) float64 {
	total := 0.0
	for _, number := range numbers {
		total += math.Pow(number-mean, 2)
	}
	variance := total / float64(len(numbers)-1)
	return math.Sqrt(variance)
}
