package main

import (
	"bytes"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"flag"
	"log"
	"math/big"
	"net/http"
	"os"
	"time"

	jose "gopkg.in/square/go-jose.v1"
)

const (
	staging    = directory("https://acme-staging.api.letsencrypt.org/directory")
	production = directory("https://acme-v01.api.letsencrypt.org/directory")
)

var (
	ErrNoNonce = errors.New("acme server did not respond with a proper nonce header")
	ErrPending = errors.New("authz still pending")
)

var (
	flagStage = flag.Bool("staging", false, "use acme staging server")
)

func main() {
	log.SetFlags(0)
	log.SetPrefix("acmecancel: ")

	flag.Parse()
	url := flag.Arg(0)

	acmeDirectory := production
	if *flagStage {
		acmeDirectory = staging
	}

	key, ok := os.LookupEnv("LE_KEY")
	if !ok {
		log.Fatal("specify Let's Encrypt registration key with LE_KEY environment variable")
	}

	c, err := newClient(key, acmeDirectory)
	if err != nil {
		log.Fatalf("could not parse Let's Encrypt registration key: %v", err)
	}

	if err := c.disableAuthz(url); err != nil {
		log.Fatalf("could not disable authz: %v", err)
	}
}

type client struct {
	directoryURL string
	signer       jose.Signer
}

func newClient(ks string, ns jose.NonceSource) (*client, error) {
	var reg struct {
		N, D *big.Int
		E int
	}
	if err := json.Unmarshal([]byte(ks), &reg); err != nil {
		return nil, err
	}
	priv := &rsa.PrivateKey{
		D: reg.D,
		PublicKey: rsa.PublicKey{
			N:     reg.N,
			E:     reg.E,
		},
	}

	signer, err := jose.NewSigner(jose.RS512, priv)
	if err != nil {
		return nil, err
	}
	signer.SetNonceSource(ns)

	return &client{signer: signer}, nil
}

func (c *client) disableAuthz(url string) error {
	b, err := json.Marshal(struct {
		Resource string `json:"resource"`
		Status   string `jsom:"status"`
	}{
		Resource: "authz",
		Status:   "deactivated",
	})
	if err != nil {
		log.Println("Called")
		return err
	}

	signed, err := c.signer.Sign(b)
	if err != nil {
		log.Println("Called1")
		return err
	}
	buf := bytes.NewBuffer([]byte(signed.FullSerialize()))
	resp, err := http.Post(url, "application/jose+json", buf)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= http.StatusBadRequest {
		var message struct {
			Detail string `json:"detail"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&message); err != nil {
			return err
		}
		return errors.New(message.Detail)
	}

	var v struct {
		Status string `json:"status"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&v); err != nil {
		return err
	}
	if v.Status == "pending" {
		return ErrPending
	}
	return nil
}

type directory string

func (d directory) Nonce() (string, error) {
	c := &http.Client{Timeout: 1 * time.Second}
	resp, err := c.Get(string(d))
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return "", ErrNoNonce
	}
	nonce := resp.Header.Get("Replay-Nonce")
	if nonce == "" {
		return "", ErrNoNonce
	}
	return nonce, nil
}
