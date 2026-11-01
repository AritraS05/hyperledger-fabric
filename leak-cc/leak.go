package main

import (
	"fmt"

	"github.com/hyperledger/fabric-contract-api-go/contractapi"
)

type Contract struct{ contractapi.Contract }

const collection = "pricesCollection"

// SubmitBid writes {asset, price} into the collection.
// The secret arrives via the TRANSIENT field, so the private value is NOT in the
// write transaction's inputs. This isolates the demonstration to the payload leak.
func (c *Contract) SubmitBid(ctx contractapi.TransactionContextInterface, key string) error {
	tmap, err := ctx.GetStub().GetTransient()
	if err != nil {
		return err
	}
	raw, ok := tmap["bid"] // JSON: {"asset":"widget","price":50}
	if !ok {
		return fmt.Errorf("missing 'bid' in transient map")
	}
	return ctx.GetStub().PutPrivateData(collection, key, raw)
}

// ReadBidLeaky reads the private bid and RETURNS it.
// The return value becomes Response.payload — plaintext, NOT hashed.
// Invoking this via submitTransaction writes that plaintext into every peer's ledger.
func (c *Contract) ReadBidLeaky(ctx contractapi.TransactionContextInterface, key string) (string, error) {
	b, err := ctx.GetStub().GetPrivateData(collection, key)
	if err != nil {
		return "", err
	}
	if b == nil {
		return "", fmt.Errorf("no bid for %s", key)
	}
	return string(b), nil // <-- LEAKS into payload
}

// SetBidLeaky is the write-side leak: it writes, then returns the value it wrote.
func (c *Contract) SetBidLeaky(ctx contractapi.TransactionContextInterface, key string) (string, error) {
	tmap, err := ctx.GetStub().GetTransient()
	if err != nil {
		return "", err
	}
	raw := tmap["bid"]
	if err := ctx.GetStub().PutPrivateData(collection, key, raw); err != nil {
		return "", err
	}
	return string(raw), nil // <-- LEAKS into payload
}

func main() {
	cc, err := contractapi.NewChaincode(&Contract{})
	if err != nil {
		panic(err)
	}
	if err := cc.Start(); err != nil {
		panic(err)
	}
}
