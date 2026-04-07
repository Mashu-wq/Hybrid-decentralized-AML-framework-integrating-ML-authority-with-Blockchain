package main

import (
	"log"

	"github.com/hyperledger/fabric-chaincode-go/shim"
)

func main() {
	if err := shim.Start(new(AlertChaincode)); err != nil {
		log.Fatalf("start alert chaincode: %v", err)
	}
}
