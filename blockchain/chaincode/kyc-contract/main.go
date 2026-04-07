package main

import (
	"log"

	"github.com/hyperledger/fabric-chaincode-go/shim"
)

func main() {
	if err := shim.Start(new(KYCChaincode)); err != nil {
		log.Fatalf("start kyc chaincode: %v", err)
	}
}
