package main

import (
	"log"

	"github.com/hyperledger/fabric-chaincode-go/shim"
)

func main() {
	if err := shim.Start(new(AuditChaincode)); err != nil {
		log.Fatalf("start audit chaincode: %v", err)
	}
}
