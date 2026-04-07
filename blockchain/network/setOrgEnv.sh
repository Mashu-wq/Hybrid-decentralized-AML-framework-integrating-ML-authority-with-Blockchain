#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export FABRIC_CFG_PATH="${ROOT_DIR}"

setGlobals() {
  local ORG="$1"
  case "${ORG}" in
    Org1)
      export CORE_PEER_LOCALMSPID="Org1MSP"
      export CORE_PEER_MSPCONFIGPATH="${ROOT_DIR}/crypto-config/peerOrganizations/org1.fraud-detection.example.com/users/Admin@org1.fraud-detection.example.com/msp"
      export CORE_PEER_ADDRESS="localhost:7051"
      export CORE_PEER_TLS_ROOTCERT_FILE="${ROOT_DIR}/crypto-config/peerOrganizations/org1.fraud-detection.example.com/peers/peer0.org1.fraud-detection.example.com/tls/ca.crt"
      ;;
    Org2)
      export CORE_PEER_LOCALMSPID="Org2MSP"
      export CORE_PEER_MSPCONFIGPATH="${ROOT_DIR}/crypto-config/peerOrganizations/org2.fraud-detection.example.com/users/Admin@org2.fraud-detection.example.com/msp"
      export CORE_PEER_ADDRESS="localhost:9051"
      export CORE_PEER_TLS_ROOTCERT_FILE="${ROOT_DIR}/crypto-config/peerOrganizations/org2.fraud-detection.example.com/peers/peer0.org2.fraud-detection.example.com/tls/ca.crt"
      ;;
    Org3)
      export CORE_PEER_LOCALMSPID="Org3MSP"
      export CORE_PEER_MSPCONFIGPATH="${ROOT_DIR}/crypto-config/peerOrganizations/org3.fraud-detection.example.com/users/Admin@org3.fraud-detection.example.com/msp"
      export CORE_PEER_ADDRESS="localhost:11051"
      export CORE_PEER_TLS_ROOTCERT_FILE="${ROOT_DIR}/crypto-config/peerOrganizations/org3.fraud-detection.example.com/peers/peer0.org3.fraud-detection.example.com/tls/ca.crt"
      ;;
    *)
      echo "unknown org ${ORG}" >&2
      return 1
      ;;
  esac

  export CORE_PEER_TLS_ENABLED=true
  export ORDERER_CA="${ROOT_DIR}/crypto-config/ordererOrganizations/fraud-detection.example.com/orderers/orderer0.fraud-detection.example.com/msp/tlscacerts/tlsca.fraud-detection.example.com-cert.pem"
}
