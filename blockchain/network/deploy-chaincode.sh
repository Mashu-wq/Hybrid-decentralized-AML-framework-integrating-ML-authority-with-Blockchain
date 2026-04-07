#!/usr/bin/env bash

set -euo pipefail

if [[ $# -ne 2 ]]; then
  echo "usage: $0 <chaincode-name> <channel-name>" >&2
  exit 1
fi

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${ROOT_DIR}/../.." && pwd)"
CHAINCODE_NAME="$1"
CHANNEL_NAME="$2"
CHAINCODE_PATH="${REPO_ROOT}/blockchain/chaincode/${CHAINCODE_NAME}"
PACKAGE_ID=""
VERSION="1.0"
SEQUENCE="1"

source "${ROOT_DIR}/setOrgEnv.sh"

package_chaincode() {
  local label="${CHAINCODE_NAME}_${VERSION}"
  peer lifecycle chaincode package "${ROOT_DIR}/${CHAINCODE_NAME}.tar.gz" \
    --path "${CHAINCODE_PATH}" \
    --lang golang \
    --label "${label}"
}

install_for_org() {
  local org="$1"
  setGlobals "${org}"
  peer lifecycle chaincode install "${ROOT_DIR}/${CHAINCODE_NAME}.tar.gz"
}

approve_for_org() {
  local org="$1"
  setGlobals "${org}"
  peer lifecycle chaincode approveformyorg \
    -o localhost:7050 \
    --ordererTLSHostnameOverride orderer0.fraud-detection.example.com \
    --channelID "${CHANNEL_NAME}" \
    --name "${CHAINCODE_NAME}" \
    --version "${VERSION}" \
    --package-id "${PACKAGE_ID}" \
    --sequence "${SEQUENCE}" \
    --tls --cafile "${ORDERER_CA}"
}

main() {
  package_chaincode
  install_for_org Org1
  install_for_org Org2
  install_for_org Org3

  setGlobals Org1
  PACKAGE_ID="$(peer lifecycle chaincode queryinstalled | awk -F '[, ]+' "/${CHAINCODE_NAME}_${VERSION}/{print \$3}")"
  if [[ -z "${PACKAGE_ID}" ]]; then
    echo "unable to resolve PACKAGE_ID for ${CHAINCODE_NAME}" >&2
    exit 1
  fi

  approve_for_org Org1
  approve_for_org Org2
  approve_for_org Org3

  setGlobals Org1
  peer lifecycle chaincode commit \
    -o localhost:7050 \
    --ordererTLSHostnameOverride orderer0.fraud-detection.example.com \
    --channelID "${CHANNEL_NAME}" \
    --name "${CHAINCODE_NAME}" \
    --version "${VERSION}" \
    --sequence "${SEQUENCE}" \
    --tls --cafile "${ORDERER_CA}" \
    --peerAddresses localhost:7051 --tlsRootCertFiles "${ROOT_DIR}/crypto-config/peerOrganizations/org1.fraud-detection.example.com/peers/peer0.org1.fraud-detection.example.com/tls/ca.crt" \
    --peerAddresses localhost:9051 --tlsRootCertFiles "${ROOT_DIR}/crypto-config/peerOrganizations/org2.fraud-detection.example.com/peers/peer0.org2.fraud-detection.example.com/tls/ca.crt" \
    --peerAddresses localhost:11051 --tlsRootCertFiles "${ROOT_DIR}/crypto-config/peerOrganizations/org3.fraud-detection.example.com/peers/peer0.org3.fraud-detection.example.com/tls/ca.crt"

  echo "${CHAINCODE_NAME} committed on ${CHANNEL_NAME}"
}

main "$@"
