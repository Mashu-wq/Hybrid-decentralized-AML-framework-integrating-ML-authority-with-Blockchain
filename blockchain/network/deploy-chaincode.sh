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
VERSION="${CHAINCODE_VERSION:-1.0}"
SEQUENCE="${CHAINCODE_SEQUENCE:-1}"

# Chaincodes that define Private Data Collections ship a collections_config.json
# next to their source; approve/commit must carry it on every org.
COLLECTIONS_ARGS=()
if [[ -f "${CHAINCODE_PATH}/collections_config.json" ]]; then
  COLLECTIONS_ARGS=(--collections-config "${CHAINCODE_PATH}/collections_config.json")
  echo "Using private data collections config: ${CHAINCODE_PATH}/collections_config.json"
fi

source "${ROOT_DIR}/setOrgEnv.sh"

package_chaincode() {
  local label="${CHAINCODE_NAME}_${VERSION}"
  GOWORK=off peer lifecycle chaincode package "${ROOT_DIR}/${CHAINCODE_NAME}.tar.gz" \
    --path "${CHAINCODE_PATH}" \
    --lang golang \
    --label "${label}"
}

install_for_org() {
  local org="$1"
  setGlobals "${org}"
  local out
  out=$(peer lifecycle chaincode install "${ROOT_DIR}/${CHAINCODE_NAME}.tar.gz" 2>&1) || {
    if echo "${out}" | grep -q "already successfully installed"; then
      echo "Chaincode already installed on ${org}, skipping."
    else
      echo "${out}" >&2
      return 1
    fi
  }
  echo "${out}"
}

approve_for_org() {
  local org="$1"
  setGlobals "${org}"
  local out
  out=$(peer lifecycle chaincode approveformyorg \
    -o localhost:7050 \
    --ordererTLSHostnameOverride orderer0.fraud-detection.example.com \
    --channelID "${CHANNEL_NAME}" \
    --name "${CHAINCODE_NAME}" \
    --version "${VERSION}" \
    --package-id "${PACKAGE_ID}" \
    --sequence "${SEQUENCE}" \
    "${COLLECTIONS_ARGS[@]}" \
    --tls --cafile "${ORDERER_CA}" 2>&1) || {
    if echo "${out}" | grep -q "unchanged content"; then
      echo "Chaincode already approved for ${org}, skipping."
    else
      echo "${out}" >&2
      return 1
    fi
  }
  echo "${out}"
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

  # peer lifecycle chaincode commit resolves --peerAddresses hostnames for TLS SNI.
  # We connect via localhost-mapped ports but need the cert's SAN hostname for TLS.
  # Requires /etc/hosts entries: 127.0.0.1 peer0.org{1,2,3}.fraud-detection.example.com
  setGlobals Org1
  peer lifecycle chaincode commit \
    -o localhost:7050 \
    --ordererTLSHostnameOverride orderer0.fraud-detection.example.com \
    --channelID "${CHANNEL_NAME}" \
    --name "${CHAINCODE_NAME}" \
    --version "${VERSION}" \
    --sequence "${SEQUENCE}" \
    "${COLLECTIONS_ARGS[@]}" \
    --tls --cafile "${ORDERER_CA}" \
    --peerAddresses peer0.org1.fraud-detection.example.com:7051 --tlsRootCertFiles "${ROOT_DIR}/crypto-config/peerOrganizations/org1.fraud-detection.example.com/peers/peer0.org1.fraud-detection.example.com/tls/ca.crt" \
    --peerAddresses peer0.org2.fraud-detection.example.com:9051 --tlsRootCertFiles "${ROOT_DIR}/crypto-config/peerOrganizations/org2.fraud-detection.example.com/peers/peer0.org2.fraud-detection.example.com/tls/ca.crt" \
    --peerAddresses peer0.org3.fraud-detection.example.com:11051 --tlsRootCertFiles "${ROOT_DIR}/crypto-config/peerOrganizations/org3.fraud-detection.example.com/peers/peer0.org3.fraud-detection.example.com/tls/ca.crt"

  echo "${CHAINCODE_NAME} committed on ${CHANNEL_NAME}"
}

main "$@"
