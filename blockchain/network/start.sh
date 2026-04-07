#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export FABRIC_CFG_PATH="${ROOT_DIR}"

CHANNELS=("kyc-channel" "alert-channel" "audit-channel")

generate_artifacts() {
  rm -rf "${ROOT_DIR}/crypto-config" "${ROOT_DIR}/channel-artifacts" "${ROOT_DIR}/system-genesis-block"
  mkdir -p "${ROOT_DIR}/channel-artifacts" "${ROOT_DIR}/system-genesis-block"

  cryptogen generate --config="${ROOT_DIR}/cryptogen.yaml" --output="${ROOT_DIR}/crypto-config"

  configtxgen -profile FraudDetectionOrdererGenesis -channelID system-channel -outputBlock "${ROOT_DIR}/system-genesis-block/genesis.block"
  for channel in "${CHANNELS[@]}"; do
    profile="$(tr '[:lower:]-' '[:upper:]_' <<< "${channel}")"
    case "${channel}" in
      kyc-channel) profile="KYCChannel" ;;
      alert-channel) profile="AlertChannel" ;;
      audit-channel) profile="AuditChannel" ;;
    esac
    configtxgen -profile "${profile}" -outputCreateChannelTx "${ROOT_DIR}/channel-artifacts/${channel}.tx" -channelID "${channel}"
    configtxgen -profile "${profile}" -outputAnchorPeersUpdate "${ROOT_DIR}/channel-artifacts/Org1MSPanchors-${channel}.tx" -channelID "${channel}" -asOrg Org1MSP
    configtxgen -profile "${profile}" -outputAnchorPeersUpdate "${ROOT_DIR}/channel-artifacts/Org2MSPanchors-${channel}.tx" -channelID "${channel}" -asOrg Org2MSP
    configtxgen -profile "${profile}" -outputAnchorPeersUpdate "${ROOT_DIR}/channel-artifacts/Org3MSPanchors-${channel}.tx" -channelID "${channel}" -asOrg Org3MSP
  done
}

create_channel() {
  local channel="$1"
  docker exec peer0.org1.fraud-detection.example.com peer channel create \
    -o orderer0.fraud-detection.example.com:7050 \
    --ordererTLSHostnameOverride orderer0.fraud-detection.example.com \
    -c "${channel}" \
    -f "/etc/hyperledger/channel-artifacts/${channel}.tx" \
    --outputBlock "/etc/hyperledger/channel-artifacts/${channel}.block" \
    --tls --cafile /etc/hyperledger/orderer/tls/ca.crt
}

join_peer() {
  local container="$1"
  local channel="$2"
  docker exec "${container}" peer channel join -b "/etc/hyperledger/channel-artifacts/${channel}.block"
}

update_anchor() {
  local container="$1"
  local orgmsp="$2"
  local channel="$3"
  docker exec "${container}" peer channel update \
    -o orderer0.fraud-detection.example.com:7050 \
    --ordererTLSHostnameOverride orderer0.fraud-detection.example.com \
    -c "${channel}" \
    -f "/etc/hyperledger/channel-artifacts/${orgmsp}anchors-${channel}.tx" \
    --tls --cafile /etc/hyperledger/orderer/tls/ca.crt
}

generate_connection_profiles() {
  mkdir -p "${ROOT_DIR}/connection-profiles"
}

main() {
  generate_artifacts
  docker compose -f "${ROOT_DIR}/docker-compose.yaml" up -d

  sleep 15

  for channel in "${CHANNELS[@]}"; do
    create_channel "${channel}"
    join_peer peer0.org1.fraud-detection.example.com "${channel}"
    join_peer peer1.org1.fraud-detection.example.com "${channel}"
    join_peer peer0.org2.fraud-detection.example.com "${channel}"
    join_peer peer1.org2.fraud-detection.example.com "${channel}"
    join_peer peer0.org3.fraud-detection.example.com "${channel}"
    join_peer peer1.org3.fraud-detection.example.com "${channel}"
    update_anchor peer0.org1.fraud-detection.example.com Org1MSP "${channel}"
    update_anchor peer0.org2.fraud-detection.example.com Org2MSP "${channel}"
    update_anchor peer0.org3.fraud-detection.example.com Org3MSP "${channel}"
  done

  generate_connection_profiles
  echo "Fabric network started"
}

main "$@"
