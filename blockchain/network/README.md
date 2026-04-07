# Hyperledger Fabric Network

This network definition provisions:

- 3 peer organizations: `Org1`, `Org2`, `Org3`
- 3 application channels: `kyc-channel`, `alert-channel`, `audit-channel`
- 3 RAFT orderers
- 2 peers per organization
- CouchDB world state for every peer

Key files:

- `cryptogen.yaml`: crypto material generation
- `configtx.yaml`: genesis block, channel, and anchor peer definitions
- `docker-compose.yaml`: local multi-org Fabric topology
- `start.sh`: generate artifacts and start the local network
- `deploy-chaincode.sh`: package/install/approve/commit one chaincode
- `connection-profiles/*.yaml`: service-side SDK connection profiles

Prerequisites:

- Docker / Docker Compose
- Hyperledger Fabric binaries in `PATH` (`cryptogen`, `configtxgen`, `peer`, `osnadmin`)

Typical flow:

```bash
bash start.sh
bash deploy-chaincode.sh kyc-contract kyc-channel
bash deploy-chaincode.sh alert-contract alert-channel
bash deploy-chaincode.sh audit-contract audit-channel
```
