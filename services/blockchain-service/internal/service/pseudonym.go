package service

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
)

// PseudonymizeCustomerID derives a deterministic pseudonym for a customer
// identifier with HMAC-SHA256 under an institution-held key. The pseudonym — not
// the raw identifier — is what reaches the shared ledger (alert-channel and
// audit-channel), so channel members outside the issuing bank cannot resolve it,
// while the bank (and the regulator, on lawful request for the mapping) can.
// Being deterministic, it still lets the regulator correlate all on-chain
// activity of one customer across channels.
func PseudonymizeCustomerID(key, customerID string) string {
	mac := hmac.New(sha256.New, []byte(key))
	mac.Write([]byte(customerID))
	return "cust-" + hex.EncodeToString(mac.Sum(nil))
}
