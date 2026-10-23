package models

// RecoveryKeyInfo says whether a recovery key is set up, and which: never the
// key itself, which only the user holds.
type RecoveryKeyInfo struct {
	Set     bool   `json:"set"`
	ID      string `json:"id,omitempty"`
	Created string `json:"created,omitempty"`
}
