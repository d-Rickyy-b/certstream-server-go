package certificatetransparency

import "errors"

var (
	ErrCreatingClient          = errors.New("failed to create JSON client")
	ErrFetchingSTHFailed       = errors.New("failed to fetch STH")
	ErrCheckpointInvalidFormat = errors.New("invalid checkpoint format: expected at least 3 lines")
	ErrInvalidDataTile         = errors.New("invalid data tile precert_entry")
	ErrRequestFailed           = errors.New("request failed")
	ErrUnknownEntryType        = errors.New("unknown entry type")
	ErrInvalidFingerprint      = errors.New("invalid fingerprint")
	ErrEntryNil                = errors.New("entry is nil")
	ErrNoCertFound             = errors.New("no certificate found")
)
