package license

import "time"

// Constants shared by the license implementation and its callers.
const (
	signatureContext   = "clor-apps-v1\x00"
	signatureSeparator = "\x00"
	// ClockTolerance bounds how far in the future an issue time may be.
	ClockTolerance = 5 * time.Minute
)
