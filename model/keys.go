package model

import "time"

// Key types select what an Account API principal may do. Every token starts
// with its type prefix so tools can recognize it without contacting the service.
const (
	KeyTypeAccount  = "account"
	KeyTypeInstance = "instance"
	KeyTypeInstall  = "install"
	// KeyTypeSession identifies a browser session principal. It is never stored.
	KeyTypeSession = "session"
)

// Key token prefixes are unbranded: key_ marks a key and the type name follows.
const (
	keyPrefixMarker   = "key_"
	KeyPrefixAccount  = keyPrefixMarker + KeyTypeAccount + "_"
	KeyPrefixInstance = keyPrefixMarker + KeyTypeInstance + "_"
	KeyPrefixInstall  = keyPrefixMarker + KeyTypeInstall + "_"
)

// MaximumKeyNameCharacters bounds team-chosen key names.
const MaximumKeyNameCharacters = 64

// KeyLastUsedInterval bounds how often authentication rewrites a key's last-used time.
const KeyLastUsedInterval = time.Minute

// Instance metadata reports are short, fixed fields an application sets about itself.
const (
	MaximumReportedStatusCharacters = 140
	MaximumUpgradeReasonCharacters  = 280
)

// Account API routes are served under this prefix on each app's API domain.
const AccountAPIPrefix = "/v1"
