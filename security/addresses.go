package security

import "net/netip"

// PublicAddress rejects private, local, and reserved outbound IP destinations.
func PublicAddress(address netip.Addr) bool {
	address = address.Unmap()
	if !address.IsGlobalUnicast() ||
		address.IsPrivate() ||
		address.IsLoopback() ||
		address.IsLinkLocalUnicast() ||
		address.IsUnspecified() {
		return false
	}
	for _, prefix := range []string{
		"0.0.0.0/8",
		"100.64.0.0/10",
		"192.0.0.0/24",
		"192.0.2.0/24",
		"198.18.0.0/15",
		"198.51.100.0/24",
		"203.0.113.0/24",
		"240.0.0.0/4",
		"2001:db8::/32",
		"64:ff9b::/96",
		"2002::/16",
	} {
		network, err := netip.ParsePrefix(prefix)
		if err != nil {
			return false
		}
		if network.Contains(address) {
			return false
		}
	}
	return true
}
