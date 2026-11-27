package security

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode"
)

const (
	MaximumFileRedirects     = 5
	maximumFileURLCharacters = 8_192
	filePhaseTimeout         = 30 * time.Second
	fileDownloadTimeout      = 15 * time.Minute
)

// ValidateFileURL validates public HTTPS declarations without fetching developer files.
func ValidateFileURL(fileURL string) error {
	if strings.IndexFunc(fileURL, func(character rune) bool { return unicode.IsSpace(character) || unicode.IsControl(character) }) >= 0 {
		return errors.New("file URL must encode whitespace and control characters")
	}
	address, err := url.Parse(fileURL)
	if err != nil || len(fileURL) > maximumFileURLCharacters ||
		address.Scheme != "https" || address.Host == "" || address.Opaque != "" ||
		address.User != nil || strings.Contains(fileURL, "#") {
		return errors.New("file requires a public HTTPS URL without credentials or fragments")
	}
	if port := address.Port(); port != "" {
		portNumber, err := strconv.Atoi(port)
		if err != nil || portNumber < 1 || portNumber > 65_535 {
			return errors.New("file URL has an invalid port")
		}
	} else if strings.HasSuffix(address.Host, ":") {
		return errors.New("file URL has an empty port")
	}
	host := strings.ToLower(address.Hostname())
	ip, err := netip.ParseAddr(host)
	if err == nil {
		if ip.Zone() != "" || !PublicAddress(ip) {
			return errors.New("file destination must be public")
		}
		return nil
	}
	host = strings.TrimSuffix(host, ".")
	if len(host) > 253 || !strings.Contains(host, ".") ||
		strings.HasSuffix(host, ".localhost") || strings.HasSuffix(host, ".local") ||
		strings.HasSuffix(host, ".internal") || strings.HasSuffix(host, ".home.arpa") {
		return errors.New("file URL requires a public hostname")
	}
	topLabel := host[strings.LastIndex(host, ".")+1:]
	// Browsers interpret a final hexadecimal label as an alternate IPv4 address.
	hexadecimalAddress := strings.HasPrefix(topLabel, "0x") &&
		len(topLabel) > 2 && strings.TrimLeft(topLabel[2:], "0123456789abcdef") == ""
	if hexadecimalAddress || strings.IndexFunc(topLabel, func(character rune) bool { return character >= 'a' && character <= 'z' }) < 0 {
		return errors.New("file URL has an invalid hostname")
	}
	for label := range strings.SplitSeq(host, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return errors.New("file URL has an invalid hostname")
		}
		for _, character := range label {
			if !(character >= 'a' && character <= 'z' || character >= '0' && character <= '9' || character == '-') {
				return errors.New("file URL has an invalid hostname")
			}
		}
	}
	return nil
}

// dialFileHost checks every DNS answer and connects to a checked IP to prevent rebinding.
func dialFileHost(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	addresses, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return nil, err
	}
	if len(addresses) == 0 {
		return nil, errors.New("file host has no addresses")
	}
	for _, ip := range addresses {
		if !PublicAddress(ip) {
			return nil, errors.New("file destination must be public")
		}
	}
	dialer := net.Dialer{Timeout: filePhaseTimeout}
	return dialer.DialContext(ctx, network, net.JoinHostPort(addresses[0].String(), port))
}

// checkFileRedirect bounds redirects and validates each HTTPS target without forwarding credentials.
func checkFileRedirect(req *http.Request, previous []*http.Request) error {
	if len(previous) > MaximumFileRedirects {
		return errors.New("file download exceeds redirect limit")
	}
	if err := ValidateFileURL(req.URL.String()); err != nil {
		return err
	}
	req.Header = make(http.Header)
	return nil
}

// NewFileClient creates a credential-free transport that validates every connection and redirect.
func NewFileClient() *http.Client {
	return &http.Client{
		Timeout:       fileDownloadTimeout,
		CheckRedirect: checkFileRedirect,
		Transport: &http.Transport{
			DialContext:           dialFileHost,
			TLSHandshakeTimeout:   filePhaseTimeout,
			ResponseHeaderTimeout: filePhaseTimeout,
			DisableCompression:    true,
			DisableKeepAlives:     true,
		},
	}
}
