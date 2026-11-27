package security

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestFileURLs rejects malformed and non-public declarations without accessing the network.
func TestFileURLs(t *testing.T) {
	for _, address := range []string{
		"https://files.example.com/app.tar.zst", "https://files.example.com:8443/file?a=b",
		"https://8.8.8.8/file",
	} {
		require.NoError(t, ValidateFileURL(address), address)
	}
	for _, address := range []string{
		"http://files.example.com/file", "https://user:pass@files.example.com/file",
		"https://files.example.com/file#", "https://files.example.com/file#part",
		"https://127.0.0.1/file", "https://127.1/file", "https://0177.0.0.1/file",
		"https://0x7f.0x0.0x0.0x1/file", "https://127.0.0.0x1/file", "https://0x7f000001/file",
		"https://files.example.com/a b", "https://10.0.0.1/file", "https://169.254.169.254/file",
		"https://[::ffff:127.0.0.1]/file", "https://[::1]/file", "https://localhost/file",
		"https://host.local/file", "https://host.internal/file", "https://a..example.com/file",
		"https://bad_host.example.com/file", "https://files.example.com:/file",
		"https://files.example.com:65536/file", "https://[garbage]/file", "https:///file",
	} {
		require.Error(t, ValidateFileURL(address), address)
	}
}

// TestFileRedirects retains HTTPS/public validation and strips all request credentials at every hop.
func TestFileRedirects(t *testing.T) {
	address, err := url.Parse("https://files.example.com/file")
	require.NoError(t, err)
	req := &http.Request{URL: address, Header: http.Header{"Authorization": {"Bearer secret"}, "Cookie": {"secret"}}}
	require.NoError(t, checkFileRedirect(req, make([]*http.Request, MaximumFileRedirects)))
	require.Empty(t, req.Header)
	require.Error(t, checkFileRedirect(req, make([]*http.Request, MaximumFileRedirects+1)))
	for _, destination := range []string{"http://files.example.com/file", "https://127.0.0.1/file"} {
		req.URL, err = url.Parse(destination)
		require.NoError(t, err)
		require.Error(t, checkFileRedirect(req, nil))
	}
	require.Nil(t, NewFileClient().Transport.(*http.Transport).Proxy)
	_, err = dialFileHost(t.Context(), "tcp", "127.0.0.1:443")
	require.Error(t, err)
}
