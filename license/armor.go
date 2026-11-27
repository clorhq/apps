package license

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"strconv"
	"strings"
	"time"

	"github.com/clorhq/apps/model"
)

// License file framing. The marker is generic so every app shares one format.
const (
	LicenseFileBegin   = "-----BEGIN LICENSE-----"
	LicenseFileEnd     = "-----END LICENSE-----"
	LicenseFileFormat  = 1
	LicenseFileColumns = 64
	// MaximumLicenseFileBytes bounds the text accepted by DecodeLicenseFile.
	MaximumLicenseFileBytes = 64 * 1024
	licenseFileDateLayout   = "2006-01-02"
)

// LicenseFileHeader holds the readable, unsigned lines written above the signed body.
type LicenseFileHeader struct {
	Product      string
	PlanName     string
	PlanInterval string
	InstanceID   string
	Starts       time.Time
	Expires      time.Time
	Revision     int64
}

// NewLicenseFileHeader describes signed claims in the readable header of a license file.
func NewLicenseFileHeader(product string, claims *model.License) *LicenseFileHeader {
	return &LicenseFileHeader{
		Product:      product,
		PlanName:     claims.PlanName,
		PlanInterval: claims.PlanInterval,
		InstanceID:   claims.InstanceID,
		Starts:       claims.Starts,
		Expires:      claims.Expires,
		Revision:     claims.Revision,
	}
}

// EncodeLicenseFile armors a signed license as readable text. Only the body is signed;
// the header lines are informative and ignored when the file is decoded.
func EncodeLicenseFile(document *model.SignedDocument, header *LicenseFileHeader) (string, error) {
	documentJSON, err := json.Marshal(document)
	if err != nil {
		return "", err
	}
	body := base64.RawURLEncoding.EncodeToString(documentJSON)
	var text strings.Builder
	text.WriteString(LicenseFileBegin + "\n")
	headerLines := [][2]string{
		{"Product", header.Product},
		{"Plan", strings.TrimSpace(header.PlanName + " (" + header.PlanInterval + ")")},
		{"Instance ID", header.InstanceID},
		{"Valid", header.Starts.UTC().Format(licenseFileDateLayout) + " to " + header.Expires.UTC().Format(licenseFileDateLayout)},
		{"Revision", strconv.FormatInt(header.Revision, 10)},
		{"Format", strconv.Itoa(LicenseFileFormat)},
	}
	for _, line := range headerLines {
		text.WriteString(line[0] + ": " + licenseHeaderValue(line[1]) + "\n")
	}
	text.WriteString("\n")
	for len(body) > LicenseFileColumns {
		text.WriteString(body[:LicenseFileColumns] + "\n")
		body = body[LicenseFileColumns:]
	}
	text.WriteString(body + "\n")
	text.WriteString(LicenseFileEnd + "\n")
	return text.String(), nil
}

// licenseHeaderValue keeps a header value on one line.
func licenseHeaderValue(value string) string {
	return strings.Join(strings.Fields(value), " ")
}

// DecodeLicenseFile extracts the signed document from armored license text. It accepts
// CRLF or LF, rewrapped or indented bodies, and ignores every header line. The result
// is untrusted until VerifyLicense authenticates it.
func DecodeLicenseFile(text string) (*model.SignedDocument, error) {
	if len(text) > MaximumLicenseFileBytes {
		return nil, ErrLicenseFormat
	}
	if strings.Count(text, LicenseFileBegin) != 1 || strings.Count(text, LicenseFileEnd) != 1 {
		return nil, ErrLicenseFormat
	}
	_, afterBegin, _ := strings.Cut(text, LicenseFileBegin)
	block, _, found := strings.Cut(afterBegin, LicenseFileEnd)
	if !found {
		return nil, ErrLicenseFormat
	}
	lines := strings.Split(strings.ReplaceAll(block, "\r\n", "\n"), "\n")
	// A blank line after the header ends it, so wrapped header values are skipped too.
	// Without one, header lines are recognized by their colon, which base64url never has.
	bodyStart := 0
	sawHeader := false
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.Contains(trimmed, ":") {
			sawHeader = true
			continue
		}
		if trimmed == "" && sawHeader {
			bodyStart = i + 1
			break
		}
	}
	var body bytes.Buffer
	for _, line := range lines[bodyStart:] {
		if strings.Contains(line, ":") {
			continue
		}
		for _, character := range []byte(line) {
			switch character {
			case ' ', '\t', '\n', '\r', '\v', '\f':
			default:
				body.WriteByte(character)
			}
		}
	}
	documentJSON, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(body.String(), "="))
	if err != nil {
		return nil, ErrLicenseFormat
	}
	var document model.SignedDocument
	if err := json.Unmarshal(documentJSON, &document); err != nil {
		return nil, ErrLicenseFormat
	}
	if document.KeyID == "" || document.Document == "" || document.Signature == "" {
		return nil, ErrLicenseFormat
	}
	return &document, nil
}
