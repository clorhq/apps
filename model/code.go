package model

// BlockTypeCode displays one or more verbatim code examples in selectable tabs.
const BlockTypeCode = "code"

const (
	MaximumCodeTabs            = 12
	MaximumCodeLabelCharacters = 60
	MaximumCodeCharacters      = 50_000
	MaximumCodeLines           = 1_000
)

// CodeTab declares a snippet without interpreting its contents as Markdown or HTML.
type CodeTab struct {
	Label    string `json:"label,omitempty"`
	Language string `json:"language"`
	Code     string `json:"code"`
}
