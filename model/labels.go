package model

import (
	"errors"
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strings"
)

// Labels organize team resources. Each key has an optional value: role=backup, site=berlin
// or a bare pinned. Keys containing a slash are reserved.
type Labels map[string]string

// Label limits.
const (
	MaximumLabels          = 32
	MaximumLabelCharacters = 63
)

// labelPattern matches label keys and non-empty values: lowercase letters, digits, dot, hyphen
// and underscore, starting and ending with a letter or digit, at most MaximumLabelCharacters long.
var labelPattern = regexp.MustCompile(fmt.Sprintf(
	`^[a-z0-9]([a-z0-9._-]{0,%d}[a-z0-9])?$`,
	MaximumLabelCharacters-2,
))

// labelSyntax describes the characters allowed in label keys and values.
var labelSyntax = fmt.Sprintf(
	"1 to %d lowercase letters, digits, dots, hyphens or underscores",
	MaximumLabelCharacters,
)

// ErrInvalidLabels reports labels or selectors outside the supported syntax.
var ErrInvalidLabels = errors.New("invalid labels")

// LabelError explains why labels or a selector are invalid. It matches ErrInvalidLabels.
type LabelError struct {
	// Message is the explanation without the generic prefix, suitable for showing to teams.
	Message string
}

// Error returns the explanation prefixed with the generic invalid-labels message.
func (e *LabelError) Error() string { return ErrInvalidLabels.Error() + ". " + e.Message }

// Is reports whether target is ErrInvalidLabels.
func (e *LabelError) Is(target error) bool { return target == ErrInvalidLabels }

// invalidLabels returns a LabelError with a formatted explanation.
func invalidLabels(format string, values ...any) error {
	return &LabelError{Message: fmt.Sprintf(format, values...)}
}

// ValidateLabels checks every key and value and the label count.
func ValidateLabels(labels Labels) error {
	if len(labels) > MaximumLabels {
		return invalidLabels("at most %d labels are allowed", MaximumLabels)
	}
	for key, value := range labels {
		if !labelPattern.MatchString(key) {
			return invalidLabels("label %q needs %s", key, labelSyntax)
		}
		if value != "" && !labelPattern.MatchString(value) {
			return invalidLabels("label value %q needs %s", value, labelSyntax)
		}
	}
	return nil
}

// ParseLabels reads key=value and bare key terms, trimming whitespace around each part.
func ParseLabels(terms []string) (Labels, error) {
	labels := Labels{}
	for _, term := range terms {
		term = strings.TrimSpace(term)
		if term == "" {
			continue
		}
		key, value, _ := strings.Cut(term, "=")
		labels[strings.TrimSpace(key)] = strings.TrimSpace(value)
	}
	return labels, ValidateLabels(labels)
}

// String formats labels as sorted key=value and bare key terms separated by spaces.
func (labels Labels) String() string { return strings.Join(labels.Terms(), " ") }

// Terms returns sorted key=value and bare key terms.
func (labels Labels) Terms() []string {
	terms := make([]string, 0, len(labels))
	for _, key := range slices.Sorted(maps.Keys(labels)) {
		terms = append(terms, labelTerm(key, labels[key]))
	}
	return terms
}

// labelTerm formats one label.
func labelTerm(key, value string) string {
	if value == "" {
		return key
	}
	return key + "=" + value
}

// Label selector operators.
const (
	selectorExists    = "exists"
	selectorMissing   = "missing"
	selectorEquals    = "equals"
	selectorNotEquals = "not_equals"
)

// selectorRequirement is one requirement of a label selector.
type selectorRequirement struct {
	operator string
	key      string
	value    string
}

// LabelSelector matches labels against comma-separated requirements that must all hold:
// key, !key, key=value and key!=value.
type LabelSelector struct {
	requirements []selectorRequirement
}

// ParseLabelSelector parses a selector such as "role=backup,!pinned". An empty selector matches everything.
func ParseLabelSelector(selector string) (*LabelSelector, error) {
	labelSelector := &LabelSelector{}
	for term := range strings.SplitSeq(selector, ",") {
		term = strings.TrimSpace(term)
		if term == "" {
			continue
		}
		requirement := selectorRequirement{}
		switch {
		case strings.Contains(term, "!="):
			key, value, _ := strings.Cut(term, "!=")
			requirement = selectorRequirement{
				operator: selectorNotEquals,
				key:      strings.TrimSpace(key),
				value:    strings.TrimSpace(value),
			}
		case strings.Contains(term, "="):
			key, value, _ := strings.Cut(term, "=")
			requirement = selectorRequirement{
				operator: selectorEquals,
				key:      strings.TrimSpace(key),
				value:    strings.TrimSpace(value),
			}
		case strings.HasPrefix(term, "!"):
			requirement = selectorRequirement{
				operator: selectorMissing,
				key:      strings.TrimSpace(strings.TrimPrefix(term, "!")),
			}
		default:
			requirement = selectorRequirement{
				operator: selectorExists,
				key:      term,
			}
		}
		validKey := labelPattern.MatchString(requirement.key)
		validValue := requirement.value == "" || labelPattern.MatchString(requirement.value)
		if !validKey || !validValue {
			return nil, invalidLabels("selector term %q is not key, !key, key=value or key!=value", term)
		}
		labelSelector.requirements = append(labelSelector.requirements, requirement)
	}
	return labelSelector, nil
}

// Matches reports whether labels satisfy every requirement.
func (selector *LabelSelector) Matches(labels Labels) bool {
	for _, requirement := range selector.requirements {
		value, present := labels[requirement.key]
		switch requirement.operator {
		case selectorExists:
			if !present {
				return false
			}
		case selectorMissing:
			if present {
				return false
			}
		case selectorEquals:
			if !present || value != requirement.value {
				return false
			}
		case selectorNotEquals:
			if present && value == requirement.value {
				return false
			}
		}
	}
	return true
}
