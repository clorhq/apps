package model

import (
	"bytes"
	"encoding/json"
)

// HeroFact is a plain-text label with an optional decorative icon and description.
type HeroFact struct {
	Label       string `json:"label"`
	Icon        string `json:"icon,omitempty"`
	Description string `json:"description,omitempty"`
}

// UnmarshalJSON accepts both original text-only facts and structured facts.
func (fact *HeroFact) UnmarshalJSON(factJSON []byte) error {
	if bytes.HasPrefix(factJSON, []byte(`"`)) {
		var label string
		if err := json.Unmarshal(factJSON, &label); err != nil {
			return err
		}
		*fact = HeroFact{Label: label}
		return nil
	}
	type heroFact HeroFact
	var declaration heroFact
	decoder := json.NewDecoder(bytes.NewReader(factJSON))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&declaration); err != nil {
		return err
	}
	*fact = HeroFact(declaration)
	return nil
}

// MarshalJSON preserves the string format for facts with only a label.
func (fact HeroFact) MarshalJSON() ([]byte, error) {
	if fact.Icon == "" && fact.Description == "" {
		return json.Marshal(fact.Label)
	}
	type heroFact HeroFact
	return json.Marshal(heroFact(fact))
}
