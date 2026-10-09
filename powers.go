package passkeys

import (
	"log/slog"
	"slices"
	"strings"
)

type OnePower struct {
	Id       string   `json:"id,omitempty" yaml:"id,omitempty" mapstructure:"id"`
	Type     string   `json:"type,omitempty" yaml:"type,omitempty" mapstructure:"type"`
	Domain   string   `json:"domain,omitempty" yaml:"domain,omitempty" mapstructure:"domain"`
	Function string   `json:"function,omitempty" yaml:"function,omitempty" mapstructure:"function"`
	Action   []string `json:"action,omitempty" yaml:"action,omitempty" mapstructure:"action"`
}

func (p *OnePower) SameAs(other *OnePower) bool {
	if !strings.EqualFold(p.Type, other.Type) {
		return false
	}
	if !strings.EqualFold(p.Domain, other.Domain) {
		return false
	}
	if !strings.EqualFold(p.Function, other.Function) {
		return false
	}
	for i, action := range p.Action {
		if !strings.EqualFold(action, other.Action[i]) {
			return false
		}
	}
	return true
}

// Includes reports whether a given power p "includes" the supplied other power.
//
// It returns true iff all of the following conditions hold:
//   - p.type equals other.type (case-insensitive, via strings.EqualFold)
//   - p.domain equals other.domain (case-insensitive)
//   - p.function equals other.function (case-insensitive)
//   - every action in other power is present in the actions of p
//
// The method performs early returns and returns false on the first mismatch. It treats p.Action as a superset:
// extra actions present in p but not in other do not prevent inclusion. Note that the implementation assumes both
// p and other are non-nil; calling Includes with a nil receiver or nil other will result in a runtime panic.
func (p *OnePower) Includes(other OnePower) bool {
	// Check the lengths of the action arrays for a maximum length of 10
	if len(p.Action) > 10 || len(other.Action) > 10 {
		slog.Error("lenghts of action arrays are greater than 10", "p", len(p.Action), "other", len(other.Action))
		return false
	}

	// Type, Domain and Function must be the same
	if !strings.EqualFold(p.Type, other.Type) {
		return false
	}
	if !strings.EqualFold(p.Domain, other.Domain) {
		return false
	}
	if !strings.EqualFold(p.Function, other.Function) {
		return false
	}

	// Now we check the Action array.
	// If p.Action has an asterisc '*', this includes any action, so we return true
	if slices.Contains(p.Action, "*") {
		return true
	}

	// Check that each element of other.action is included in p.action
	// The comparison of individual elements is case-insensitive
	for _, otherAction := range other.Action {
		found := false
		for _, pAction := range p.Action {
			if strings.EqualFold(pAction, otherAction) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	return true

}
