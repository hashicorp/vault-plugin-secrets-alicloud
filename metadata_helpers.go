// Copyright IBM Corp. 2018, 2025
// SPDX-License-Identifier: MPL-2.0

package alicloud

import "fmt"

// toStringMap converts an interface{} value to a map[string]string.
// It accepts map[string]string directly, or map[string]interface{} where
// every value must be a string.
func toStringMap(v interface{}) (map[string]string, error) {
	out := make(map[string]string)
	if v == nil {
		return out, nil
	}
	switch m := v.(type) {
	case map[string]string:
		return m, nil
	case map[string]interface{}:
		for k, val := range m {
			s, ok := val.(string)
			if !ok {
				return nil, fmt.Errorf("metadata values must be strings (key %q had type %T)", k, val)
			}
			out[k] = s
		}
		return out, nil
	default:
		return nil, fmt.Errorf("unsupported metadata type %T", v)
	}
}
