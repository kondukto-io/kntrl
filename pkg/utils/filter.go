package utils

import "strings"

// OneOf returns true if the given value is in the given list
// Note: This func is not used in the project.
func OneOf[T comparable](s T, values []T) bool {
	for _, v := range values {
		if s == v {
			return true
		}
	}

	return false
}

// OneOfContains returns true if any items of the given string list contains the given value
func OneOfContains(search string, set []string) bool {
	for _, s := range set {
		if strings.Contains(s, search) {
			return true
		}
	}

	return false
}
