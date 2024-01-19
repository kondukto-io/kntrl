package utils

import "strings"

// OneOf returns true if the given string is one of the given values
func OneOf(s string, values []string) bool {
	for _, v := range values {
		if s == v {
			return true
		}
	}

	return false
}

// OneOfInt32 returns true if the given string is one of the given values
func OneOfInt32(s int32, values []int32) bool {
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
