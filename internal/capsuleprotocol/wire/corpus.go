package wire

const MaxCorpusExtensions = 4

// ValidCorpusMount: a directory name under /corpus, ^[a-z0-9][a-z0-9_-]{0,62}$.
func ValidCorpusMount(m string) bool {
	if len(m) < 1 || len(m) > 63 {
		return false
	}
	for i, c := range []byte(m) {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || i > 0 && (c == '_' || c == '-')) {
			return false
		}
	}
	return true
}

// ValidUUID: a lowercase canonical UUID other than the nil UUID.
func ValidUUID(u string) bool {
	if len(u) != 36 || u == "00000000-0000-0000-0000-000000000000" {
		return false
	}
	for i, c := range []byte(u) {
		switch {
		case i == 8 || i == 13 || i == 18 || i == 23:
			if c != '-' {
				return false
			}
		case !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f'):
			return false
		}
	}
	return true
}
