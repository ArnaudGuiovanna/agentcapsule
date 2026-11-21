package corpuspkg

import (
	"crypto/sha256"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/corpusmeta"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/ext4image"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/harnesspkg"
)

// ImageUUID is the UUID of the image a builder makes from a commit of a
// corpus (ADR 023 §2.3): the first 16 bytes of
// sha256("agentcapsule.corpus-uuid.v1\0" + corpus ID + "\0" + commit + "\0" +
// builder digest), formatted as a UUID. It is also the image's directory
// hash seed: the same commit built by the same builder gives the same image.
func ImageUUID(corpusID, commit, builderDigest string) (string, error) {
	if !corpusmeta.ValidID("cor", corpusID) || !corpusmeta.ValidCommit(commit) || !harnesspkg.ValidDigest(builderDigest) {
		return "", corpusmeta.Invalid("a corpus ID, a commit of 40 hex digits and a builder digest are required")
	}
	return ext4image.SeedUUID(sha256.Sum256([]byte("agentcapsule.corpus-uuid.v1\x00" + corpusID + "\x00" + commit + "\x00" + builderDigest))), nil
}
