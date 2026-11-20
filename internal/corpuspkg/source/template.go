package source

import (
	"encoding/json"
	"fmt"
)

// Template is the commented manifest corpus init writes: every file kept, no
// processing step on, the other fields shown commented out. title and
// language must be valid (Text, 200 characters; a BCP 47 tag).
func Template(title, lang string) ([]byte, error) {
	m := Manifest{Schema: Schema, Title: title, Language: lang}
	if err := m.Validate(); err != nil {
		return nil, err
	}
	quoted, err := json.Marshal(title) // a JSON string is a YAML double-quoted scalar
	if err != nil {
		return nil, err
	}
	return fmt.Appendf(nil, `# How AgentCapsule builds a corpus from this directory (docs/corpus.md).
# Check it on your machine with: agentcapsule corpus lint DIR
schema: %s

# Shown to administrators and agents: 1 to 200 characters.
title: %s

# The documents' main language, as a BCP 47 tag: fr, en, en-GB.
language: %s

# Files to keep, as globs relative to this directory. "*" matches within a
# name, "**" any number of directories, and a glob that names a directory
# keeps what it holds. Names that start with "." are never kept.
include: ["**"]
# exclude: ["**/drafts/**"]

# Each step runs through an LLM alias of your organization; its budgets and
# prices apply. A step left out is off: Markdown, text, PDF with text, office
# files and spreadsheets are still converted, but audio and video need
# transcription, and images need vision.
processing:
  # ocr: {alias: ocr, mode: auto}       # auto: pages without text; always: every page
  # transcription: {alias: transcribe}  # audio and video
  # vision: {alias: vision, describe_figures: true}
  # summaries: {alias: summary}         # a summary per document, for INDEX.md
  # embeddings: {alias: embed}          # vectors for semantic search

# Optional metadata of some files:
# documents:
#   - path: courses/chap1.pdf
#     title: "Chapter 1: time value of money"
#     tags: [discounting, NPV]

# Your own Markdown in place of a document's generated view; rebuild after a
# change:
# corrections:
#   - path: videos/session2.mp4
#     markdown: corrections/session2.md
`, Schema, quoted, lang), nil
}
