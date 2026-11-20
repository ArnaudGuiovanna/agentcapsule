package source

import (
	"bytes"
	"path"
	"strings"
)

// Kind is a source file's type, from its extension (the report's kind, ADR
// 023 §2.4).
type Kind string

const (
	KindMarkdown Kind = "markdown"
	KindText     Kind = "text"
	KindPDF      Kind = "pdf"
	KindDOCX     Kind = "docx"
	KindPPTX     Kind = "pptx"
	KindODT      Kind = "odt"
	KindXLSX     Kind = "xlsx"
	KindCSV      Kind = "csv"
	KindImage    Kind = "image"
	KindAudio    Kind = "audio"
	KindVideo    Kind = "video"
	KindOther    Kind = "other"
)

// Kinds lists every kind, other last.
var Kinds = []Kind{KindMarkdown, KindText, KindPDF, KindDOCX, KindPPTX, KindODT, KindXLSX, KindCSV, KindImage,
	KindAudio, KindVideo, KindOther}

// Extensions maps each recognized extension, in lower case, to its kind.
// Any other extension is KindOther, which no build converts.
var Extensions = map[string]Kind{
	".md": KindMarkdown, ".markdown": KindMarkdown,
	".txt": KindText, ".text": KindText,
	".pdf":  KindPDF,
	".docx": KindDOCX,
	".pptx": KindPPTX,
	".odt":  KindODT,
	".xlsx": KindXLSX,
	".csv":  KindCSV, ".tsv": KindCSV,
	".png": KindImage, ".jpg": KindImage, ".jpeg": KindImage, ".webp": KindImage, ".gif": KindImage,
	".mp3": KindAudio, ".wav": KindAudio, ".m4a": KindAudio, ".flac": KindAudio, ".ogg": KindAudio, ".opus": KindAudio,
	".mp4": KindVideo, ".m4v": KindVideo, ".mov": KindVideo, ".webm": KindVideo, ".mkv": KindVideo,
}

// KindOf is the kind of the file at name, from its extension.
func KindOf(name string) Kind {
	if k, ok := Extensions[strings.ToLower(path.Ext(name))]; ok {
		return k
	}
	return KindOther
}

// NeededStep is the processing step without which a build skips a file of
// kind k: audio and video need transcription, images need vision. Other
// kinds need none ("").
func NeededStep(k Kind) string {
	switch k {
	case KindAudio, KindVideo:
		return StepTranscription
	case KindImage:
		return StepVision
	}
	return ""
}

// looksLike reports whether head, a file's first bytes, starts as a file of
// its extension does. Text kinds and extensions without a fixed signature
// always do.
func looksLike(ext string, head []byte) bool {
	has := func(off int, sig string) bool {
		return len(head) >= off+len(sig) && string(head[off:off+len(sig)]) == sig
	}
	switch ext {
	case ".pdf":
		return bytes.Contains(head[:min(len(head), 1024)], []byte("%PDF-"))
	case ".docx", ".pptx", ".xlsx", ".odt":
		return has(0, "PK\x03\x04")
	case ".png":
		return has(0, "\x89PNG\r\n\x1a\n")
	case ".jpg", ".jpeg":
		return has(0, "\xff\xd8\xff")
	case ".gif":
		return has(0, "GIF8")
	case ".webp":
		return has(0, "RIFF") && has(8, "WEBP")
	case ".wav":
		return has(0, "RIFF") && has(8, "WAVE")
	case ".flac":
		return has(0, "fLaC")
	case ".ogg", ".opus":
		return has(0, "OggS")
	case ".mp3":
		return has(0, "ID3") || len(head) >= 2 && head[0] == 0xff && head[1]&0xe0 == 0xe0
	case ".mp4", ".m4a", ".m4v", ".mov":
		return has(4, "ftyp") || has(4, "moov") || has(4, "wide") || has(4, "mdat") || has(4, "free")
	case ".webm", ".mkv":
		return has(0, "\x1a\x45\xdf\xa3")
	}
	return true
}
