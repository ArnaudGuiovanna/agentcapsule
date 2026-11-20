package source

import (
	"bytes"
	"math"
	"testing"
)

// Each measured format gives its pages, slides, sheets or duration from its
// headers; a file that is not what its extension says is unmeasured, never
// an error.
func TestMeasureReadsEachFormatsHeaders(t *testing.T) {
	near := func(got, want float64) bool { return math.Abs(got-want) <= want/100 }
	for _, c := range []struct {
		name string
		data []byte
		want Measures
	}{
		{"a.pdf", samplePDF(3), Measures{Pages: 3}},
		{"compressed.pdf", samplePDFObjectStreams(t, 7), Measures{Pages: 7}},
		{"linearized.pdf", []byte("%PDF-1.7\n1 0 obj <</Linearized 1/L 9000/H [ 500 100]/O 3/E 800/N 12/T 8000>> endobj\n"), Measures{Pages: 12}},
		{"pages-only.pdf", []byte("%PDF-1.4\n3 0 obj <</Type/Page>> endobj 4 0 obj <</Type /Page /Parent 2 0 R>> endobj\n"), Measures{Pages: 2}},
		{"empty.pdf", []byte("%PDF-1.4\n%%EOF\n"), Measures{Unmeasured: true}},
		{"a.docx", sampleZip(t, map[string]string{"word/document.xml": "<w/>", "docProps/app.xml": "<Properties><Pages>5</Pages></Properties>"}), Measures{Pages: 5}},
		{"unsaved.docx", sampleZip(t, map[string]string{"word/document.xml": "<w/>"}), Measures{Unmeasured: true}},
		{"a.odt", sampleZip(t, map[string]string{"meta.xml": `<meta:document-statistic meta:page-count="9" meta:word-count="10"/>`}), Measures{Pages: 9}},
		{"a.pptx", sampleZip(t, map[string]string{"ppt/slides/slide1.xml": "", "ppt/slides/slide2.xml": "", "ppt/slides/slide10.xml": "",
			"ppt/slides/_rels/slide1.xml.rels": "", "ppt/slideLayouts/slideLayout1.xml": ""}), Measures{Slides: 3}},
		{"a.xlsx", sampleZip(t, map[string]string{"xl/worksheets/sheet1.xml": "", "xl/worksheets/sheet2.xml": "", "xl/workbook.xml": ""}), Measures{Sheets: 2}},
		{"not-a-zip.pptx", []byte("PK\x03\x04 but not really"), Measures{Unmeasured: true}},
		{"a.wav", sampleWAV(3), Measures{Seconds: 3}},
		{"vbr.mp3", sampleMP3(380, true), Measures{Seconds: 380 * 1152 / 44100.0}},
		{"cbr.mp3", sampleMP3(380, false), Measures{Seconds: 380 * 417 * 8 / 128000.0}},
		{"a.flac", sampleFLAC(441000), Measures{Seconds: 10}},
		{"a.ogg", sampleOgg(false, 42), Measures{Seconds: 42}},
		{"a.opus", sampleOgg(true, 61), Measures{Seconds: 61}},
		{"a.m4a", sampleMP4(0, 1000, 125500), Measures{Seconds: 125.5}},
		{"a.mov", sampleMP4(1, 600, 600*3600), Measures{Seconds: 3600}},
		{"a.webm", sampleMKV(95.25), Measures{Seconds: 95.25}},
		{"noise.mp4", bytes.Repeat([]byte{0xff, 0}, 3000), Measures{Unmeasured: true}},
		{"noise.mkv", []byte{0x1a, 0x45, 0xdf, 0xa3, 0x80}, Measures{Unmeasured: true}},
		{"silence.wav", []byte("RIFF\x00\x00\x00\x00WAVEdata\x00\x00\x00\x00"), Measures{Unmeasured: true}},
		{"notes.md", []byte("# Notes\n"), Measures{}},
	} {
		got := Measure(bytes.NewReader(c.data), int64(len(c.data)), c.name)
		if got.Pages != c.want.Pages || got.Slides != c.want.Slides || got.Sheets != c.want.Sheets ||
			got.Unmeasured != c.want.Unmeasured || !near(got.Seconds, c.want.Seconds) {
			t.Errorf("%s: %+v, want %+v", c.name, got, c.want)
		}
	}
}

// A large PDF is read by its ends only.
func TestMeasureReadsALargePDFByItsEnds(t *testing.T) {
	head := samplePDF(4)
	size := int64(maxPDFRead + 1)
	r := sparse{head: head, size: size}
	if got := Measure(r, size, "scan.pdf"); got.Pages != 4 || got.Unmeasured {
		t.Fatal(got)
	}
}

// sparse is a file of size bytes whose start is head and the rest zeros.
type sparse struct {
	head []byte
	size int64
}

func (s sparse) ReadAt(p []byte, off int64) (int, error) {
	for i := range p {
		pos := off + int64(i)
		switch {
		case pos >= s.size:
			return i, bytes.ErrTooLarge
		case pos < int64(len(s.head)):
			p[i] = s.head[pos]
		default:
			p[i] = 0
		}
	}
	return len(p), nil
}

func TestTextTokens(t *testing.T) {
	if TextTokens(KindMarkdown, 4001) != 1001 || TextTokens(KindCSV, 0) != 0 || TextTokens(KindPDF, 4000) != 0 {
		t.Fatal("tokens")
	}
}
