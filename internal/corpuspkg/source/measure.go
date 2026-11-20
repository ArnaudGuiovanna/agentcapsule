package source

import (
	"archive/zip"
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"errors"
	"io"
	"math"
	"path"
	"regexp"
	"strconv"
	"strings"
)

// Measures are what a build will process in one file, read from its headers
// and indexes: Measure never runs a program, never decodes audio, video or
// images, and inflates at most a few small compressed parts (a document's
// statistics, a PDF's object streams), each bounded. Unmeasured is set when
// a measure applies to the kind but could not be read so.
type Measures struct {
	Pages      int     `json:"pages,omitempty"`
	Slides     int     `json:"slides,omitempty"`
	Sheets     int     `json:"sheets,omitempty"`
	Seconds    float64 `json:"seconds,omitempty"`
	Tokens     int64   `json:"tokens,omitempty"`
	Unmeasured bool    `json:"unmeasured,omitempty"`
}

// Bounds of what Measure reads.
const (
	maxPDFRead      = 128 << 20 // a PDF read whole; a larger one by its first and last pdfEnds bytes
	pdfEnds         = 32 << 20
	maxInflated     = 64 << 20 // inflated object streams of one PDF
	maxObjectStream = 16 << 20 // one object stream, inflated
	maxZipEntries   = 100000
	maxZipPart      = 1 << 20 // a document's statistics part, inflated
	maxBoxes        = 4096    // MP4 boxes walked
	ebmlRead        = 1 << 20 // the head of a Matroska or WebM file
)

func measurable(k Kind) bool {
	switch k {
	case KindPDF, KindDOCX, KindODT, KindPPTX, KindXLSX, KindAudio, KindVideo:
		return true
	}
	return false
}

// TextTokens estimates the tokens of a text file of n bytes: one per four
// bytes. Other kinds give 0.
func TextTokens(k Kind, n int64) int64 {
	if k == KindMarkdown || k == KindText || k == KindCSV {
		return (n + 3) / 4
	}
	return 0
}

// Measure reads the pages of a PDF, DOCX or ODT file (as its producer
// recorded them), the slides of a PPTX, the sheets of an XLSX and the
// duration of audio and video (WAV, MP3, FLAC, Ogg Vorbis and Opus, MP4 and
// QuickTime, Matroska and WebM) from r, size bytes, named name.
func Measure(r io.ReaderAt, size int64, name string) Measures {
	var m Measures
	var ok bool
	switch kind := KindOf(name); kind {
	case KindPDF:
		m.Pages, ok = pdfPages(r, size)
	case KindDOCX, KindODT, KindPPTX, KindXLSX:
		var n int
		n, ok = zipCount(r, size, kind)
		switch kind {
		case KindPPTX:
			m.Slides = n
		case KindXLSX:
			m.Sheets = n
		default:
			m.Pages = n
		}
	case KindAudio, KindVideo:
		m.Seconds, ok = duration(r, size, strings.ToLower(path.Ext(name)))
		ok = ok && m.Seconds > 0 && m.Seconds < 1e7 && !math.IsNaN(m.Seconds)
		if !ok {
			m.Seconds = 0
		}
	default:
		return m
	}
	m.Unmeasured = !ok
	return m
}

func readAt(r io.ReaderAt, off, n int64) []byte {
	if off < 0 || n <= 0 {
		return nil
	}
	b := make([]byte, n)
	got, _ := r.ReadAt(b, off)
	return b[:got]
}

var (
	pdfLinearized = regexp.MustCompile(`/Linearized\s[^>]*?/N\s+(\d+)`)
	pdfTree       = regexp.MustCompile(`/Type\s*/Pages\b[^>]*?/Count\s+(\d+)|/Count\s+(\d+)[^>]*?/Type\s*/Pages\b`)
	pdfPage       = regexp.MustCompile(`/Type\s*/Page\b`)
	pdfObjStm     = regexp.MustCompile(`/Type\s*/ObjStm\b`)
	pdfLength     = regexp.MustCompile(`/Length\s+(\d+)(\s+\d+\s+R)?`)
	pdfFlate      = regexp.MustCompile(`/Filter\s*\[?\s*/FlateDecode\s*\]?`)
)

// pdfPages reads the page count a PDF declares: its linearization
// dictionary, else the largest /Count of its page tree nodes, else the
// number of its page objects; in its body and in its object streams
// (inflated, bounded).
func pdfPages(r io.ReaderAt, size int64) (int, bool) {
	var parts [][]byte
	if size <= maxPDFRead {
		parts = [][]byte{readAt(r, 0, size)}
	} else {
		parts = [][]byte{readAt(r, 0, pdfEnds), readAt(r, size-pdfEnds, pdfEnds)}
	}
	if m := pdfLinearized.FindSubmatch(parts[0][:min(len(parts[0]), 2048)]); m != nil {
		if n, err := strconv.Atoi(string(m[1])); err == nil && n > 0 {
			return n, true
		}
	}
	tree, pages, budget := 0, 0, int64(maxInflated)
	scan := func(b []byte) {
		for _, m := range pdfTree.FindAllSubmatch(b, -1) {
			n, _ := strconv.Atoi(string(m[1]) + string(m[2]))
			tree = max(tree, n)
		}
		pages += len(pdfPage.FindAllIndex(b, -1))
	}
	for _, b := range parts {
		scan(b)
		for _, loc := range pdfObjStm.FindAllIndex(b, 10000) {
			start := bytes.LastIndex(b[max(0, loc[0]-1024):loc[0]], []byte("<<"))
			end := bytes.Index(b[loc[1]:min(len(b), loc[1]+1024)], []byte(">>"))
			if start < 0 || end < 0 || budget <= 0 {
				continue
			}
			dict := b[max(0, loc[0]-1024)+start : loc[1]+end]
			length := pdfLength.FindSubmatch(dict)
			if length == nil || len(length[2]) > 0 || !pdfFlate.Match(dict) {
				continue // an indirect length, or another filter
			}
			n, err := strconv.Atoi(string(length[1]))
			body := bytes.TrimLeft(b[loc[1]+end+2:], " \t\r\n")
			body, found := bytes.CutPrefix(body, []byte("stream"))
			body = bytes.TrimPrefix(bytes.TrimPrefix(body, []byte("\r")), []byte("\n"))
			if err != nil || !found || n <= 0 || n > len(body) {
				continue
			}
			z, err := zlib.NewReader(bytes.NewReader(body[:n]))
			if err != nil {
				continue
			}
			inflated, _ := io.ReadAll(io.LimitReader(z, min(budget, maxObjectStream)))
			budget -= int64(len(inflated))
			scan(inflated)
		}
	}
	switch {
	case tree > 0:
		return tree, true
	case pages > 0:
		return pages, true
	}
	return 0, false
}

var (
	pptxSlide = regexp.MustCompile(`^ppt/slides/slide\d+\.xml$`)
	xlsxSheet = regexp.MustCompile(`^xl/worksheets/sheet\d+\.xml$`)
	docxPages = regexp.MustCompile(`<Pages>\s*(\d+)\s*</Pages>`)
	odtPages  = regexp.MustCompile(`meta:page-count="(\d+)"`)
)

// zipCount counts the slides of a PPTX or the sheets of an XLSX from the
// archive's central directory, without inflating anything, or reads the
// page count a DOCX (docProps/app.xml) or an ODT (meta.xml) recorded when
// it was saved, inflating that part only, at most 1 MiB of it.
func zipCount(r io.ReaderAt, size int64, kind Kind) (int, bool) {
	z, err := zip.NewReader(r, size)
	if err != nil && !errors.Is(err, zip.ErrInsecurePath) || len(z.File) > maxZipEntries {
		return 0, false
	}
	count := func(name *regexp.Regexp) (int, bool) {
		n := 0
		for _, f := range z.File {
			if name.MatchString(f.Name) {
				n++
			}
		}
		return n, n > 0
	}
	part := func(name string, field *regexp.Regexp) (int, bool) {
		for _, f := range z.File {
			if f.Name != name {
				continue
			}
			rc, err := f.Open()
			if err != nil {
				return 0, false
			}
			b, _ := io.ReadAll(io.LimitReader(rc, maxZipPart))
			rc.Close()
			if m := field.FindSubmatch(b); m != nil {
				if n, err := strconv.Atoi(string(m[1])); err == nil && n > 0 {
					return n, true
				}
			}
			return 0, false
		}
		return 0, false
	}
	switch kind {
	case KindPPTX:
		return count(pptxSlide)
	case KindXLSX:
		return count(xlsxSheet)
	case KindDOCX:
		return part("docProps/app.xml", docxPages)
	case KindODT:
		return part("meta.xml", odtPages)
	}
	return 0, false
}

// duration reads the duration an audio or video file's headers give.
func duration(r io.ReaderAt, size int64, ext string) (float64, bool) {
	switch ext {
	case ".wav":
		return wavSeconds(r, size)
	case ".mp3":
		return mp3Seconds(r, size)
	case ".flac":
		return flacSeconds(r)
	case ".ogg", ".opus":
		return oggSeconds(r, size)
	case ".mp4", ".m4a", ".m4v", ".mov":
		return mp4Seconds(r, size)
	case ".webm", ".mkv":
		return ebmlSeconds(r, size)
	}
	return 0, false
}

// wavSeconds: the data chunk's size over the format chunk's byte rate.
func wavSeconds(r io.ReaderAt, size int64) (float64, bool) {
	h := readAt(r, 0, 12)
	if len(h) < 12 || string(h[0:4]) != "RIFF" || string(h[8:12]) != "WAVE" {
		return 0, false
	}
	var byteRate uint32
	off := int64(12)
	for range 64 {
		c := readAt(r, off, 8)
		if len(c) < 8 {
			return 0, false
		}
		n := int64(binary.LittleEndian.Uint32(c[4:]))
		switch string(c[0:4]) {
		case "fmt ":
			f := readAt(r, off+8, 16)
			if len(f) < 16 {
				return 0, false
			}
			byteRate = binary.LittleEndian.Uint32(f[8:])
		case "data":
			if byteRate == 0 {
				return 0, false
			}
			if n == 0xffffffff || off+8+n > size { // streamed: the data runs to the end
				n = size - off - 8
			}
			return float64(n) / float64(byteRate), true
		}
		off += 8 + n + n%2
	}
	return 0, false
}

var (
	mp3Rates = [4][3]int{{11025, 12000, 8000}, {}, {22050, 24000, 16000}, {44100, 48000, 32000}}
	// kbit/s by MPEG version 1 or 2 (2.5 as 2), layer I, II, III.
	mp3Bitrates = [2][3][15]int{
		{{0, 32, 64, 96, 128, 160, 192, 224, 256, 288, 320, 352, 384, 416, 448},
			{0, 32, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320, 384},
			{0, 32, 40, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320}},
		{{0, 32, 48, 56, 64, 80, 96, 112, 128, 144, 160, 176, 192, 224, 256},
			{0, 8, 16, 24, 32, 40, 48, 56, 64, 80, 96, 112, 128, 144, 160},
			{0, 8, 16, 24, 32, 40, 48, 56, 64, 80, 96, 112, 128, 144, 160}},
	}
)

// mp3Seconds: after an ID3v2 tag, the first frame's Xing, Info or VBRI
// header gives the frame count; without one, the stream is taken as of a
// constant bit rate.
func mp3Seconds(r io.ReaderAt, size int64) (float64, bool) {
	start := int64(0)
	if h := readAt(r, 0, 10); len(h) == 10 && string(h[0:3]) == "ID3" {
		start = 10 + int64(h[6]&0x7f)<<21 | int64(h[7]&0x7f)<<14 | int64(h[8]&0x7f)<<7 | int64(h[9]&0x7f)
		if h[5]&0x10 != 0 {
			start += 10
		}
	}
	b := readAt(r, start, 64<<10)
	for i := 0; i+4 <= len(b); i++ {
		if b[i] != 0xff || b[i+1]&0xe0 != 0xe0 {
			continue
		}
		version, layer := b[i+1]>>3&3, b[i+1]>>1&3
		bitrateIndex, rateIndex := int(b[i+2]>>4), int(b[i+2]>>2&3)
		if version == 1 || layer == 0 || bitrateIndex == 0 || bitrateIndex == 15 || rateIndex == 3 {
			continue
		}
		rate := mp3Rates[version][rateIndex]
		mpeg1 := version == 3
		v := 1
		if mpeg1 {
			v = 0
		}
		bitrate := mp3Bitrates[v][3-layer][bitrateIndex] * 1000
		samples := 1152
		switch {
		case layer == 3:
			samples = 384
		case layer == 1 && !mpeg1:
			samples = 576
		}
		mono := b[i+3]>>6 == 3
		side := map[[2]bool]int{{true, false}: 32, {true, true}: 17, {false, false}: 17, {false, true}: 9}[[2]bool{mpeg1, mono}]
		frames := uint32(0)
		if x := b[min(len(b), i+4+side):]; len(x) >= 12 && (string(x[0:4]) == "Xing" || string(x[0:4]) == "Info") &&
			binary.BigEndian.Uint32(x[4:])&1 != 0 {
			frames = binary.BigEndian.Uint32(x[8:])
		} else if x := b[min(len(b), i+36):]; len(x) >= 18 && string(x[0:4]) == "VBRI" {
			frames = binary.BigEndian.Uint32(x[14:])
		}
		if frames > 0 {
			return float64(frames) * float64(samples) / float64(rate), true
		}
		audio := size - start - int64(i)
		return float64(audio) * 8 / float64(bitrate), audio > 0
	}
	return 0, false
}

// flacSeconds: the STREAMINFO block's total samples over its sample rate.
func flacSeconds(r io.ReaderAt) (float64, bool) {
	b := readAt(r, 0, 42)
	if len(b) < 42 || string(b[0:4]) != "fLaC" || b[4]&0x7f != 0 {
		return 0, false
	}
	v := binary.BigEndian.Uint64(b[8+10:])
	rate, samples := v>>44, v&(1<<36-1)
	if rate == 0 || samples == 0 {
		return 0, false
	}
	return float64(samples) / float64(rate), true
}

// oggSeconds: the last page's granule position, at the rate the first
// page's Vorbis or Opus header gives.
func oggSeconds(r io.ReaderAt, size int64) (float64, bool) {
	b := readAt(r, 0, 512)
	if len(b) < 28 || string(b[0:4]) != "OggS" {
		return 0, false
	}
	serial := binary.LittleEndian.Uint32(b[14:])
	body := b[min(len(b), 27+int(b[26])):]
	var rate, skip float64
	switch {
	case len(body) >= 16 && string(body[0:7]) == "\x01vorbis":
		rate = float64(binary.LittleEndian.Uint32(body[12:]))
	case len(body) >= 12 && string(body[0:8]) == "OpusHead":
		rate, skip = 48000, float64(binary.LittleEndian.Uint16(body[10:]))
	}
	if rate == 0 {
		return 0, false
	}
	tail := readAt(r, max(0, size-(64<<10)), min(size, 64<<10))
	for i := bytes.LastIndex(tail, []byte("OggS")); i >= 0; i = bytes.LastIndex(tail[:i], []byte("OggS")) {
		if len(tail) < i+27 || tail[i+4] != 0 || binary.LittleEndian.Uint32(tail[i+14:]) != serial {
			continue
		}
		granule := int64(binary.LittleEndian.Uint64(tail[i+6:]))
		if granule > 0 {
			return (float64(granule) - skip) / rate, true
		}
	}
	return 0, false
}

// mp4Seconds: the movie header's duration over its time scale, from the
// top-level moov box wherever it lies.
func mp4Seconds(r io.ReaderAt, size int64) (float64, bool) {
	box := func(off, end int64) (string, int64, int64, bool) { // type, payload offset, box end
		h := readAt(r, off, 16)
		if len(h) < 8 {
			return "", 0, 0, false
		}
		n, header := int64(binary.BigEndian.Uint32(h)), int64(8)
		switch {
		case n == 1 && len(h) == 16:
			n, header = int64(binary.BigEndian.Uint64(h[8:])), 16
		case n == 0:
			n = end - off
		}
		if n < header || off+n > end || n < 0 {
			return "", 0, 0, false
		}
		return string(h[4:8]), off + header, off + n, true
	}
	off := int64(0)
	for range maxBoxes {
		kind, payload, next, ok := box(off, size)
		if !ok {
			return 0, false
		}
		if kind == "moov" {
			for child := payload; child < next; {
				ckind, cpayload, cnext, ok := box(child, next)
				if !ok {
					return 0, false
				}
				if ckind == "mvhd" {
					h := readAt(r, cpayload, 32)
					if len(h) < 20 {
						return 0, false
					}
					var scale uint32
					var units uint64
					if h[0] == 1 && len(h) >= 32 {
						scale, units = binary.BigEndian.Uint32(h[20:]), binary.BigEndian.Uint64(h[24:])
					} else {
						scale, units = binary.BigEndian.Uint32(h[12:]), uint64(binary.BigEndian.Uint32(h[16:]))
					}
					if scale == 0 {
						return 0, false
					}
					return float64(units) / float64(scale), true
				}
				child = cnext
			}
			return 0, false
		}
		off = next
	}
	return 0, false
}

// ebmlSeconds: the Segment Info's Duration times its TimestampScale, from
// the first megabyte of a Matroska or WebM file.
func ebmlSeconds(r io.ReaderAt, size int64) (float64, bool) {
	b := readAt(r, 0, min(size, ebmlRead))
	vint := func(i int, keepMarker bool) (uint64, int, bool) {
		if i >= len(b) || b[i] == 0 {
			return 0, 0, false
		}
		n := 1
		for mask := byte(0x80); b[i]&mask == 0; mask >>= 1 {
			n++
		}
		if i+n > len(b) {
			return 0, 0, false
		}
		v := uint64(b[i])
		if !keepMarker {
			v &= uint64(0xff >> n)
		}
		unknown := v == uint64(0xff>>n)
		for _, c := range b[i+1 : i+n] {
			v = v<<8 | uint64(c)
			unknown = unknown && c == 0xff
		}
		if unknown && !keepMarker {
			v = math.MaxUint64
		}
		return v, n, true
	}
	element := func(i int) (uint64, int, int, bool) { // id, data start, data end
		id, n, ok := vint(i, true)
		if !ok {
			return 0, 0, 0, false
		}
		length, m, ok := vint(i+n, false)
		if !ok {
			return 0, 0, 0, false
		}
		start := i + n + m
		end := len(b)
		if length != math.MaxUint64 && length < uint64(len(b)-start) {
			end = start + int(length)
		}
		return id, start, end, true
	}
	scale, dur := 1e6, -1.0
	var walk func(i, end, depth int) bool
	walk = func(i, end, depth int) bool {
		for i < end && depth < 4 {
			id, start, stop, ok := element(i)
			if !ok {
				return false
			}
			switch id {
			case 0x18538067, 0x1549a966: // Segment, Info
				walk(start, stop, depth+1)
				if dur >= 0 {
					return true
				}
			case 0x2ad7b1: // TimestampScale
				v := uint64(0)
				for _, c := range b[start:stop] {
					v = v<<8 | uint64(c)
				}
				scale = float64(v)
			case 0x4489: // Duration
				switch stop - start {
				case 4:
					dur = float64(math.Float32frombits(binary.BigEndian.Uint32(b[start:])))
				case 8:
					dur = math.Float64frombits(binary.BigEndian.Uint64(b[start:]))
				}
			case 0x1f43b675: // Cluster: the Info comes before
				return dur >= 0
			}
			i = stop
		}
		return dur >= 0
	}
	if !walk(0, len(b), 0) || dur <= 0 || scale <= 0 {
		return 0, false
	}
	return dur * scale / 1e9, true
}
