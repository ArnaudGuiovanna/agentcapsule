package source

import (
	"archive/zip"
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"fmt"
	"math"
	"testing"
)

// Samples of each measured format, made here: the smallest files whose
// headers say what a real file's would.

func samplePDF(pages int) []byte {
	var b bytes.Buffer
	b.WriteString("%PDF-1.4\n1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj\n")
	fmt.Fprintf(&b, "2 0 obj << /Type /Pages /Kids [3 0 R] /Count %d >> endobj\n", pages)
	for i := range pages {
		fmt.Fprintf(&b, "%d 0 obj << /Type /Page /Parent 2 0 R >> endobj\n", i+3)
	}
	b.WriteString("trailer << /Root 1 0 R >>\n%%EOF\n")
	return b.Bytes()
}

// samplePDFObjectStreams hides the page tree and the pages in a compressed
// object stream, as PDF 1.5 producers do.
func samplePDFObjectStreams(t *testing.T, pages int) []byte {
	var objects bytes.Buffer
	fmt.Fprintf(&objects, "<< /Type /Pages /Kids [] /Count %d >>", pages)
	for range pages {
		objects.WriteString("<</Type/Page/Parent 2 0 R>>")
	}
	var z bytes.Buffer
	w := zlib.NewWriter(&z)
	if _, err := w.Write(objects.Bytes()); err != nil {
		t.Fatal(err)
	}
	w.Close()
	var b bytes.Buffer
	b.WriteString("%PDF-1.5\n%\xe2\xe3\xcf\xd3\n")
	fmt.Fprintf(&b, "5 0 obj\n<</Type/ObjStm/N %d/First 10/Filter/FlateDecode/Length %d>>\nstream\r\n", pages+1, z.Len())
	b.Write(z.Bytes())
	b.WriteString("\r\nendstream\nendobj\n%%EOF\n")
	return b.Bytes()
}

func sampleZip(t *testing.T, files map[string]string) []byte {
	var b bytes.Buffer
	w := zip.NewWriter(&b)
	for name, data := range files {
		f, err := w.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = f.Write([]byte(data)); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func le16(v uint16) []byte { return binary.LittleEndian.AppendUint16(nil, v) }
func le32(v uint32) []byte { return binary.LittleEndian.AppendUint32(nil, v) }
func be32(v uint32) []byte { return binary.BigEndian.AppendUint32(nil, v) }

// sampleWAV: 16 kHz, 16-bit mono, a LIST chunk before the data.
func sampleWAV(seconds int) []byte {
	data := make([]byte, 32000*seconds)
	var b bytes.Buffer
	b.WriteString("RIFF")
	b.Write(le32(uint32(4 + 8 + 16 + 8 + 4 + 8 + len(data))))
	b.WriteString("WAVEfmt ")
	b.Write(le32(16))
	b.Write(le16(1))
	b.Write(le16(1))
	b.Write(le32(16000))
	b.Write(le32(32000))
	b.Write(le16(2))
	b.Write(le16(16))
	b.WriteString("LIST")
	b.Write(le32(4))
	b.WriteString("INFO")
	b.WriteString("data")
	b.Write(le32(uint32(len(data))))
	b.Write(data)
	return b.Bytes()
}

// sampleMP3: an ID3v2 tag, then MPEG-1 Layer III frames at 128 kbit/s,
// 44.1 kHz, joint stereo; with a Xing header counting frames when xing.
func sampleMP3(frames int, xing bool) []byte {
	var b bytes.Buffer
	b.WriteString("ID3\x04\x00\x00\x00\x00\x00\x0a")
	b.Write(make([]byte, 10)) // the tag's 10 bytes
	header := []byte{0xff, 0xfb, 0x90, 0x44}
	frame := make([]byte, 417) // 144 * 128000 / 44100
	copy(frame, header)
	if xing {
		first := bytes.Clone(frame)
		copy(first[4+32:], "Xing")
		copy(first[4+32+4:], be32(1))
		copy(first[4+32+8:], be32(uint32(frames)))
		b.Write(first)
	}
	for range frames {
		b.Write(frame)
	}
	return b.Bytes()
}

// sampleFLAC: STREAMINFO of 44.1 kHz and the given samples.
func sampleFLAC(samples uint64) []byte {
	var b bytes.Buffer
	b.WriteString("fLaC")
	b.Write([]byte{0x80, 0, 0, 34})
	info := make([]byte, 34)
	v := uint64(44100)<<44 | uint64(1)<<41 | uint64(15)<<36 | samples
	binary.BigEndian.PutUint64(info[10:], v)
	b.Write(info)
	return b.Bytes()
}

func oggPage(granule int64, serial uint32, body []byte) []byte {
	var b bytes.Buffer
	b.WriteString("OggS\x00\x02")
	b.Write(binary.LittleEndian.AppendUint64(nil, uint64(granule)))
	b.Write(le32(serial))
	b.Write(le32(0))
	b.Write(le32(0))
	b.Write([]byte{1, byte(len(body))})
	b.Write(body)
	return b.Bytes()
}

// sampleOgg: a Vorbis stream at 44.1 kHz, or an Opus stream (48 kHz
// granules, a pre-skip of 312), lasting seconds.
func sampleOgg(opus bool, seconds int64) []byte {
	var id []byte
	var granule int64
	if opus {
		id = append([]byte("OpusHead\x01\x02"), le16(312)...)
		id = append(id, le32(48000)...)
		granule = seconds*48000 + 312
	} else {
		id = append([]byte("\x01vorbis"), le32(0)...)
		id = append(id, 2)
		id = append(id, le32(44100)...)
		id = append(id, make([]byte, 13)...)
		granule = seconds * 44100
	}
	b := oggPage(0, 7, id)
	b = append(b, oggPage(1000, 7, make([]byte, 200))...)
	b = append(b, oggPage(granule, 7, make([]byte, 100))...)
	b = append(b, oggPage(-1, 9, make([]byte, 10))...) // another stream's page
	return b
}

func mp4Box(kind string, payload []byte) []byte {
	return append(append(be32(uint32(8+len(payload))), kind...), payload...)
}

// sampleMP4: ftyp, a media box, then the movie box with its header (version
// 0 or 1), as a file written without moving moov to the front.
func sampleMP4(version byte, scale uint32, units uint64) []byte {
	var mvhd []byte
	if version == 1 {
		mvhd = append([]byte{1, 0, 0, 0}, make([]byte, 16)...)
		mvhd = append(mvhd, be32(scale)...)
		mvhd = binary.BigEndian.AppendUint64(mvhd, units)
	} else {
		mvhd = append([]byte{0, 0, 0, 0}, make([]byte, 8)...)
		mvhd = append(mvhd, be32(scale)...)
		mvhd = append(mvhd, be32(uint32(units))...)
	}
	mvhd = append(mvhd, make([]byte, 80)...)
	b := mp4Box("ftyp", []byte("isom\x00\x00\x02\x00isomiso2"))
	b = append(b, mp4Box("mdat", make([]byte, 5000))...)
	return append(b, mp4Box("moov", append(mp4Box("udta", nil), mp4Box("mvhd", mvhd)...))...)
}

func ebml(id uint32, payload []byte) []byte {
	var b []byte
	for shift := 24; shift >= 0; shift -= 8 {
		if c := byte(id >> shift); c != 0 || len(b) > 0 {
			b = append(b, c)
		}
	}
	return append(append(b, 0x01, 0, 0, 0, 0, 0, 0, byte(len(payload))), payload...) // an 8-byte size
}

// sampleMKV: an EBML header, then a Segment of unknown size whose Info
// gives a 64-bit Duration in milliseconds, and a cluster.
func sampleMKV(seconds float64) []byte {
	b := ebml(0x1a45dfa3, ebml(0x4282, []byte("webm")))
	info := append(ebml(0x2ad7b1, []byte{0x0f, 0x42, 0x40}),
		ebml(0x4489, binary.BigEndian.AppendUint64(nil, math.Float64bits(seconds*1000)))...)
	segment := append(ebml(0x114d9b74, make([]byte, 20)), ebml(0x1549a966, info)...)
	segment = append(segment, ebml(0x1f43b675, make([]byte, 100))...)
	b = append(b, 0x18, 0x53, 0x80, 0x67, 0x01, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff)
	return append(b, segment...)
}
