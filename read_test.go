package pdf

import (
	"bytes"
	"compress/zlib"
	"fmt"
	"io"
	"os"
	"runtime"
	"slices"
	"strings"
	"testing"
)

func TestReadObject(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		wantKind Kind
	}{
		{"Dictionary", "<< /Key1 (Val1) /Key2 123 >> ", Dict},
		{"Array", "[ 1 2 (3) /Name ] ", Array},
		{"Nested", "<< /Arr [ 1 << /K /V >> ] >> ", Dict},
		{"Indirect", "10 0 R ", Indirect},
		{"HexString", "<414243> ", String},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := newBuffer(io.NewSectionReader(bytes.NewReader([]byte(tt.input)), 0, int64(len(tt.input))), 0, 0)
			obj := b.readObject()
			if obj.Kind != tt.wantKind {
				t.Errorf("%s: readObject().Kind = %v, want %v", tt.name, obj.Kind, tt.wantKind)
			}
		})
	}
}

func TestReader(t *testing.T) {
	// Use testfile12.pdf from root testfiles
	file := "../../testfiles/testfile12.pdf"
	f, err := os.Open(file)
	if err != nil {
		t.Skip("testfile12.pdf not found, skipping integration test")
		return
	}
	defer f.Close()

	fi, _ := f.Stat()
	r, err := NewReader(f, fi.Size())
	if err != nil {
		t.Fatalf("NewReader failed: %v", err)
	}

	if r.NumPage() == 0 {
		t.Error("NumPage() returned 0")
	}

	// Try to resolve an object
	found := false
	for id, x := range r.xref {
		if x.offset > 0 {
			obj, err := r.GetObject(uint32(id))
			if err != nil {
				t.Errorf("GetObject(%d) failed: %v", id, err)
			} else if obj.Kind() == Null {
				t.Errorf("GetObject(%d) returned Null", id)
			}
			found = true
			break
		}
	}
	if !found {
		t.Error("No objects found in xref")
	}
}

func TestReadDict(t *testing.T) {
	input := "<< /Type /Catalog /Pages 2 0 R /Empty () >>"
	b := newBuffer(io.NewSectionReader(bytes.NewReader([]byte(input)), 0, int64(len(input))), 0, 0)
	// skip '<<'
	b.readToken()
	obj := b.readDict()

	if obj.Kind != Dict {
		t.Fatalf("Expected Dict, got %v", obj.Kind)
	}

	if obj.DictVal["Type"].NameVal != "Catalog" {
		t.Errorf("Type mismatch: %q", obj.DictVal["Type"].NameVal)
	}

	if obj.DictVal["Pages"].Kind != Indirect {
		t.Errorf("Pages should be Indirect, got %v", obj.DictVal["Pages"].Kind)
	}

	if obj.DictVal["Pages"].PtrVal.id != 2 {
		t.Errorf("Pages ID mismatch: %d", obj.DictVal["Pages"].PtrVal.id)
	}
}

func TestReadArray(t *testing.T) {
	input := "[ 1 2.5 (string) /Name [ 3 ] ]"
	b := newBuffer(io.NewSectionReader(bytes.NewReader([]byte(input)), 0, int64(len(input))), 0, 0)
	// skip '['
	b.readToken()
	obj := b.readArray()

	if obj.Kind != Array {
		t.Fatalf("Expected Array, got %v", obj.Kind)
	}

	if len(obj.ArrayVal) != 5 {
		t.Errorf("Length mismatch: %d", len(obj.ArrayVal))
	}

	if obj.ArrayVal[0].Int64Val != 1 {
		t.Errorf("Index 0 mismatch: %d", obj.ArrayVal[0].Int64Val)
	}

	if obj.ArrayVal[1].Float64Val != 2.5 {
		t.Errorf("Index 1 mismatch: %f", obj.ArrayVal[1].Float64Val)
	}
}

func TestOpen(t *testing.T) {
	// Root testfiles
	file := "../../testfiles/testfile12.pdf"
	r, err := Open(file)
	if err != nil {
		t.Skipf("Open failed: %v", err)
	}
	defer r.Close()

	if r.NumPage() == 0 {
		t.Error("Open() returned reader with 0 pages")
	}
}

func TestReaderUtilities(t *testing.T) {
	r := &Reader{}
	r.trailer = Object{Kind: Dict, DictVal: map[string]Object{"Size": {Kind: Integer, Int64Val: 10}}}

	if r.Trailer().Kind() != Dict {
		t.Error("Trailer() failed")
	}

	if len(r.Xref()) != 0 {
		t.Error("Xref() should be empty for new reader")
	}

	dict := GetDict()
	if dict.Kind != Dict {
		t.Error("GetDict() failed")
	}
}

// passwordOnce returns a password callback that gives password once, so that
// NewReaderEncrypted stops instead of retrying a wrong password forever.
func passwordOnce(password string) func() string {
	asked := false
	return func() string {
		if asked {
			return ""
		}
		asked = true
		return password
	}
}

func TestNewReaderEncryptedV5(t *testing.T) {
	uHex := "8a35e0ef6b995a3af7a084c7b39f3f9aa96f4ce6b961d27d5ee084a779b93ec331323334353637383837363534333231"
	ueHex := "fdf2ebcf67bd7c6f527008513dd4c01c4d5a3db53b16f3713ab07e58e67026e9"

	var buf bytes.Buffer
	buf.WriteString("%PDF-1.7\n")
	off1 := buf.Len()
	buf.WriteString("1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n")
	off2 := buf.Len()
	buf.WriteString("2 0 obj\n<< /Type /Pages /Count 0 /Kids [] >>\nendobj\n")
	off3 := buf.Len()
	buf.WriteString(fmt.Sprintf("3 0 obj\n<< /Filter /Standard /V 5 /R 5 /CF << /StdCF << /AuthEvent /DocOpen /CFM /AESV3 /Length 32 >> >> /StmF /StdCF /StrF /StdCF /O <%s> /U <%s> /OE <%s> /UE <%s> >>\nendobj\n", uHex, uHex, ueHex, ueHex))
	xrefPos := buf.Len()
	buf.WriteString("xref\n0 4\n0000000000 65535 f \n")
	buf.WriteString(fmt.Sprintf("%010d 00000 n \n", off1))
	buf.WriteString(fmt.Sprintf("%010d 00000 n \n", off2))
	buf.WriteString(fmt.Sprintf("%010d 00000 n \n", off3))
	buf.WriteString(fmt.Sprintf("trailer\n<< /Size 4 /Root 1 0 R /Encrypt 3 0 R /ID [<%s><%s>] >>\n", "00112233445566778899AABBCCDDEEFF", "00112233445566778899AABBCCDDEEFF"))
	buf.WriteString("startxref\n")
	buf.WriteString(fmt.Sprintf("%d\n", xrefPos))
	buf.WriteString("%%EOF\n")

	data := buf.Bytes()
	r, err := NewReaderEncrypted(bytes.NewReader(data), int64(len(data)), passwordOnce("user"))
	if err != nil {
		t.Fatalf("NewReaderEncrypted V5 failed: %v", err)
	}

	if r.encVersion != 5 {
		t.Errorf("expected encVersion 5, got %d", r.encVersion)
	}
}

func TestReader_Errorf(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Errorf("errorf did not panic")
		}
	}()
	r := &Reader{}
	r.errorf("test error")
}

func TestReaderXrefInformation_PrintDebug(t *testing.T) {
	info := &ReaderXrefInformation{
		Type: "test",
	}
	info.PrintDebug() // Just for coverage
}

func TestApplyFilter_Error(t *testing.T) {
	_, err := applyFilter(bytes.NewReader(nil), "UnknownFilter", Value{})
	if err == nil {
		t.Error("expected error for unknown filter")
	}
}

// TestNewReaderEncryptedV4 opens an AES-128 document whose /Encrypt dictionary,
// /ID and encrypted /Title come from a document written by qpdf 12.4 with user
// password "userpw".
func TestNewReaderEncryptedV4(t *testing.T) {
	const qpdfID = "31415926535897932384626433832795"
	objects := []string{
		"<< /Type /Catalog /Pages 2 0 R >>",
		"<< /Title <5cd9dbb47ff2a3a32e1c5839a3a76899dbd33e662410c2344e7e56e263243210> >>",
		"<< /Filter /Standard /V 4 /R 4 /Length 128 /P -4" +
			" /O <07c02079e0d8d0c3404477e977b56ef1720b2f6be2a464225fb7e72ffc05cc7f>" +
			" /U <3eadea12150bd88e74ec04a486eabc780021446990b9e4114071a4d9104984c1>" +
			" /CF << /StdCF << /AuthEvent /DocOpen /CFM /AESV2 /Length 16 >> >> /StmF /StdCF /StrF /StdCF >>",
	}

	var buf bytes.Buffer
	buf.WriteString("%PDF-1.6\n")
	offsets := make([]int, len(objects))
	for i, obj := range objects {
		offsets[i] = buf.Len()
		fmt.Fprintf(&buf, "%d 0 obj\n%s\nendobj\n", i+1, obj)
	}
	xrefPos := buf.Len()
	fmt.Fprintf(&buf, "xref\n0 %d\n0000000000 65535 f \n", len(objects)+1)
	for _, off := range offsets {
		fmt.Fprintf(&buf, "%010d 00000 n \n", off)
	}
	fmt.Fprintf(&buf, "trailer\n<< /Size %d /Root 1 0 R /Info 2 0 R /Encrypt 3 0 R /ID [<%s><%s>] >>\nstartxref\n%d\n%%%%EOF\n",
		len(objects)+1, qpdfID, qpdfID, xrefPos)

	data := buf.Bytes()
	r, err := NewReaderEncrypted(bytes.NewReader(data), int64(len(data)), passwordOnce("userpw"))
	if err != nil {
		t.Fatalf("NewReaderEncrypted: %v", err)
	}
	if r.encVersion != 4 || !r.useAES {
		t.Errorf("encVersion = %d, useAES = %v; want 4, true", r.encVersion, r.useAES)
	}
	if got := r.Trailer().Key("Info").Key("Title").RawString(); got != "Signature 1" {
		t.Errorf("Title = %q, want %q", got, "Signature 1")
	}
}

// xrefStreamFile returns a document whose cross-reference stream declares size
// objects and lists the catalog, the stream itself and, if start is not zero,
// one more entry for the object number start.
func xrefStreamFile(size int64, start int64) []byte {
	var buf bytes.Buffer
	buf.WriteString("%PDF-1.5\n%" + strings.Repeat("x", 300) + "\n")
	catalog := buf.Len()
	buf.WriteString("1 0 obj\n<< /Type /Catalog >>\nendobj\n")
	stream := buf.Len()

	entry := func(t byte, off int, gen byte) []byte { return []byte{t, byte(off >> 8), byte(off), gen} }
	data := entry(0, 65535, 255)
	data = append(data, entry(1, catalog, 0)...)
	data = append(data, entry(1, stream, 0)...)
	index := "[0 3]"
	if start != 0 {
		data = append(data, entry(1, catalog, 0)...)
		index = fmt.Sprintf("[0 3 %d 1]", start)
	}
	fmt.Fprintf(&buf, "2 0 obj\n<< /Type /XRef /Size %d /Index %s /W [1 2 1] /Root 1 0 R /Length %d >>\nstream\n",
		size, index, len(data))
	buf.Write(data)
	buf.WriteString("\nendstream\nendobj\n")
	fmt.Fprintf(&buf, "startxref\n%d\n%%%%EOF\n", stream)
	return buf.Bytes()
}

// allocatedBy returns the bytes that f allocates.
func allocatedBy(f func()) uint64 {
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	f()
	runtime.ReadMemStats(&after)
	return after.TotalAlloc - before.TotalAlloc
}

// compressedXrefFile returns a document of a few hundred bytes whose Flate
// encoded cross-reference stream holds n entries: the catalog, the stream
// itself and free entries.
func compressedXrefFile(n int) []byte {
	var buf bytes.Buffer
	buf.WriteString("%PDF-1.5\n")
	catalog := buf.Len()
	buf.WriteString("1 0 obj\n<< /Type /Catalog >>\nendobj\n")
	stream := buf.Len()

	entries := make([]byte, 0, 4*n)
	entry := func(t byte, off int, gen byte) { entries = append(entries, t, byte(off>>8), byte(off), gen) }
	entry(0, 65535, 255)
	entry(1, catalog, 0)
	entry(1, stream, 0)
	for i := 3; i < n; i++ {
		entry(0, 0, 0)
	}
	var data bytes.Buffer
	zw := zlib.NewWriter(&data)
	zw.Write(entries)
	zw.Close()

	fmt.Fprintf(&buf, "2 0 obj\n<< /Type /XRef /Size %d /W [1 2 1] /Filter /FlateDecode /Root 1 0 R /Length %d >>\nstream\n",
		n, data.Len())
	buf.Write(data.Bytes())
	buf.WriteString("\nendstream\nendobj\n")
	fmt.Fprintf(&buf, "startxref\n%d\n%%%%EOF\n", stream)
	return buf.Bytes()
}

// TestCompressedXrefStreamEntries reads a document whose cross-reference stream
// holds far more entries than the file has bytes, which Flate makes possible.
func TestCompressedXrefStreamEntries(t *testing.T) {
	const n = 10001
	data := compressedXrefFile(n)
	r, err := NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatalf("NewReader for %d entries in %d bytes: %v", n, len(data), err)
	}
	if got := r.Trailer().Key("Root").Key("Type").Name(); got != "Catalog" {
		t.Errorf("Root is %q, want the Catalog", got)
	}
	if len(r.Xref()) != n {
		t.Errorf("the xref table has %d entries, want %d", len(r.Xref()), n)
	}
}

// TestHugeDeclaredXrefSize reads a document whose /Size is far larger than the
// file, which must not make the cross-reference table that large.
func TestHugeDeclaredXrefSize(t *testing.T) {
	data := xrefStreamFile(100000000, 0)
	var r *Reader
	var err error
	alloc := allocatedBy(func() { r, err = NewReader(bytes.NewReader(data), int64(len(data))) })
	if err != nil {
		t.Fatalf("NewReader: %v", err)
	}
	if got := r.Trailer().Key("Root").Key("Type").Name(); got != "Catalog" {
		t.Errorf("Root is %q, want the Catalog", got)
	}
	if len(r.Xref()) > len(data) {
		t.Errorf("the xref table has %d entries for a file of %d bytes", len(r.Xref()), len(data))
	}
	if alloc > 1<<20 {
		t.Errorf("reading a file of %d bytes allocated %d MiB", len(data), alloc>>20)
	}
}

// TestXrefObjectNumberOverLimit reads documents that number an object over the
// architectural limit, which must not size the cross-reference table.
func TestXrefObjectNumberOverLimit(t *testing.T) {
	var table bytes.Buffer
	table.WriteString("%PDF-1.7\n%" + strings.Repeat("x", 300) + "\n")
	catalog := table.Len()
	table.WriteString("1 0 obj\n<< /Type /Catalog >>\nendobj\n")
	xref := table.Len()
	fmt.Fprintf(&table, "xref\n0 2\n0000000000 65535 f \n%010d 00000 n \n100000000 1\n%010d 00000 n \n"+
		"trailer\n<< /Size 2 /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n", catalog, catalog, xref)

	for name, data := range map[string][]byte{
		"xref stream": xrefStreamFile(3, 100000000),
		"xref table":  table.Bytes(),
	} {
		t.Run(name, func(t *testing.T) {
			var err error
			alloc := allocatedBy(func() { _, err = NewReader(bytes.NewReader(data), int64(len(data))) })
			if err == nil {
				t.Error("NewReader: got no error")
			}
			if alloc > 1<<20 {
				t.Errorf("reading a file of %d bytes allocated %d MiB", len(data), alloc>>20)
			}
		})
	}
}

func TestMalformedObjectHeaders(t *testing.T) {
	deep := strings.Repeat("1 0 obj\n", 500000)

	r := &Reader{}
	setObjects(r, deep)
	var v Value
	if !runWithin(t, func() { v, _ = r.GetObject(1) }) {
		t.Fatal("GetObject for deeply nested object definitions did not return")
	}
	if v.Err() == nil {
		t.Error("GetObject for deeply nested object definitions: got no error")
	}
}

func TestTrailingWhitespace(t *testing.T) {
	var file bytes.Buffer
	file.WriteString("%PDF-1.7\n%" + strings.Repeat("x", 400) + "\n")
	catalog := file.Len()
	file.WriteString("1 0 obj\n<< /Type /Catalog >>\nendobj\n")
	xref := file.Len()
	fmt.Fprintf(&file, "xref\n0 2\n0000000000 65535 f \n%010d 00000 n \ntrailer\n<< /Size 2 /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n", catalog, xref)

	for _, tail := range []string{
		"",
		strings.Repeat("\n", 197),
		strings.Repeat("\n", 300),
		strings.Repeat(" ", 197),
		strings.Repeat(" \r\n\t", 100),
	} {
		data := []byte(file.String() + tail)
		r, err := NewReader(bytes.NewReader(data), int64(len(data)))
		if err != nil {
			t.Errorf("NewReader with %d bytes of trailing whitespace: %v", len(tail), err)
			continue
		}
		if got := r.Trailer().Key("Root").Key("Type").Name(); got != "Catalog" {
			t.Errorf("NewReader with %d bytes of trailing whitespace: Root is %q, want the Catalog", len(tail), got)
		}
	}
}

func TestMalformedNesting(t *testing.T) {
	deep := strings.Repeat("[", 300000) + strings.Repeat("]", 300000)

	r := &Reader{}
	setObjects(r, deep)
	var v Value
	if !runWithin(t, func() { v, _ = r.GetObject(1) }) {
		t.Fatal("GetObject for deeply nested arrays did not return")
	}
	if v.Err() == nil {
		t.Error("GetObject for deeply nested arrays: got no error")
	}

	for _, trailer := range []string{
		"<< /Size 2 /Root 1 0 R /ID [ 1 2 endobj >>",
		"<< /Size 2 /Root 1 0 R /X " + deep + " >>",
	} {
		var file bytes.Buffer
		// NewReader needs more than 200 bytes to find %%EOF.
		file.WriteString("%PDF-1.7\n%" + strings.Repeat("x", 400) + "\n")
		catalog := file.Len()
		file.WriteString("1 0 obj\n<< /Type /Catalog >>\nendobj\n")
		xref := file.Len()
		fmt.Fprintf(&file, "xref\n0 2\n0000000000 65535 f \n%010d 00000 n \ntrailer\n%s\nstartxref\n%d\n%%%%EOF\n", catalog, trailer, xref)
		var err error
		if !runWithin(t, func() { _, err = NewReader(bytes.NewReader(file.Bytes()), int64(file.Len())) }) {
			t.Fatalf("NewReader for trailer %.40q did not return", trailer)
		}
		if err == nil {
			t.Errorf("NewReader for trailer %.40q: got no error", trailer)
		}
	}
}

// countingReaderAt counts the reads of the file behind a Reader.
type countingReaderAt struct {
	rd    io.ReaderAt
	reads int
}

func (c *countingReaderAt) ReadAt(b []byte, off int64) (int, error) {
	c.reads++
	return c.rd.ReadAt(b, off)
}

func TestObjectStreamExtends(t *testing.T) {
	// Object stream 1 holds object 3 and extends object stream 2, which holds
	// object 4.
	const stm1 = "<< /Type /ObjStm /N 1 /First 4 /Length 8 /Extends 2 0 R >>\nstream\n3 0 null\nendstream"
	const stm2 = "<< /Type /ObjStm /N 1 /First 4 /Length 11 >>\nstream\n4 0 (found)\nendstream"

	r := &Reader{}
	setObjects(r, stm1, stm2)
	r.xref = append(r.xref, xref{}, xref{})
	r.xref[4] = xref{ptr: objptr{id: 4}, inStream: true, stream: objptr{id: 1}}

	v, err := r.GetObject(4)
	if err != nil || v.RawString() != "found" {
		t.Errorf("GetObject(4) = %v, %v; want found, nil", objfmt(v.obj), err)
	}
}

func TestObjectStreamExtendsCycle(t *testing.T) {
	// Object stream 1 extends itself and does not hold object 4. However many
	// objects the file declares, the chain is walked only once.
	const stm = "<< /Type /ObjStm /N 1 /First 4 /Length 8 /Extends 1 0 R >>\nstream\n3 0 null\nendstream"

	r := &Reader{}
	setObjects(r, stm)
	r.xref = append(r.xref, make([]xref, 10000)...)
	r.xref[4] = xref{ptr: objptr{id: 4}, inStream: true, stream: objptr{id: 1}}
	counter := &countingReaderAt{rd: r.f}
	r.f = counter

	var v Value
	if !runWithin(t, func() { v, _ = r.GetObject(4) }) {
		t.Fatal("GetObject(4) did not return")
	}
	if v.Err() == nil {
		t.Error("GetObject(4): got no error")
	}
	if counter.reads > 10 {
		t.Errorf("GetObject(4) read the file %d times, want at most 10", counter.reads)
	}
}

func TestObjectStreamInObjectStream(t *testing.T) {
	// The xref says that object 4 is in object stream 3, which is itself in
	// object stream 1. A stream cannot be stored in an object stream
	// (ISO 32000-1, 7.5.7), so the chain is not followed at all.
	const stm = "<< /Type /ObjStm /N 1 /First 4 /Length 8 >>\nstream\n2 0 null\nendstream"

	r := &Reader{}
	setObjects(r, stm)
	r.xref = append(r.xref, xref{}, xref{}, xref{})
	r.xref[3] = xref{ptr: objptr{id: 3}, inStream: true, stream: objptr{id: 1}}
	r.xref[4] = xref{ptr: objptr{id: 4}, inStream: true, stream: objptr{id: 3}}
	counter := &countingReaderAt{rd: r.f}
	r.f = counter

	v, _ := r.GetObject(4)
	if v.Err() == nil {
		t.Error("GetObject(4): got no error")
	}
	if counter.reads != 0 {
		t.Errorf("GetObject(4) read the file %d times, want none", counter.reads)
	}
}

func TestMalformedObjectStreams(t *testing.T) {
	// Object 2 is at offset 0 of the object stream data, object 3 is not in it.
	const data = "\nstream\n2 0 null\nendstream"
	tests := []struct {
		name   string
		objStm string
		id     uint32
	}{
		{"cyclic Extends", "<< /Type /ObjStm /N 1 /First 4 /Length 8 /Extends 1 0 R >>" + data, 3},
		{"huge N", "<< /Type /ObjStm /N 9223372036854775807 /First 4 /Length 8 >>" + data, 3},
		{"object stream in itself", "<< /Type /ObjStm /N 1 /First 4 /Length 8 >>" + data, 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &Reader{}
			setObjects(r, tt.objStm)
			r.xref = append(r.xref, xref{}, xref{})
			r.xref[tt.id] = xref{ptr: objptr{id: tt.id}, inStream: true, stream: objptr{id: 1}}

			var v Value
			if !runWithin(t, func() { v, _ = r.GetObject(tt.id) }) {
				t.Fatalf("GetObject(%d) did not return", tt.id)
			}
			if v.Err() == nil {
				t.Errorf("GetObject(%d): got no error", tt.id)
			}
		})
	}
}

// The next section written must not declare a smaller /Size.
func TestXrefStreamItemCount(t *testing.T) {
	data := xrefStreamFile(20, 0)
	r, err := NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatalf("NewReader: %v", err)
	}
	if r.XrefInformation.ItemCount != 20 {
		t.Errorf("ItemCount = %d, want the /Size 20", r.XrefInformation.ItemCount)
	}
}

func TestXrefIndexLimit(t *testing.T) {
	if _, err := xrefIndex(maxObjects); err != nil {
		t.Errorf("xrefIndex(%d): %v", maxObjects, err)
	}
	if _, err := xrefIndex(maxObjects + 1); err == nil {
		t.Errorf("xrefIndex(%d): got no error", maxObjects+1)
	}
}

func xrefTableFile(trailer string) []byte {
	var buf bytes.Buffer
	buf.WriteString("%PDF-1.7\n")
	catalog := buf.Len()
	buf.WriteString("1 0 obj\n<< /Type /Catalog >>\nendobj\n")
	xref := buf.Len()
	fmt.Fprintf(&buf, "xref\n0 2\n0000000000 65535 f \n%010d 00000 n \ntrailer\n%s\nstartxref\n%d\n%%%%EOF\n",
		catalog, trailer, xref)
	return buf.Bytes()
}

func TestShortFile(t *testing.T) {
	data := xrefTableFile("<< /Size 2 /Root 1 0 R >>")
	if len(data) >= 200 {
		t.Fatalf("the document has %d bytes, want less than 200", len(data))
	}
	r, err := NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatalf("NewReader for %d bytes: %v", len(data), err)
	}
	if got := r.Trailer().Key("Root").Key("Type").Name(); got != "Catalog" {
		t.Errorf("Root is %q, want the Catalog", got)
	}
}

func TestNegativeTrailerSize(t *testing.T) {
	data := xrefTableFile("<< /Size -1 /Root 1 0 R >>")
	if _, err := NewReader(bytes.NewReader(data), int64(len(data))); err == nil || !strings.Contains(err.Error(), "negative") {
		t.Errorf("NewReader: got %v, want an error about the negative /Size", err)
	}
}

func TestDataAfterEOF(t *testing.T) {
	doc := xrefTableFile("<< /Size 2 /Root 1 0 R >>")
	// 65532 bytes after the end of the document put %%EOF across two of the
	// chunks that findEOF reads.
	for _, n := range []int{65532, 4 << 20} {
		data := append(slices.Clone(doc), bytes.Repeat([]byte("x"), n)...)
		var err error
		if !runWithin(t, func() { _, err = NewReader(bytes.NewReader(data), int64(len(data))) }) {
			t.Fatalf("NewReader for %d bytes after %%%%EOF did not return", n)
		}
		if err != nil {
			t.Errorf("NewReader for %d bytes after %%%%EOF: %v", n, err)
		}
	}

	data := bytes.Repeat([]byte("x"), 4<<20)
	copy(data, doc[:len(doc)-7])
	var err error
	if !runWithin(t, func() { _, err = NewReader(bytes.NewReader(data), int64(len(data))) }) {
		t.Fatal("NewReader for a document without the EOF marker did not return")
	}
	if err == nil {
		t.Error("NewReader for a document without the EOF marker: got no error")
	}
}

func TestInvalidXrefStreamFields(t *testing.T) {
	pairs := strings.Repeat(" 0 8388606", 20)
	tests := []struct{ name, w, index string }{
		{"huge field", "/W [1 2 250000000000000]", ""},
		{"huge fourth field", "/W [1 2 1 250000000000000]", ""},
		{"negative field", "/W [1 -2 1]", ""},
		{"empty entries", "/W [0 0 0]", "/Index [" + pairs + "]"},
		{"too many entries", "", "/Index [0 3" + pairs + "]"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := xrefStreamFile(3, 0)
			if tt.w != "" {
				data = bytes.Replace(data, []byte("/W [1 2 1]"), []byte(tt.w), 1)
			}
			if tt.index != "" {
				data = bytes.Replace(data, []byte("/Index [0 3]"), []byte(tt.index), 1)
			}
			var err error
			if !runWithin(t, func() { _, err = NewReader(bytes.NewReader(data), int64(len(data))) }) {
				t.Fatal("NewReader did not return")
			}
			if err == nil {
				t.Error("NewReader: got no error")
			}
		})
	}
}

func TestPredictorColumnsOverLimit(t *testing.T) {
	var data bytes.Buffer
	zw := zlib.NewWriter(&data)
	zw.Close()
	for _, columns := range []int64{-2, 1 << 40} {
		param := Value{obj: Object{Kind: Dict, DictVal: map[string]Object{
			"Predictor": {Kind: Integer, Int64Val: 12},
			"Columns":   {Kind: Integer, Int64Val: columns},
		}}}
		if _, err := applyFilter(bytes.NewReader(data.Bytes()), "FlateDecode", param); err == nil {
			t.Errorf("applyFilter for /Columns %d: got no error", columns)
		}
	}
}

func TestFilterParameterShapes(t *testing.T) {
	var data bytes.Buffer
	zw := zlib.NewWriter(&data)
	zw.Write([]byte{2, 1, 2, 2, 2, 2})
	zw.Close()

	flate := Object{Kind: Name, NameVal: "FlateDecode"}
	params := Object{Kind: Dict, DictVal: map[string]Object{
		"Predictor": {Kind: Integer, Int64Val: 12},
		"Columns":   {Kind: Integer, Int64Val: 2},
	}}
	array := func(x Object) Object { return Object{Kind: Array, ArrayVal: []Object{x}} }
	tests := []struct {
		name           string
		filter, params Object
	}{
		{"name and dictionary", flate, params},
		{"arrays", array(flate), array(params)},
		{"array and dictionary", array(flate), params},
		{"name and array", flate, array(params)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := readStreamData(&Reader{}, map[string]Object{"Filter": tt.filter, "DecodeParms": tt.params}, data.Bytes())
			if got != "\x01\x02\x03\x04" || err != nil {
				t.Errorf("read %q, %v; want %q, nil", got, err, "\x01\x02\x03\x04")
			}
		})
	}
}

// A chain shorter than maxObjStmDepth fails at its end, and a longer one at
// that depth.
func TestObjectStreamChain(t *testing.T) {
	for _, k := range []int{20, 100} {
		t.Run(fmt.Sprint(k), func(t *testing.T) { testObjectStreamChain(t, k) })
	}
}

func testObjectStreamChain(t *testing.T, k int) {
	const first = 1000
	var streams []string
	for i := 1; i <= k; i++ {
		n := first + 4*(i+1)
		streams = append(streams, fmt.Sprintf(
			"<< /Type /ObjStm /N %d 0 R /First 4 /Length %d 0 R /Filter %d 0 R /Extends %d 0 R >>\nstream\n0 0 null\nendstream",
			n, n+1, n+2, n+3))
	}
	r := &Reader{}
	setObjects(r, streams...)
	r.xref = append(r.xref, make([]xref, first+4*(k+2)-len(r.xref))...)
	for i := 1; i <= k+1; i++ {
		for id := uint32(first + 4*i); id < uint32(first+4*i+4); id++ {
			r.xref[id] = xref{ptr: objptr{id: id}, inStream: true, stream: objptr{id: uint32(i)}}
		}
	}

	var v Value
	if !runWithin(t, func() { v, _ = r.GetObject(first + 4) }) {
		t.Fatal("GetObject did not return")
	}
	if v.Err() == nil {
		t.Fatal("GetObject: got no error")
	}
	if want := fmt.Sprintf("%d 0 R", first+4); !strings.Contains(v.Err().Error(), want) {
		t.Errorf("GetObject: error %q does not name %s", v.Err(), want)
	}
}
