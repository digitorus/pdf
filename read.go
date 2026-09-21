// Copyright 2014 The Go Authors.  All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package pdf

import (
	"bytes"
	"compress/zlib"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"crypto/rc4"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/ascii85"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"slices"
	"sort"
	"strconv"
)

// A Reader is a single PDF file open for reading.
type Reader struct {
	f               io.ReaderAt
	end             int64
	xref            []xref
	trailer         Object // was dict
	trailerptr      objptr
	key             []byte
	useAES          bool
	encVersion      int               // encryption version (V), 0 if not encrypted
	encKey          []byte            // File Encryption Key (FEK) - for V=5 calls this is the final key
	plainMetadata   bool              // the document metadata stream is not encrypted (/EncryptMetadata false)
	cryptFilters    map[string]string // the method of each crypt filter of /CF, by name
	XrefInformation ReaderXrefInformation
	PDFVersion      string
	closer          io.Closer

	// objCache caches resolved objects to prevent repetitive disk I/O.
	// Map key is the object ID.
	objCache map[uint32]Value

	// objStms holds the object streams being searched, to detect cycles.
	objStms []objptr
	// Failures that depend on the object streams being searched must not be
	// cached.
	objStmLoops  int
	objStmFailed bool
}

// maxObjStmDepth bounds the object streams searched at once, since a key of one,
// such as /Length, may be in another. A long chain would overflow the stack.
const maxObjStmDepth = 32

type ReaderXrefInformation struct {
	StartPos               int64
	EndPos                 int64
	Length                 int64
	PositionLength         int64
	PositionStartPos       int64
	PositionEndPos         int64
	ItemCount              int64
	Type                   string
	IncludingTrailerEndPos int64
	IncludingTrailerLength int64
}

func (info *ReaderXrefInformation) PrintDebug() {
	log.Printf("Start of xref position bytes: %d", info.PositionStartPos)
	log.Printf("Length of xref position bytes: %d", info.PositionLength)
	log.Printf("End of xref position bytes: %d", info.PositionEndPos)
	log.Printf("xref start position byte: %d", info.StartPos)
	log.Printf("xref end position byte: %d", info.EndPos)
	log.Printf("xref length in bytes: %d", info.Length)
	log.Printf("xref type: %s", info.Type)
	log.Printf("Amount of items in xref: %d", info.ItemCount)
	log.Printf("xref end (including trailer) position byte: %d", info.IncludingTrailerEndPos)
	log.Printf("xref length (including trailer) in bytes: %d", info.IncludingTrailerLength)
}

type xref struct {
	ptr      objptr
	inStream bool
	stream   objptr
	offset   int64
}

func (x *xref) Ptr() Ptr {
	return Ptr{id: x.ptr.id, gen: x.ptr.gen}
}

func (x *xref) Stream() objptr {
	return x.stream
}

func GetDict() Object {
	return Object{Kind: Dict, DictVal: make(map[string]Object)}
}

func (r *Reader) errorf(format string, args ...interface{}) {
	panic(fmt.Errorf(format, args...))
}

func (r *Reader) Xref() []xref {
	return r.xref
}

// GetObject reads and returns the object with the given ID.
// It resolves the object from the XRef table, using the cache if available.
func (r *Reader) GetObject(id uint32) (Value, error) {
	if int(id) >= len(r.xref) {
		return Value{}, fmt.Errorf("object ID %d out of range", id)
	}

	x := r.xref[id]
	if x.offset == 0 && !x.inStream {
		// Possibly free or invalid
		return Value{}, fmt.Errorf("object ID %d is not in use", id)
	}

	ptr := x.ptr
	if ptr.id != id {
		ptr.id = id
	}

	return r.resolve(objptr{}, Object{Kind: Indirect, PtrVal: ptr}), nil
}

// Open opens a file for reading.
func Open(file string) (*Reader, error) {
	// TODO: Deal with closing file.
	f, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	fi, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	return NewReader(f, fi.Size())
}

// NewReader opens a file for reading, using the data in f with the given total size.
func NewReader(f io.ReaderAt, size int64) (*Reader, error) {
	return NewReaderEncrypted(f, size, nil)
}

// NewReaderEncrypted opens a file for reading, using the data in f with the given total size.
// If the PDF is encrypted, NewReaderEncrypted calls pw repeatedly to obtain passwords
// to try. If pw returns the empty string, NewReaderEncrypted stops trying to decrypt
// the file and returns an error.
func NewReaderEncrypted(f io.ReaderAt, size int64, pw func() string) (r *Reader, err error) {
	defer func() {
		if e := recover(); e != nil {
			r = nil
			if err, _ = e.(error); err == nil {
				err = fmt.Errorf("malformed PDF: %v", e)
			}
		}
	}()
	return newReaderEncrypted(f, size, pw)
}

func newReaderEncrypted(f io.ReaderAt, size int64, pw func() string) (*Reader, error) {
	buf := make([]byte, 10)
	f.ReadAt(buf, 0)
	if (!bytes.HasPrefix(buf, []byte("%PDF-1.")) || buf[7] < '0' || buf[7] > '7') && (!bytes.HasPrefix(buf, []byte("%PDF-2.")) || buf[7] < '0' || buf[7] > '0') {
		return nil, fmt.Errorf("not a PDF file: invalid header")
	}

	version := buf[5:8]

	end := size

	// Some PDF's are quite broken and have a lot of stuff after %%EOF.
	eof := findEOF(f, end)
	if eof < 0 {
		return nil, fmt.Errorf("not a PDF file: missing %%%%EOF")
	}

	start := max(eof-200, 0)
	buf = make([]byte, eof-start)
	f.ReadAt(buf, start)

	i := findLastLine(buf, "startxref")
	if i < 0 {
		return nil, fmt.Errorf("malformed PDF file: missing final startxref")
	}

	r := &Reader{
		f:               f,
		end:             end,
		XrefInformation: ReaderXrefInformation{},
		PDFVersion:      string(version),
		objCache:        make(map[uint32]Value),
	}
	if c, ok := f.(io.Closer); ok {
		r.closer = c
	}
	pos := start + int64(i)

	// Save the position of the startxref element.
	r.XrefInformation.PositionStartPos = pos

	b := newBuffer(io.NewSectionReader(f, pos, end-pos), pos, r.encVersion)

	tok := b.readToken()
	if tok.Kind != Keyword || tok.KeywordVal != "startxref" {
		return nil, fmt.Errorf("malformed PDF file: missing startxref")
	}

	startXRefObj := b.readToken()
	if startXRefObj.Kind != Integer {
		return nil, fmt.Errorf("malformed PDF file: startxref not followed by integer")
	}
	startxref := startXRefObj.Int64Val

	// Save length. Useful for calculations later on.
	r.XrefInformation.PositionLength = b.realPos + 1

	// Save end position. Add 1 for the newline character.
	r.XrefInformation.PositionEndPos = r.XrefInformation.PositionStartPos + r.XrefInformation.PositionLength

	// Save start position of xref.
	r.XrefInformation.StartPos = startxref

	b = newBuffer(io.NewSectionReader(r.f, startxref, r.end-startxref), startxref, r.encVersion)
	xref, trailerptr, trailer, err := readXref(r, b)
	if err != nil {
		return nil, err
	}
	r.xref = xref
	r.trailer = trailer
	r.trailerptr = trailerptr
	if trailer.Kind == Dict && trailer.DictVal["Encrypt"].Kind == Null {
		return r, nil
	}
	// Check if Encrypt is present properly
	enc := trailer.DictVal["Encrypt"]
	if enc.Kind == Null {
		return r, nil
	}

	err = r.initEncrypt("")
	if err == nil {
		return r, nil
	}
	if pw == nil || err != ErrInvalidPassword {
		return nil, err
	}
	for {
		next := pw()
		if next == "" {
			break
		}
		if r.initEncrypt(next) == nil {
			return r, nil
		}
	}
	return nil, err
}

// Trailer returns the file's Trailer value.
func (r *Reader) Trailer() Value {
	return Value{r: r, ptr: r.trailerptr, obj: r.trailer}
}

func readXref(r *Reader, b *buffer) ([]xref, objptr, Object, error) {
	tok := b.readToken()
	if tok.Kind == Keyword && tok.KeywordVal == "xref" {
		return readXrefTable(r, b)
	}
	if tok.Kind == Integer {
		b.unreadToken(tok)
		return readXrefStream(r, b)
	}
	return nil, objptr{}, Object{Kind: Null}, fmt.Errorf("malformed PDF: cross-reference table not found: %v", tok)
}

func readXrefStream(r *Reader, b *buffer) ([]xref, objptr, Object, error) {
	obj1 := b.readObject()
	// readObject returns the object. If it was an indirect definition, it has PtrVal set.
	strmptr := obj1.PtrVal
	if obj1.Kind != Stream {
		return nil, objptr{}, Object{Kind: Null}, fmt.Errorf("malformed PDF: cross-reference table not found: %v", objfmt(obj1))
	}
	strm := obj1
	if strm.DictVal["Type"].NameVal != "XRef" {
		return nil, objptr{}, Object{Kind: Null}, fmt.Errorf("malformed PDF: xref stream does not have type XRef")
	}
	sizeObj := strm.DictVal["Size"]
	if sizeObj.Kind != Integer {
		return nil, objptr{}, Object{Kind: Null}, fmt.Errorf("malformed PDF: xref stream missing Size")
	}
	size := sizeObj.Int64Val
	if size < 0 {
		return nil, objptr{}, Object{Kind: Null}, fmt.Errorf("malformed PDF: negative xref stream Size")
	}

	// The table grows as the entries are read, so /Size only gives the initial
	// capacity: a file that declares a huge one must not make the table that
	// large before a single entry is read.
	table := make([]xref, 0, min(size, 4096))

	table, err := readXrefStreamData(r, strm, table, size)
	if err != nil {
		return nil, objptr{}, Object{Kind: Null}, fmt.Errorf("malformed PDF: %v", err)
	}

	seenPrev := map[int64]bool{}

	prevoff := strm.DictVal["Prev"]
	for prevoff.Kind != Null {
		off := prevoff.Int64Val
		if prevoff.Kind != Integer {
			return nil, objptr{}, Object{Kind: Null}, fmt.Errorf("malformed PDF: xref Prev is not integer: %v", prevoff)
		}

		if _, ok := seenPrev[off]; ok {
			return nil, objptr{}, Object{Kind: Null}, fmt.Errorf("malformed PDF: xref Prev loop detected: %v", off)
		}

		seenPrev[off] = true

		b := newBuffer(io.NewSectionReader(r.f, off, r.end-off), off, r.encVersion)
		obj1 := b.readObject()
		if obj1.Kind != Stream {
			return nil, objptr{}, Object{Kind: Null}, fmt.Errorf("malformed PDF: xref prev stream not found: %v", objfmt(obj1))
		}
		prevstrm := obj1
		prevoff = prevstrm.DictVal["Prev"]

		prev := Value{r: r, obj: prevstrm}
		if prev.Kind() != Stream {
			return nil, objptr{}, Object{Kind: Null}, fmt.Errorf("malformed PDF: xref prev stream is not stream: %v", prev)
		}
		if prev.Key("Type").Name() != "XRef" {
			return nil, objptr{}, Object{Kind: Null}, fmt.Errorf("malformed PDF: xref prev stream does not have type XRef")
		}
		psize := prev.Key("Size").Int64()
		if psize > size {
			return nil, objptr{}, Object{Kind: Null}, fmt.Errorf("malformed PDF: xref prev stream larger than last stream")
		}
		if table, err = readXrefStreamData(r, prev.obj, table, psize); err != nil {
			return nil, objptr{}, Object{Kind: Null}, fmt.Errorf("malformed PDF: reading xref prev stream: %v", err)
		}
	}

	// Save the xref type. Useful for adding data to it.
	r.XrefInformation.Type = "stream"
	// Writers take the /Size of the next section from ItemCount, and it must not
	// be smaller than this one, even if the table lists fewer objects.
	r.XrefInformation.ItemCount = max(size, int64(len(table)))

	return table, strmptr, strm, nil
}

func readXrefStreamData(r *Reader, strm Object, table []xref, size int64) ([]xref, error) {
	index := strm.DictVal["Index"]
	if index.Kind == Null {
		index = Object{Kind: Array, ArrayVal: []Object{{Kind: Integer, Int64Val: 0}, {Kind: Integer, Int64Val: size}}}
	}
	if len(index.ArrayVal)%2 != 0 {
		return nil, fmt.Errorf("invalid Index array %v", objfmt(index))
	}
	ww := strm.DictVal["W"]
	if ww.Kind != Array {
		return nil, fmt.Errorf("xref stream missing W array")
	}

	// A field is at most 8 bytes wide, like in qpdf, and an entry takes at least
	// one byte: an entry of no bytes would let a short /Index list any number.
	var w []int
	wtotal := 0
	for _, x := range ww.ArrayVal {
		i := x.Int64Val
		if x.Kind != Integer || i < 0 || i > 8 {
			return nil, fmt.Errorf("invalid W array %v", objfmt(ww))
		}
		w = append(w, int(i))
		wtotal += int(i)
	}
	if len(w) < 3 || wtotal == 0 {
		return nil, fmt.Errorf("invalid W array %v", objfmt(ww))
	}

	v := Value{r: r, obj: strm}
	buf := make([]byte, wtotal)
	data := v.Reader()

	entries := int64(0)
	idxArr := index.ArrayVal
	for len(idxArr) > 0 {
		start := idxArr[0].Int64Val
		n := idxArr[1].Int64Val
		if idxArr[0].Kind != Integer || idxArr[1].Kind != Integer {
			return nil, fmt.Errorf("malformed Index pair %v %v", objfmt(idxArr[0]), objfmt(idxArr[1]))
		}
		if n > maxObjects+1-entries {
			return nil, fmt.Errorf("xref stream lists more than %d objects", maxObjects+1)
		}
		entries += max(n, 0)
		idxArr = idxArr[2:]
		for i := 0; i < int(n); i++ {
			_, err := io.ReadFull(data, buf)
			if err != nil {
				return nil, fmt.Errorf("error reading xref stream: %v", err)
			}

			v1 := decodeInt(buf[0:w[0]])
			if w[0] == 0 {
				v1 = 1
			}

			v2 := decodeInt(buf[w[0] : w[0]+w[1]])
			v3 := decodeInt(buf[w[0]+w[1] : w[0]+w[1]+w[2]])
			x, err := xrefIndex(start + int64(i))
			if err != nil {
				return nil, err
			}
			if x >= len(table) {
				table = append(table, make([]xref, x+1-len(table))...)
			}
			if table[x].ptr != (objptr{}) {
				continue
			}
			switch v1 {
			case 0:
				table[x] = xref{ptr: objptr{0, 65535}}
			case 1:
				table[x] = xref{ptr: objptr{uint32(x), uint16(v3)}, offset: int64(v2)}
			case 2:
				table[x] = xref{ptr: objptr{uint32(x), 0}, inStream: true, stream: objptr{uint32(v2), 0}, offset: int64(v3)}
			default:
				fmt.Printf("invalid xref stream type %d: %x\n", v1, buf)
			}
		}
	}
	return table, nil
}

func decodeInt(b []byte) int {
	x := 0
	for _, c := range b {
		x = x<<8 | int(c)
	}
	return x
}

func readXrefTable(r *Reader, b *buffer) ([]xref, objptr, Object, error) {
	var table []xref

	table, err := readXrefTableData(b, table)
	if err != nil {
		return nil, objptr{}, Object{Kind: Null}, fmt.Errorf("malformed PDF: %v", err)
	}

	// Get length of trailer keyword and newline.
	trailer_length := int64(len("trailer")) + 1

	// Save end position.
	r.XrefInformation.EndPos = (r.XrefInformation.StartPos - trailer_length) + b.realPos

	// Save length position. Useful for calculations. Remove trailer keyword length, add 1 for newline.
	r.XrefInformation.Length = (b.realPos - trailer_length) + 1

	trailer := b.readObject()
	if trailer.Kind != Dict {
		return nil, objptr{}, Object{Kind: Null}, fmt.Errorf("malformed PDF: xref table not followed by trailer dictionary")
	}

	seenPrev := map[int64]bool{}

	prevoff := trailer.DictVal["Prev"]
	for prevoff.Kind != Null {
		off := prevoff.Int64Val
		if prevoff.Kind != Integer {
			return nil, objptr{}, Object{Kind: Null}, fmt.Errorf("malformed PDF: xref Prev is not integer: %v", prevoff)
		}

		if _, ok := seenPrev[off]; ok {
			return nil, objptr{}, Object{Kind: Null}, fmt.Errorf("malformed PDF: xref Prev loop detected: %v", off)
		}

		seenPrev[off] = true

		b := newBuffer(io.NewSectionReader(r.f, off, r.end-off), off, r.encVersion)
		tok := b.readToken()
		if tok.Kind != Keyword || tok.KeywordVal != "xref" {
			return nil, objptr{}, Object{Kind: Null}, fmt.Errorf("malformed PDF: xref Prev does not point to xref")
		}
		table, err = readXrefTableData(b, table)
		if err != nil {
			return nil, objptr{}, Object{Kind: Null}, fmt.Errorf("malformed PDF: %v", err)
		}

		t := b.readObject()
		if t.Kind != Dict {
			return nil, objptr{}, Object{Kind: Null}, fmt.Errorf("malformed PDF: xref Prev table not followed by trailer dictionary")
		}
		prevoff = t.DictVal["Prev"]
	}

	sizeObj := trailer.DictVal["Size"]
	if sizeObj.Kind != Integer {
		return nil, objptr{}, Object{Kind: Null}, fmt.Errorf("malformed PDF: trailer missing /Size entry")
	}
	size := sizeObj.Int64Val
	if size < 0 {
		return nil, objptr{}, Object{Kind: Null}, fmt.Errorf("malformed PDF: negative trailer Size")
	}

	if size < int64(len(table)) {
		table = table[:size]
	}

	// Save the xref type. Useful for adding data to it.
	r.XrefInformation.Type = "table"

	// Save the amount of items in the table. Useful for generating a new id for the signature.
	r.XrefInformation.ItemCount = int64(len(table))

	// Save end position. Note that this is including the trailer and startxref (without value).
	r.XrefInformation.IncludingTrailerEndPos = r.XrefInformation.StartPos + b.realPos

	// Save length position. Useful for calculations.
	r.XrefInformation.IncludingTrailerLength = b.realPos + 1

	return table, objptr{}, trailer, nil
}

// maxObjects is the architectural limit on the number of indirect objects in a
// document (ISO 32000-1, Annex C.2), numbered 1 to maxObjects. It bounds the
// cross-reference table, which a file would otherwise size with a single entry,
// however few objects it holds.
const maxObjects = 8388607

// xrefIndex returns the object number x as an index into the cross-reference
// table.
func xrefIndex(x int64) (int, error) {
	if x < 0 || x > maxObjects {
		return 0, fmt.Errorf("object number %d over the limit of %d", x, maxObjects)
	}
	return int(x), nil
}

func readXrefTableData(b *buffer, table []xref) ([]xref, error) {
	for {
		tok := b.readToken()
		if tok.Kind == Keyword && tok.KeywordVal == "trailer" {
			break
		}
		if tok.Kind != Integer {
			return nil, fmt.Errorf("malformed xref table: expected integer start")
		}
		start := tok.Int64Val
		nObj := b.readToken()
		if nObj.Kind != Integer {
			return nil, fmt.Errorf("malformed xref table: expected integer count")
		}
		n := nObj.Int64Val

		for i := 0; i < int(n); i++ {
			offObj := b.readToken()
			genObj := b.readToken()
			allocObj := b.readToken()
			if offObj.Kind != Integer || genObj.Kind != Integer || allocObj.Kind != Keyword {
				return nil, fmt.Errorf("malformed xref table entry")
			}
			off := offObj.Int64Val
			gen := genObj.Int64Val
			alloc := allocObj.KeywordVal

			if alloc != "f" && alloc != "n" {
				return nil, fmt.Errorf("malformed xref table entry: invalid type %q", alloc)
			}
			x, err := xrefIndex(start + int64(i))
			if err != nil {
				return nil, err
			}
			if x >= len(table) {
				table = append(table, make([]xref, x+1-len(table))...)
			}
			if alloc == "n" && table[x].offset == 0 {
				table[x] = xref{ptr: objptr{uint32(x), uint16(gen)}, offset: int64(off)}
			}
		}
	}
	return table, nil
}

// findEOF returns the offset just after the last %%EOF in f, or -1.
func findEOF(f io.ReaderAt, end int64) int64 {
	const chunk = 64 << 10
	marker := []byte("%%EOF")
	buf := make([]byte, chunk+len(marker)-1)
	for hi := end; hi > 0; {
		// The chunks overlap, for a marker across two of them.
		lo := max(hi-chunk, 0)
		n, _ := f.ReadAt(buf[:min(end, hi+int64(len(marker)-1))-lo], lo)
		if i := bytes.LastIndex(buf[:n], marker); i >= 0 {
			return lo + int64(i+len(marker))
		}
		hi = lo
	}
	return -1
}

func findLastLine(buf []byte, s string) int {
	bs := []byte(s)
	max := len(buf)
	for {
		i := bytes.LastIndex(buf[:max], bs)
		if i <= 0 || i+len(bs) >= len(buf) {
			return -1
		}
		if (buf[i-1] == '\n' || buf[i-1] == '\r') && (buf[i+len(bs)] == '\n' || buf[i+len(bs)] == '\r') {
			return i
		}
		max = i
	}
}

func objfmt(x Object) string {
	switch x.Kind {
	default:
		return fmt.Sprintf("?Kind=%v?", x.Kind)
	case Null:
		return "null"
	case Bool:
		return strconv.FormatBool(x.BoolVal)
	case Integer:
		return strconv.FormatInt(x.Int64Val, 10)
	case Real:
		return strconv.FormatFloat(x.Float64Val, 'f', -1, 64)
	case String:
		return "(" + x.StringVal + ")"
	case Name:
		return "/" + x.NameVal
	case Keyword:
		return x.KeywordVal
	case Indirect:
		return fmt.Sprintf("%d %d R", x.PtrVal.id, x.PtrVal.gen)
	case Dict:
		var keys []string
		for k := range x.DictVal {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		var buf bytes.Buffer
		buf.WriteString("<<")
		for i, k := range keys {
			elem := x.DictVal[k]
			if i > 0 {
				buf.WriteString(" ")
			}
			buf.WriteString("/")
			buf.WriteString(k)
			buf.WriteString(" ")
			buf.WriteString(objfmt(elem))
		}
		buf.WriteString(">>")
		return buf.String()

	case Array:
		var buf bytes.Buffer
		buf.WriteString("[")
		for i, elem := range x.ArrayVal {
			if i > 0 {
				buf.WriteString(" ")
			}
			buf.WriteString(objfmt(elem))
		}
		buf.WriteString("]")
		return buf.String()

	case Stream:
		hdr := Object{Kind: Dict, DictVal: x.DictVal}
		return fmt.Sprintf("%v@%d", objfmt(hdr), x.StreamOffset)
	}
}

// objectInStream returns the object ptr from the object stream strm, and
// whether the stream holds it.
func (r *Reader) objectInStream(strm Value, ptr objptr) (Object, bool) {
	if strm.Kind() != Stream {
		panic("not a stream")
	}
	if strm.Key("Type").Name() != "ObjStm" {
		panic("not an object stream")
	}
	n := int(strm.Key("N").Int64())
	first := strm.Key("First").Int64()
	if first == 0 {
		panic("missing First")
	}
	b := newBuffer(strm.Reader(), 0, r.encVersion)
	defer bufferPool.Put(b)
	b.allowEOF = true
	for i := 0; i < n && !b.eof; i++ {
		id := b.readToken().Int64Val
		off := b.readToken().Int64Val
		if uint32(id) == ptr.id {
			b.seekForward(first + off)
			return b.readObject(), true
		}
	}
	return Object{}, false
}

func (r *Reader) resolve(parent objptr, x Object) (v Value) {
	orig, loops := x, 0
	if r != nil {
		loops = r.objStmLoops
	}
	defer func() {
		if e := recover(); e != nil {
			v = Value{err: fmt.Errorf("panic resolving %v: %v", objfmt(orig), e)}
			// A chain of object streams would otherwise resolve a failing object
			// once for each key of each stream.
			if orig.Kind == Indirect && r != nil && r.objCache != nil && r.objStmLoops == loops {
				r.objCache[orig.PtrVal.id] = v
			}
		}
	}()

	if x.Kind == Indirect {
		ptr := x.PtrVal
		// Check cache first
		if v, ok := r.objCache[ptr.id]; ok {
			return v
		}

		if ptr.id >= uint32(len(r.xref)) {
			return Value{}
		}
		xref := r.xref[ptr.id]
		if xref.ptr != ptr || !xref.inStream && xref.offset == 0 {
			return Value{}
		}
		var obj Object
		if xref.inStream {
			if slices.Contains(r.objStms, xref.stream) || len(r.objStms) >= maxObjStmDepth || r.objStmFailed {
				// Otherwise each stream would search the next ones again for
				// each of its keys.
				r.objStmLoops++
				r.objStmFailed = len(r.objStms) > 0
				panic("cyclic or too deeply nested object streams")
			}
			// An object stream is a stream, and a stream is never stored in an
			// object stream (ISO 32000-1, 7.5.7).
			if s := xref.stream.id; s < uint32(len(r.xref)) && r.xref[s].inStream {
				panic("object stream in an object stream")
			}
			r.objStms = append(r.objStms, xref.stream)
			defer func() {
				r.objStms = r.objStms[:len(r.objStms)-1]
				if len(r.objStms) == 0 {
					r.objStmFailed = false
				}
			}()
			strm := r.resolve(parent, Object{Kind: Indirect, PtrVal: xref.stream})
			// The object stream is searched first, then the chain of the object
			// streams it extends, each of them only once.
			var extends []objptr
			for {
				var found bool
				if x, found = r.objectInStream(strm, ptr); found {
					break
				}
				ext := strm.Key("Extends")
				next := ext.obj.PtrVal
				if ext.Kind() != Stream || next == xref.stream || slices.Contains(extends, next) {
					panic("cannot find object in stream")
				}
				extends = append(extends, next)
				strm = ext
			}
		} else {
			b := newBuffer(io.NewSectionReader(r.f, xref.offset, r.end-xref.offset), xref.offset, r.encVersion)
			defer bufferPool.Put(b) // Return to pool
			b.key = r.key
			b.useAES = r.useAES

			obj = b.readObject()
			if b.key != nil && obj.Kind == Stream && obj.DictVal["Type"].NameVal == "XRef" {
				// The strings of a cross-reference stream are not encrypted.
				b = newBuffer(io.NewSectionReader(r.f, xref.offset, r.end-xref.offset), xref.offset, r.encVersion)
				defer bufferPool.Put(b)
				obj = b.readObject()
			}
			// readObject handles the "objdef" structure internally by returning the Object
			// but storing the definition ID in PtrVal if it was an indirect definition.
			// Let's verify it matches the pointer we expected.

			// If obj matches criteria for definition:
			// In readObject, we return the object with PtrVal set to the def ID.

			// We check if PtrVal is set and check if it matches.
			// However, if obj IS an Indirect reference, PtrVal will be the reference ID.
			// But readObject for a definition returns the defined object (not Kind=Indirect).
			if obj.Kind != Indirect && obj.PtrVal != (objptr{}) {
				if obj.PtrVal.id != ptr.id || obj.PtrVal.gen != ptr.gen {
					panic(fmt.Errorf("loading %v: found %v", ptr, obj.PtrVal))
				}
			} else if obj.Kind == Indirect && obj.PtrVal != ptr {
				// It turned out to be a reference? A definition cannot act as a reference directly unless it's a stream?
				panic(fmt.Errorf("loading %v: found reference %v", ptr, obj.PtrVal))
			}
			x = obj
		}
		parent = ptr

		// Cache the resolved value
		val := r.createValue(parent, x)
		r.objCache[ptr.id] = val
		return val
	}

	return r.createValue(parent, x)
}

// Close closes the Reader and the underlying file if it implements io.Closer.
func (r *Reader) Close() error {
	if r.closer != nil {
		return r.closer.Close()
	}
	return nil
}

func (r *Reader) createValue(ptr objptr, obj Object) Value {
	return Value{r: r, ptr: ptr, obj: obj}
}

type errorReadCloser struct {
	err error
}

func (e *errorReadCloser) Read([]byte) (int, error) {
	return 0, e.err
}

func (e *errorReadCloser) Close() error {
	return e.err
}

// newStreamReader returns a reader for the stream s.
func newStreamReader(s Object, r *Reader) io.ReadCloser {
	var rd io.Reader
	// s is Object(Stream). DictVal is header. StreamOffset is offset.

	// Need "Length" from header.
	// We can wrap s in Value to use Key method.
	val := Value{r: r, obj: s}
	length := val.Key("Length").Int64()

	rd = io.NewSectionReader(r.f, s.StreamOffset, length)

	if r.key != nil {
		// We need the stream's object ID for decryption. Use s.PtrVal, which
		// readObject sets to the definition ID.
		encrypted, useAES, err := r.streamCipher(s)
		if err != nil {
			return &errorReadCloser{err}
		}
		if encrypted {
			rd, err = decryptStream(r.key, useAES, r.encVersion, s.PtrVal, rd)
			if err != nil {
				return &errorReadCloser{err}
			}
		}
	}

	names, params := streamFilters(val)
	for i, name := range names {
		var err error
		rd, err = applyFilter(rd, name, params(i))
		if err != nil {
			return &errorReadCloser{err}
		}
	}

	return ioutil.NopCloser(rd)
}

// streamFilters returns the names of the filters of the stream s, and a function
// that returns the parameters of the i-th one. Like pdf.js, it accepts a single
// filter in an array, a single filter with its parameters in an array, and a
// single DecodeParms dictionary for all the filters.
func streamFilters(s Value) (names []string, params func(i int) Value) {
	filter, decodeParms := s.Key("Filter"), s.Key("DecodeParms")
	switch filter.Kind() {
	case Name:
		names = []string{filter.Name()}
	case Array:
		for i := 0; i < filter.Len(); i++ {
			names = append(names, filter.Index(i).Name())
		}
	}
	params = func(i int) Value {
		if decodeParms.Kind() == Array {
			return decodeParms.Index(i)
		}
		return decodeParms
	}
	return names, params
}

// streamCipher reports whether the stream s is encrypted, and whether its crypt
// filter uses AES. A cross-reference stream, the metadata stream of the catalog
// when /EncryptMetadata is false, and a stream whose Crypt filter is Identity or
// does not encrypt are not encrypted. A stream that names another crypt filter
// of the document uses the method of that filter, not the one of /StmF.
func (r *Reader) streamCipher(s Object) (encrypted, useAES bool, err error) {
	switch s.DictVal["Type"].NameVal {
	case "XRef":
		return false, false, nil
	case "Metadata":
		if r.plainMetadata && s.PtrVal == r.resolve(objptr{}, r.trailer.DictVal["Root"]).obj.DictVal["Metadata"].PtrVal {
			return false, false, nil
		}
	}
	// A Crypt filter comes first.
	names, params := streamFilters(Value{r: r, obj: s})
	if len(names) == 0 || names[0] != "Crypt" {
		return true, r.useAES, nil
	}
	name := params(0).Key("Name").Name()
	if name == "" || name == "Identity" {
		return false, false, nil
	}
	switch method := r.cryptFilters[name]; method {
	case "Identity", "None":
		return false, false, nil
	case "V2":
		return true, false, nil
	case "AESV2", "AESV3":
		return true, true, nil
	case "":
		return false, false, fmt.Errorf("undefined crypt filter %s", name)
	default:
		return false, false, fmt.Errorf("unsupported PDF: crypt filter method %s", method)
	}
}

// maxColumns bounds the /Columns of a predictor, whose rows are buffered.
const maxColumns = 1 << 24

func applyFilter(rd io.Reader, name string, param Value) (io.Reader, error) {
	switch name {
	default:
		return nil, fmt.Errorf("unknown filter %s", name)
	case "Crypt":
		// newStreamReader decrypts the stream.
		return rd, nil
	case "ASCIIHexDecode":
		return asciiHexReader{rd}, nil
	case "ASCII85Decode":
		return ascii85.NewDecoder(rd), nil
	case "FlateDecode":
		zr, err := zlib.NewReader(rd)
		if err != nil {
			return nil, err
		}
		pred := param.Key("Predictor")
		if pred.Kind() == Null {
			return zr, nil
		}
		columns := param.Key("Columns").Int64()
		if columns < 0 || columns > maxColumns {
			return nil, fmt.Errorf("invalid predictor Columns %d", columns)
		}
		switch pred.Int64() {
		default:
			return nil, fmt.Errorf("unknown predictor %v", pred)
		case 12:
			return &pngUpReader{r: zr, hist: make([]byte, 1+columns), tmp: make([]byte, 1+columns)}, nil
		}
	}
}

type asciiHexReader struct {
	r io.Reader
}

func (r asciiHexReader) Read(dst []byte) (int, error) {
	if len(dst) == 0 {
		return 0, nil
	}
	var src [2]byte
	n := 0
	for n < len(dst) {
		_, err := io.ReadFull(r.r, src[:1])
		if err != nil {
			return n, err
		}
		if src[0] == '>' {
			return n, io.EOF
		}
		if isSpace(src[0]) {
			continue
		}
		_, err = io.ReadFull(r.r, src[1:2])
		if err != nil {
			return n, err
		}
		if src[1] == '>' {
			x := unhex(src[0]) << 4
			dst[n] = byte(x)
			return n + 1, io.EOF
		}
		if isSpace(src[1]) {
			// PDF spec says ignore whitespace. If second nibble is space, keep looking for it.
			for isSpace(src[1]) {
				_, err = io.ReadFull(r.r, src[1:2])
				if err != nil {
					return n, err
				}
				if src[1] == '>' {
					x := unhex(src[0]) << 4
					dst[n] = byte(x)
					return n + 1, io.EOF
				}
			}
		}
		x := unhex(src[0])<<4 | unhex(src[1])
		dst[n] = byte(x)
		n++
	}
	return n, nil
}

type pngUpReader struct {
	r    io.Reader
	hist []byte
	tmp  []byte
	pend []byte
}

func (r *pngUpReader) Read(b []byte) (int, error) {
	n := 0
	for len(b) > 0 {
		if len(r.pend) > 0 {
			m := copy(b, r.pend)
			n += m
			b = b[m:]
			r.pend = r.pend[m:]
			continue
		}
		_, err := io.ReadFull(r.r, r.tmp)
		if err != nil {
			return n, err
		}
		if r.tmp[0] != 2 {
			return n, fmt.Errorf("malformed PNG-Up encoding")
		}
		for i, b := range r.tmp {
			r.hist[i] += b
		}
		r.pend = r.hist[1:]
	}
	return n, nil
}

var passwordPad = []byte{
	0x28, 0xBF, 0x4E, 0x5E, 0x4E, 0x75, 0x8A, 0x41, 0x64, 0x00, 0x4E, 0x56, 0xFF, 0xFA, 0x01, 0x08,
	0x2E, 0x2E, 0x00, 0xB6, 0xD0, 0x68, 0x3E, 0x80, 0x2F, 0x0C, 0xA9, 0xFE, 0x64, 0x53, 0x69, 0x7A,
}

func (r *Reader) initEncrypt(password string) error {
	// See PDF 32000-1:2008, §7.6.
	// r.trailer is Object.
	encrypt := r.resolve(objptr{}, r.trailer.DictVal["Encrypt"]).obj.DictVal
	// Encrypt is a dict Object, so DictVal

	if encrypt["Filter"].NameVal != "Standard" {
		return fmt.Errorf("unsupported PDF: encryption filter %v", objfmt(Object{Kind: Name, NameVal: encrypt["Filter"].NameVal}))
	}
	V := encrypt["V"].Int64Val

	// Support V=5
	if V != 1 && V != 2 && V != 4 && V != 5 {
		return fmt.Errorf("unsupported PDF: encryption version V=%d", V)
	}
	useAES := false
	if V >= 4 {
		stmf := r.cryptFilterMethod(encrypt, encrypt["StmF"].NameVal)
		strf := r.cryptFilterMethod(encrypt, encrypt["StrF"].NameVal)
		switch {
		case stmf != strf:
			return fmt.Errorf("unsupported PDF: crypt filter methods %s for streams and %s for strings", stmf, strf)
		case V == 4 && stmf == "V2":
		case stmf == "AESV2", V == 5 && stmf == "AESV3":
			useAES = true
		default:
			return fmt.Errorf("unsupported PDF: crypt filter method %s for V=%d", stmf, V)
		}
		// A stream may name any of the crypt filters, not only the one of /StmF.
		cf := r.resolve(objptr{}, encrypt["CF"])
		r.cryptFilters = make(map[string]string)
		for _, name := range cf.Keys() {
			r.cryptFilters[name] = r.cryptFilterMethod(encrypt, name)
		}
	}

	r.plainMetadata = V >= 4 && encrypt["EncryptMetadata"].Kind == Bool && !encrypt["EncryptMetadata"].BoolVal

	// If V=5, delegate to V5 authentication
	if V == 5 {
		return r.initEncryptV5(password, encrypt)
	}

	ids := r.trailer.DictVal["ID"].ArrayVal
	if len(ids) < 1 {
		return fmt.Errorf("malformed PDF: missing ID in trailer")
	}
	idstr := ids[0].StringVal
	ID := []byte(idstr)
	R := encrypt["R"].Int64Val

	// Legacy path (V < 5)
	if R < 2 {
		return fmt.Errorf("malformed PDF: encryption revision R=%d", R)
	}
	if R > 4 {
		return fmt.Errorf("unsupported PDF: encryption revision R=%d", R)
	}
	O := encrypt["O"].StringVal
	U := encrypt["U"].StringVal
	if len(O) != 32 || len(U) != 32 {
		return fmt.Errorf("malformed PDF: missing O= or U= encryption parameters")
	}
	P := uint32(encrypt["P"].Int64Val)

	// Only V=2 and V=3 use /Length. Revision 2 always has a 40-bit key, unlike
	// in qpdf, which takes /Length for it too.
	var keyLen int
	switch {
	case V == 4:
		keyLen = 16
	case V == 1 || R == 2:
		keyLen = 5
	default:
		n := encrypt["Length"].Int64Val
		if n == 0 {
			n = 40
		}
		if n%8 != 0 || n < 40 || n > 128 {
			return fmt.Errorf("malformed PDF: %d-bit encryption key", n)
		}
		keyLen = int(n / 8)
	}
	authenticate := func(pw []byte) ([]byte, bool) {
		key, ok := authenticateUserPassword(R, keyLen, pw, []byte(O), []byte(U), P, ID, !r.plainMetadata)
		// Like Acrobat, do not accept an empty owner password for a document
		// that has a user password.
		if !ok && len(pw) > 0 {
			userPassword := ownerToUserPassword(R, keyLen, pw, []byte(O))
			key, ok = authenticateUserPassword(R, keyLen, userPassword, []byte(O), []byte(U), P, ID, !r.plainMetadata)
		}
		return key, ok
	}
	pw := []byte(password)
	if encoded, ok := pdfDocEncode(password); ok {
		pw = encoded
	}
	key, ok := authenticate(pw)
	if !ok && string(pw) != password {
		// Some writers use UTF-8 instead of PDFDocEncoding.
		key, ok = authenticate([]byte(password))
	}
	if !ok {
		return ErrInvalidPassword
	}

	r.key = key
	r.useAES = useAES
	r.encVersion = int(V)

	return nil
}

// padPassword pads or truncates a password to 32 bytes (Algorithm 2, step a).
func padPassword(pw []byte) []byte {
	padded := make([]byte, 32)
	n := copy(padded, pw)
	copy(padded[n:], passwordPad)
	return padded
}

// rc4Rounds applies RC4 with key XORed with each of the given counters in turn.
func rc4Rounds(key, data []byte, counters []byte) {
	key1 := make([]byte, len(key))
	for _, i := range counters {
		for j := range key {
			key1[j] = key[j] ^ i
		}
		c, _ := rc4.NewCipher(key1)
		c.XORKeyStream(data, data)
	}
}

// authenticateUserPassword computes the file key for a user password
// (Algorithm 2) and checks it against U (Algorithms 4 and 5).
func authenticateUserPassword(R int64, keyLen int, pw, O, U []byte, P uint32, ID []byte, encryptMetadata bool) (key []byte, ok bool) {
	h := md5.New()
	h.Write(padPassword(pw))
	h.Write(O)
	h.Write([]byte{byte(P), byte(P >> 8), byte(P >> 16), byte(P >> 24)})
	h.Write(ID)
	if R >= 4 && !encryptMetadata {
		h.Write([]byte{0xff, 0xff, 0xff, 0xff})
	}
	key = h.Sum(nil)
	if R >= 3 {
		for i := 0; i < 50; i++ {
			h.Reset()
			h.Write(key[:keyLen])
			key = h.Sum(key[:0])
		}
	}
	key = key[:keyLen]

	var u []byte
	if R == 2 {
		u = make([]byte, 32)
		copy(u, passwordPad)
		rc4Rounds(key, u, []byte{0})
	} else {
		h.Reset()
		h.Write(passwordPad)
		h.Write(ID)
		u = h.Sum(nil)
		rc4Rounds(key, u, []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19})
	}
	return key, bytes.HasPrefix(U, u)
}

// ownerToUserPassword decrypts O with the key derived from an owner password,
// giving the padded user password if the owner password is correct (Algorithm 7).
func ownerToUserPassword(R int64, keyLen int, pw, O []byte) []byte {
	sum := md5.Sum(padPassword(pw))
	if R >= 3 {
		// Hash only the first keyLen bytes, as Acrobat does.
		for i := 0; i < 50; i++ {
			sum = md5.Sum(sum[:keyLen])
		}
	}
	key := sum[:keyLen]

	userPassword := bytes.Clone(O)
	if R == 2 {
		rc4Rounds(key, userPassword, []byte{0})
	} else {
		rc4Rounds(key, userPassword, []byte{19, 18, 17, 16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0})
	}
	return userPassword
}

func (r *Reader) initEncryptV5(password string, encrypt map[string]Object) error {
	// AES-256 (V=5, R=5/6)
	// See ISO 32000-2 7.6.3.3 and Extension Level 3 logic

	O := encrypt["O"].StringVal
	U := encrypt["U"].StringVal
	OE := encrypt["OE"].StringVal
	UE := encrypt["UE"].StringVal
	// Perms := encrypt["Perms"].StringVal

	// Like Acrobat, use the prefix of longer values.
	if len(O) < 48 || len(U) < 48 || len(OE) < 32 || len(UE) < 32 {
		return fmt.Errorf("malformed PDF V=5: invalid O/U/OE/UE length")
	}
	O, U, OE, UE = O[:48], U[:48], OE[:32], UE[:32]

	R := encrypt["R"].Int64Val
	if R != 5 && R != 6 {
		return fmt.Errorf("unsupported PDF: encryption revision R=%d for V=5", R)
	}

	// Authenticate
	// Try User Password (U)
	key, ok := authenticateV5Password(R, password, []byte(U), []byte(UE), nil)
	if !ok && password != "" {
		// Try Owner Password (O)
		key, ok = authenticateV5Password(R, password, []byte(O), []byte(OE), []byte(U))
	}

	if !ok {
		return ErrInvalidPassword
	}

	r.key = key // The FEK
	r.encKey = key
	r.useAES = true
	r.encVersion = 5
	return nil
}

func authenticateV5Password(revision int64, password string, entry, payload, udata []byte) (fek []byte, ok bool) {
	// entry is 48 bytes: 32 hash + 8 val salt + 8 key salt
	if len(entry) != 48 {
		return nil, false
	}
	hashStored := entry[:32]
	valSalt := entry[32:40]
	keySalt := entry[40:48]

	// Truncate password to 127 bytes UTF-8
	pwdBytes := []byte(password)
	if len(pwdBytes) > 127 {
		pwdBytes = pwdBytes[:127]
	}

	// 1. Validate Password
	if !bytes.Equal(hashV5(revision, pwdBytes, valSalt, udata), hashStored) {
		return nil, false
	}

	// 2. Decrypt FEK (payload) using derived key
	block, err := aes.NewCipher(hashV5(revision, pwdBytes, keySalt, udata))
	if err != nil {
		return nil, false
	}

	iv := make([]byte, aes.BlockSize) // Zero IV
	plaintext := make([]byte, len(payload))
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(plaintext, payload)

	// FEK is the payload (32 bytes)
	return plaintext, true
}

func hashV5(revision int64, password, salt, udata []byte) []byte {
	h := sha256.New()
	h.Write(password)
	h.Write(salt)
	h.Write(udata)
	k := h.Sum(nil)
	if revision < 6 {
		return k
	}

	for round := 0; ; round++ {
		seq := make([]byte, 0, len(password)+len(k)+len(udata))
		seq = append(seq, password...)
		seq = append(seq, k...)
		seq = append(seq, udata...)
		k1 := bytes.Repeat(seq, 64)

		block, _ := aes.NewCipher(k[:16])
		e := make([]byte, len(k1))
		cipher.NewCBCEncrypter(block, k[16:32]).CryptBlocks(e, k1)

		sum := 0
		for _, b := range e[:16] {
			sum += int(b)
		}
		switch sum % 3 {
		case 0:
			s := sha256.Sum256(e)
			k = s[:]
		case 1:
			s := sha512.Sum384(e)
			k = s[:]
		case 2:
			s := sha512.Sum512(e)
			k = s[:]
		}

		if round >= 63 && int(e[len(e)-1]) <= round-31 {
			break
		}
	}
	return k[:32]
}

var ErrInvalidPassword = fmt.Errorf("encrypted PDF: invalid password")

// cryptFilterMethod returns the method of the named crypt filter, such as AESV2,
// None if it has no method, or Identity if it does not encrypt.
func (r *Reader) cryptFilterMethod(encrypt map[string]Object, name string) string {
	if name == "" || name == "Identity" {
		return "Identity"
	}
	method := r.resolve(objptr{}, encrypt["CF"]).Key(name).Key("CFM")
	if method.Kind() != Name {
		return "None"
	}
	return method.Name()
}

// objectKey returns the key for the strings and streams of object ptr (Algorithm 1).
func objectKey(key []byte, useAES bool, encVersion int, ptr objptr) []byte {
	if encVersion < 5 {
		return cryptKey(key, useAES, ptr)
	}
	return key
}

func cryptKey(key []byte, useAES bool, ptr objptr) []byte {
	h := md5.New()
	h.Write(key)
	h.Write([]byte{byte(ptr.id), byte(ptr.id >> 8), byte(ptr.id >> 16), byte(ptr.gen), byte(ptr.gen >> 8)})
	if useAES {
		h.Write([]byte("sAlT"))
	}
	return h.Sum(nil)[:min(len(key)+5, md5.Size)]
}

// IsEncrypted reports whether the document is encrypted.
func (r *Reader) IsEncrypted() bool {
	return r.key != nil
}

// EncryptsMetadata reports whether the metadata stream of the document catalog
// is encrypted, which /EncryptMetadata false turns off.
func (r *Reader) EncryptsMetadata() bool {
	return r.key != nil && !r.plainMetadata
}

// Encrypt encrypts a string or stream of the object ptr with the document's key,
// using the method of the document's default crypt filters (/StmF and /StrF).
// Some data of an encrypted document stays unencrypted and must not be passed to
// Encrypt: cross-reference streams and their strings, the Contents of signature
// dictionaries, the strings of objects in object streams, streams whose first
// filter is /Crypt with the /Identity crypt filter, no /Name or a crypt filter
// whose method is /None, and the metadata stream of the catalog if
// EncryptsMetadata reports false. A stream whose first filter is /Crypt with
// another crypt filter is decrypted with the method of that filter, so Encrypt
// suits it only if that method is the default one.
func (r *Reader) Encrypt(ptr Ptr, data []byte) ([]byte, error) {
	if r.key == nil {
		return nil, fmt.Errorf("encrypt: document is not encrypted")
	}
	key := objectKey(r.key, r.useAES, r.encVersion, objptr(ptr))

	if !r.useAES {
		c, _ := rc4.NewCipher(key)
		out := make([]byte, len(data))
		c.XORKeyStream(out, data)
		return out, nil
	}

	block, _ := aes.NewCipher(key)
	padLen := aes.BlockSize - len(data)%aes.BlockSize
	out := make([]byte, aes.BlockSize+len(data)+padLen)
	iv := out[:aes.BlockSize]
	if _, err := rand.Read(iv); err != nil {
		return nil, fmt.Errorf("encrypt: generating IV: %v", err)
	}
	body := out[aes.BlockSize:]
	copy(body, data)
	for i := len(data); i < len(body); i++ {
		body[i] = byte(padLen)
	}
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(body, body)
	return out, nil
}

// decryptString decrypts a string of the object ptr. A string that is too short
// to hold a complete ciphertext decrypts to the empty string.
func decryptString(key []byte, useAES bool, encVersion int, ptr objptr, x string) string {
	key = objectKey(key, useAES, encVersion, ptr)

	if useAES {
		data := []byte(x)
		if len(data) <= aes.BlockSize {
			return ""
		}
		iv := data[:aes.BlockSize]
		ciphertext := data[aes.BlockSize:]
		if len(ciphertext)%aes.BlockSize != 0 {
			return ""
		}

		block, _ := aes.NewCipher(key)
		mode := cipher.NewCBCDecrypter(block, iv)
		mode.CryptBlocks(ciphertext, ciphertext)

		return string(unpad(ciphertext))
	}
	c, _ := rc4.NewCipher(key)
	data := []byte(x)
	c.XORKeyStream(data, data)
	return string(data)
}

func decryptStream(key []byte, useAES bool, encVersion int, ptr objptr, rd io.Reader) (io.Reader, error) {
	key = objectKey(key, useAES, encVersion, ptr)

	if useAES {
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, fmt.Errorf("AES: %v", err)
		}

		iv := make([]byte, aes.BlockSize)
		if n, err := io.ReadFull(rd, iv); err != nil {
			// An empty stream may have no IV, and /Length may count the
			// end-of-line marker before endstream, as cbcReader allows.
			if err == io.ErrUnexpectedEOF && !slices.ContainsFunc(iv[:n], func(c byte) bool { return !isSpace(c) }) {
				return bytes.NewReader(nil), nil
			}
			return nil, err
		}

		cbc := cipher.NewCBCDecrypter(block, iv)
		return &cbcReader{cbc: cbc, rd: rd}, nil
	}
	c, _ := rc4.NewCipher(key)
	return &rc4Reader{cipher: c, rd: rd}, nil
}

// cbcReader decrypts an AES-CBC stream. It holds back each decrypted block
// until the next one is read, to remove the padding from the last block.
type cbcReader struct {
	cbc   cipher.BlockMode
	rd    io.Reader
	block [aes.BlockSize]byte
	held  bool
	next  [aes.BlockSize]byte
	out   [aes.BlockSize]byte
	pend  []byte
	err   error
}

func (r *cbcReader) Read(b []byte) (n int, err error) {
	for len(r.pend) == 0 {
		if r.err != nil {
			return 0, r.err
		}
		var tail int
		tail, err = io.ReadFull(r.rd, r.next[:])
		switch err {
		case nil:
			r.cbc.CryptBlocks(r.next[:], r.next[:])
			if r.held {
				r.out = r.block
				r.pend = r.out[:]
			}
			r.block, r.held = r.next, true
			continue
		case io.EOF, io.ErrUnexpectedEOF:
			// Like pdf.js, ignore bytes after the last complete block, such as
			// an end-of-line marker that /Length counts. Anything else means
			// that /Length cut the stream short.
			r.err = io.EOF
			for _, c := range r.next[:tail] {
				if !isSpace(c) {
					r.err = fmt.Errorf("encrypted stream not a multiple of block size")
					break
				}
			}
		default:
			r.err = err
			return 0, err
		}
		if r.held {
			r.out = r.block
			r.pend = unpad(r.out[:])
		}
	}

	n = copy(b, r.pend)
	r.pend = r.pend[n:]
	return n, nil
}

// unpad removes PKCS#7 padding from decrypted data. Like qpdf and pdf.js, it
// keeps data that does not end with valid padding.
func unpad(data []byte) []byte {
	n := int(data[len(data)-1])
	if n == 0 || n > aes.BlockSize || n > len(data) {
		return data
	}
	for _, c := range data[len(data)-n:] {
		if int(c) != n {
			return data
		}
	}
	return data[:len(data)-n]
}

type rc4Reader struct {
	cipher *rc4.Cipher
	rd     io.Reader
	buf    []byte
}

func (r *rc4Reader) Read(b []byte) (n int, err error) {
	n, err = r.rd.Read(b)
	if n > 0 {
		r.cipher.XORKeyStream(b[:n], b[:n])
	}
	return n, err
}
