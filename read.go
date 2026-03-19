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
	"crypto/rc4"
	"crypto/sha256"
	"encoding/ascii85"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
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
	encVersion      int    // encryption version (V), 0 if not encrypted
	encKey          []byte // File Encryption Key (FEK) - for V=5 calls this is the final key
	XrefInformation ReaderXrefInformation
	PDFVersion      string
	closer          io.Closer

	// objCache caches resolved objects to prevent repetitive disk I/O.
	// Map key is the object ID.
	objCache map[uint32]Value
}

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
func NewReaderEncrypted(f io.ReaderAt, size int64, pw func() string) (*Reader, error) {
	buf := make([]byte, 10)
	f.ReadAt(buf, 0)
	if (!bytes.HasPrefix(buf, []byte("%PDF-1.")) || buf[7] < '0' || buf[7] > '7') && (!bytes.HasPrefix(buf, []byte("%PDF-2.")) || buf[7] < '0' || buf[7] > '0') {
		return nil, fmt.Errorf("not a PDF file: invalid header")
	}

	version := buf[5:8]

	end := size

	// Some PDF's are quite broken and have a lot of stuff after %%EOF.
	searchSize := int64(200)
	searchSizeRead := int(0)

EOFDetect:
	for {
		buf = make([]byte, searchSize)

		searchSizeRead, _ = f.ReadAt(buf, end-searchSize)
		for len(buf) > 0 && buf[len(buf)-1] == '\n' || buf[len(buf)-1] == '\r' {
			buf = buf[:len(buf)-1]
		}
		buf = bytes.TrimRight(buf, "\r\n\t ")
		for {
			if len(buf) == 5 {
				break
			}

			if bytes.HasSuffix(buf, []byte("%%EOF")) {
				break EOFDetect
			}

			buf = buf[0 : len(buf)-1]
		}

		searchSize += 200

		if searchSize > end {
			return nil, fmt.Errorf("not a PDF file: missing %%%%EOF")
		}
	}

	eofPosition := len(buf)

	// Read 200 bytes before the %%EOF.
	buf = make([]byte, int64(200))
	f.ReadAt(buf, end-(int64(searchSizeRead)-int64(eofPosition))-int64(len(buf)))

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
	pos := (end - (int64(searchSizeRead) - int64(eofPosition)) - int64(len(buf))) + int64(i)

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

	table := make([]xref, size)

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
	r.XrefInformation.ItemCount = size

	r.XrefInformation.ItemCount = int64(len(table))

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

	var w []int
	for _, x := range ww.ArrayVal {
		i := x.Int64Val
		if x.Kind != Integer || int64(int(i)) != i {
			return nil, fmt.Errorf("invalid W array %v", objfmt(ww))
		}
		w = append(w, int(i))
	}
	if len(w) < 3 {
		return nil, fmt.Errorf("invalid W array %v", objfmt(ww))
	}

	v := Value{r: r, obj: strm}
	wtotal := 0
	for _, wid := range w {
		wtotal += wid
	}
	buf := make([]byte, wtotal)
	data := v.Reader()

	idxArr := index.ArrayVal
	for len(idxArr) > 0 {
		start := idxArr[0].Int64Val
		n := idxArr[1].Int64Val
		if idxArr[0].Kind != Integer || idxArr[1].Kind != Integer {
			return nil, fmt.Errorf("malformed Index pair %v %v", objfmt(idxArr[0]), objfmt(idxArr[1]))
		}
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
			x := int(start) + i
			for cap(table) <= x {
				table = append(table[:cap(table)], xref{})
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
			x := int(start) + i
			for cap(table) <= x {
				table = append(table[:cap(table)], xref{})
			}
			if len(table) <= x {
				table = table[:x+1]
			}
			if alloc == "n" && table[x].offset == 0 {
				table[x] = xref{ptr: objptr{uint32(x), uint16(gen)}, offset: int64(off)}
			}
		}
	}
	return table, nil
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

func (r *Reader) resolve(parent objptr, x Object) (v Value) {
	defer func() {
		if e := recover(); e != nil {
			v = Value{err: fmt.Errorf("panic resolving %v: %v", x, e)}
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
			strm := r.resolve(parent, Object{Kind: Indirect, PtrVal: xref.stream})
		Search:
			for {
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
				for i := 0; i < n; i++ {
					idObj := b.readToken()
					offObj := b.readToken()
					id := idObj.Int64Val
					off := offObj.Int64Val

					if uint32(id) == ptr.id {
						b.seekForward(first + off)
						x = b.readObject()
						break Search
					}
				}
				ext := strm.Key("Extends")
				if ext.Kind() != Stream {
					panic("cannot find object in stream")
				}
				strm = ext
			}
		} else {
			b := newBuffer(io.NewSectionReader(r.f, xref.offset, r.end-xref.offset), xref.offset, r.encVersion)
			defer bufferPool.Put(b) // Return to pool
			b.key = r.key
			b.useAES = r.useAES

			obj = b.readObject()
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
		var err error
		// We need the stream's object ID for decryption.
		// Use s.PtrVal which should be set to definition ID if it was read via readObject.
		// If s was created manually, PtrVal might be empty.
		// But newStreamReader is usually called from resolved objects.

		rd, err = decryptStream(r.key, r.useAES, r.encVersion, s.PtrVal, rd)
		if err != nil {
			return &errorReadCloser{err}
		}
	}

	filters := val.Key("Filter")
	if filters.Kind() == Name {
		var err error
		rd, err = applyFilter(rd, filters.Name(), val.Key("DecodeParms"))
		if err != nil {
			return &errorReadCloser{err}
		}
	} else if filters.Kind() == Array {
		for i := 0; i < filters.Len(); i++ {
			var err error
			rd, err = applyFilter(rd, filters.Index(i).Name(), val.Key("DecodeParms").Index(i))
			if err != nil {
				return &errorReadCloser{err}
			}
		}
	}

	return ioutil.NopCloser(rd)
}

func applyFilter(rd io.Reader, name string, param Value) (io.Reader, error) {
	switch name {
	default:
		return nil, fmt.Errorf("unknown filter %s", name)
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
	n := encrypt["Length"].Int64Val
	if n == 0 {
		n = 40
	}
	// For V=5 (AES-256), Length is usually 256.
	if n%8 != 0 || n > 256 || n < 40 {
		return fmt.Errorf("malformed PDF: %d-bit encryption key", n)
	}
	V := encrypt["V"].Int64Val

	// Support V=5
	if V != 1 && V != 2 && V != 4 && V != 5 {
		return fmt.Errorf("unsupported PDF: encryption version V=%d", V)
	}
	if V == 4 && !okayV4(encrypt) {
		return fmt.Errorf("unsupported PDF: encryption version V=%d", V)
	}

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

	// TODO: Password should be converted to Latin-1.
	pw := []byte(password)
	h := md5.New()
	if len(pw) >= 32 {
		h.Write(pw[:32])
	} else {
		h.Write(pw)
		h.Write(passwordPad[:32-len(pw)])
	}
	h.Write([]byte(O))
	h.Write([]byte{byte(P), byte(P >> 8), byte(P >> 16), byte(P >> 24)})
	h.Write([]byte(ID))

	if R >= 4 {
		e, _ := encrypt["EncryptMetadata"].(bool)
		if !e {
			h.Write([]byte{0xFF, 0xFF, 0xFF, 0xFF})
		}
	}
	
	key := h.Sum(nil)

	if R >= 3 {
		for i := 0; i < 50; i++ {
			h.Reset()
			h.Write(key[:n/8])
			key = h.Sum(key[:0])
		}
		key = key[:n/8]
	} else {
		key = key[:40/8]
	}

	c, err := rc4.NewCipher(key)
	if err != nil {
		return fmt.Errorf("malformed PDF: invalid RC4 key: %v", err)
	}

	var u []byte
	if R == 2 {
		u = make([]byte, 32)
		copy(u, passwordPad)
		c.XORKeyStream(u, u)
	} else {
		h.Reset()
		h.Write(passwordPad)
		h.Write([]byte(ID))
		u = h.Sum(nil)
		c.XORKeyStream(u, u)

		for i := 1; i <= 19; i++ {
			key1 := make([]byte, len(key))
			copy(key1, key)
			for j := range key1 {
				key1[j] ^= byte(i)
			}
			c, _ = rc4.NewCipher(key1)
			c.XORKeyStream(u, u)
		}
	}

	if !bytes.HasPrefix([]byte(U), u) {
		return ErrInvalidPassword
	}

	r.key = key
	r.useAES = V == 4
	r.encVersion = int(V)

	return nil
}

func (r *Reader) initEncryptV5(password string, encrypt map[string]Object) error {
	// AES-256 (V=5, R=5/6)
	// See ISO 32000-2 7.6.3.3 and Extension Level 3 logic

	O := encrypt["O"].StringVal
	U := encrypt["U"].StringVal
	OE := encrypt["OE"].StringVal
	UE := encrypt["UE"].StringVal
	// Perms := encrypt["Perms"].StringVal

	// Standard check for V=5 string lengths
	if len(O) != 48 || len(U) != 48 || len(OE) != 32 || len(UE) != 32 {
		return fmt.Errorf("malformed PDF V=5: invalid O/U/OE/UE length")
	}

	// Authenticate
	// Try User Password (U)
	key, ok := authenticateV5Password(password, []byte(U), []byte(UE))
	if !ok {
		// Try Owner Password (O)
		key, ok = authenticateV5Password(password, []byte(O), []byte(OE))
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

func authenticateV5Password(password string, entry []byte, payload []byte) (fek []byte, ok bool) {
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
	h := sha256.New()
	h.Write(pwdBytes)
	h.Write(valSalt)
	hashComputed := h.Sum(nil)

	if !bytes.Equal(hashComputed, hashStored) {
		return nil, false
	}

	// 2. Decrypt FEK (payload) using derived key
	// Key = SHA256(pwd + KeySalt)
	h.Reset()
	h.Write(pwdBytes)
	h.Write(keySalt)
	kdk := h.Sum(nil) // 32 bytes Key Derivation Key

	// Decrypt payload (UE or OE) using AES-256-CBC with zero IV
	block, err := aes.NewCipher(kdk)
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

var ErrInvalidPassword = fmt.Errorf("encrypted PDF: invalid password")

func okayV4(encrypt map[string]Object) bool {
	cfGen := encrypt["CF"]
	if cfGen.Kind != Dict {
		return false
	}
	cf := cfGen.DictVal
	stmf := encrypt["StmF"].NameVal
	strf := encrypt["StrF"].NameVal
	if stmf != strf {
		return false
	}
	cfparamGen := cf[stmf]
	if cfparamGen.Kind != Dict {
		return false
	}
	cfparam := cfparamGen.DictVal

	if val, ok := cfparam["AuthEvent"]; ok {
		if val.Kind != Name || val.NameVal != "DocOpen" {
			return false
		}
	}
	if val, ok := cfparam["Length"]; ok {
		if val.Kind != Integer || val.Int64Val != 16 {
			return false
		}
	}
	if val, ok := cfparam["CFM"]; ok {
		if val.Kind != Name || val.NameVal != "AESV2" {
			return false
		}
	}
	return true
}

func cryptKey(key []byte, useAES bool, ptr objptr) []byte {
	h := md5.New()
	h.Write(key)
	h.Write([]byte{byte(ptr.id), byte(ptr.id >> 8), byte(ptr.id >> 16), byte(ptr.gen), byte(ptr.gen >> 8)})
	if useAES {
		h.Write([]byte("sAlT"))
	}
	return h.Sum(nil)
}

func decryptString(key []byte, useAES bool, encVersion int, ptr objptr, x string) (string, error) {
	if encVersion < 5 {
		key = cryptKey(key, useAES, ptr)
	}
	// For V=5, key is already the FEK (32 bytes for AES-256)

	if useAES {
		data := []byte(x)
		if len(data) < aes.BlockSize {
			return "", nil
		}
		iv := data[:aes.BlockSize]
		ciphertext := data[aes.BlockSize:]

		block, err := aes.NewCipher(key)
		if err != nil {
			return "", err
		}

		if len(ciphertext)%aes.BlockSize != 0 {
			// return "", fmt.Errorf("decryption error: ciphertext not a multiple of block size")
			// Try to handle gracefully?
			return "", nil
		}

		mode := cipher.NewCBCDecrypter(block, iv)
		mode.CryptBlocks(ciphertext, ciphertext)

		padLen := int(ciphertext[len(ciphertext)-1])
		if padLen > aes.BlockSize || padLen == 0 {
			// return "", fmt.Errorf("decryption error: invalid padding")
			// Handle graceful
			return string(ciphertext), nil
		}
		return string(ciphertext[:len(ciphertext)-padLen]), nil
	} else {
		c, _ := rc4.NewCipher(key)
		data := []byte(x)
		c.XORKeyStream(data, data)
		x = string(data)
	}
	return x, nil
}

func decryptStream(key []byte, useAES bool, encVersion int, ptr objptr, rd io.Reader) (io.Reader, error) {
	if encVersion < 5 {
		key = cryptKey(key, useAES, ptr)
	}

	if useAES {
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, fmt.Errorf("AES: %v", err)
		}

		iv := make([]byte, aes.BlockSize)
		if _, err := io.ReadFull(rd, iv); err != nil {
			return nil, err
		}

		cbc := cipher.NewCBCDecrypter(block, iv)
		return &cbcReader{cbc: cbc, rd: rd, buf: make([]byte, aes.BlockSize)}, nil
	}
	c, _ := rc4.NewCipher(key)
	return &rc4Reader{cipher: c, rd: rd}, nil
}

type cbcReader struct {
	cbc  cipher.BlockMode
	rd   io.Reader
	buf  []byte
	pend []byte
}

func (r *cbcReader) Read(b []byte) (n int, err error) {
	if len(r.pend) > 0 {
		n = copy(b, r.pend)
		r.pend = r.pend[n:]
		return n, nil
	}

	_, err = io.ReadFull(r.rd, r.buf)
	if err != nil {
		if err == io.EOF {
			return 0, io.EOF
		}
		if err == io.ErrUnexpectedEOF {
			return 0, fmt.Errorf("encrypted stream not a multiple of block size")
		}
		return 0, err
	}

	r.cbc.CryptBlocks(r.buf, r.buf)
	r.pend = r.buf

	n = copy(b, r.pend)
	r.pend = r.pend[n:]
	return n, nil
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
