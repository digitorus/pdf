// Copyright 2014 The Go Authors.  All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Reading of PDF tokens and objects from a raw byte stream.

package pdf

import (
	"fmt"
	"io"
	"strconv"
	"sync"
)

// A buffer holds buffered input bytes from the PDF file.
type buffer struct {
	r           io.Reader // source of data
	buf         []byte    // buffered data
	pos         int       // read index in buf
	realPos     int64     // read index in file
	offset      int64     // offset at end of buf; aka offset of next read
	tmp         []byte    // scratch space for accumulating token
	unread      []Object  // queue of read but then unread tokens
	allowEOF    bool
	allowObjptr bool
	allowStream bool
	decDisabled bool
	eof         bool
	key         []byte
	useAES      bool
	encVersion  int
	objptr      objptr
	line        int
}

var bufferPool = sync.Pool{
	New: func() interface{} {
		return &buffer{
			buf: make([]byte, 0, 4096),
		}
	},
}

// newBuffer returns a new buffer reading from r at the given offset.
func newBuffer(r io.Reader, offset int64, encVersion int) *buffer {
	b := bufferPool.Get().(*buffer)
	b.r = r
	b.offset = offset
	b.buf = b.buf[:0]
	b.pos = 0
	b.realPos = 0
	b.unread = b.unread[:0] // reset slice, keep underlying array
	b.allowEOF = false
	b.allowObjptr = true
	b.allowStream = true
	b.eof = false
	b.key = nil
	b.useAES = false
	b.encVersion = encVersion
	b.objptr = objptr{}
	b.line = 1
	return b
}

func (b *buffer) seek(offset int64) {
	b.offset = offset
	b.buf = b.buf[:0]
	b.pos = 0
	b.realPos = 0
	b.unread = b.unread[:0]
}

func (b *buffer) readByte() byte {
	if b.pos >= len(b.buf) {
		b.reload()
		if b.pos >= len(b.buf) {
			return '\n'
		}
	}
	c := b.buf[b.pos]
	b.pos++
	b.realPos++
	return c
}

func (b *buffer) errorf(format string, args ...interface{}) {
	panic(fmt.Errorf(format, args...))
}

func (b *buffer) reload() bool {
	n := cap(b.buf) - int(b.offset%int64(cap(b.buf)))
	n, err := b.r.Read(b.buf[:n])
	if n == 0 && err != nil {
		b.buf = b.buf[:0]
		b.pos = 0
		b.realPos = 0
		if b.allowEOF && err == io.EOF {
			b.eof = true
			return false
		}
		b.errorf("malformed PDF: reading at offset %d: %v", b.offset, err)
		return false
	}
	b.offset += int64(n)
	b.buf = b.buf[:n]
	b.pos = 0
	return true
}

func (b *buffer) seekForward(offset int64) {
	for b.offset < offset {
		if !b.reload() {
			return
		}
	}
	b.pos = len(b.buf) - int(b.offset-offset)
}

func (b *buffer) readOffset() int64 {
	return b.offset - int64(len(b.buf)) + int64(b.pos)
}

func (b *buffer) unreadByte() {
	if b.pos > 0 {
		b.pos--
		b.realPos--
	}
}

func (b *buffer) unreadToken(t Object) {
	b.unread = append(b.unread, t)
}

func (b *buffer) readToken() Object {
	if n := len(b.unread); n > 0 {
		t := b.unread[n-1]
		b.unread = b.unread[:n-1]
		return t
	}

	// Find first non-space, non-comment byte.
	var c byte
	for {
		// Fast path: skip space in buffer
		for b.pos < len(b.buf) {
			c = b.buf[b.pos]
			if !isSpace(c) {
				break
			}
			b.pos++
			b.realPos++
		}

		if b.pos >= len(b.buf) {
			c = b.readByte() // This handles reload
			if isSpace(c) {
				if b.eof {
					return Object{Kind: Null} // Treat EOF as Null?
				}
				continue
			}
		} else {
			// b.buf[b.pos] is non-space c
			b.pos++
			b.realPos++
		}

		if c == '%' {
			// Comment
			for c != '\r' && c != '\n' {
				c = b.readByte() // Slow path for comments is fine, they are rare-ish
			}
			// c is now newline, loop back to consume it as space
		} else {
			break
		}
	}

	switch c {
	case '<':
		if b.readByte() == '<' {
			return Object{Kind: Keyword, KeywordVal: "<<"}
		}
		b.unreadByte()
		return b.readHexString()

	case '(':
		return b.readLiteralString()

	case '[', ']', '{', '}':
		return Object{Kind: Keyword, KeywordVal: string(c)}

	case '/':
		return b.readName()

	case '>':
		if b.readByte() == '>' {
			return Object{Kind: Keyword, KeywordVal: ">>"}
		}
		b.unreadByte()
		fallthrough

	default:
		if isDelim(c) {
			b.errorf("unexpected delimiter %#q", rune(c))
			return Object{Kind: Null}
		}
		b.unreadByte()
		return b.readKeyword()
	}
}

func (b *buffer) readHexString() Object {
	tmp := b.tmp[:0]
	for {
	Loop:
		c := b.readByte()
		if c == '>' {
			break
		}
		if isSpace(c) {
			goto Loop
		}
	Loop2:
		c2 := b.readByte()
		if c2 == '>' {
			x := unhex(c) << 4
			if x >= 0 {
				tmp = append(tmp, byte(x))
			}
			break
		}
		if isSpace(c2) {
			goto Loop2
		}
		x := unhex(c)<<4 | unhex(c2)
		if x < 0 {
			b.errorf("malformed hex string %c %c", c, c2)
			break
		}
		tmp = append(tmp, byte(x))
	}
	b.tmp = tmp
	return Object{Kind: String, StringVal: string(tmp)}
}

func unhex(b byte) int {
	switch {
	case '0' <= b && b <= '9':
		return int(b) - '0'
	case 'a' <= b && b <= 'f':
		return int(b) - 'a' + 10
	case 'A' <= b && b <= 'F':
		return int(b) - 'A' + 10
	}
	return -1
}

func (b *buffer) readLiteralString() Object {
	tmp := b.tmp[:0]
	depth := 1
Loop:
	for {
		if b.pos >= len(b.buf) {
			if !b.reload() {
				break Loop
			}
		}

		chunkStart := b.pos
		// Scan for separate formatting chars
		for b.pos < len(b.buf) {
			c := b.buf[b.pos]
			if c == ')' {
				if depth--; depth == 0 {
					tmp = append(tmp, b.buf[chunkStart:b.pos]...)
					b.pos++ // consume ')'
					b.realPos += int64(b.pos - chunkStart)
					break Loop
				}
			} else if c == '(' {
				depth++
			} else if c == '\\' {
				// Escape sequence
				tmp = append(tmp, b.buf[chunkStart:b.pos]...)
				b.pos++ // consume '\'
				b.realPos += int64(b.pos - chunkStart)

				// Handle escape
				c = b.readByte()
				switch c {
				default:
					b.errorf("invalid escape sequence \\%c", c)
					tmp = append(tmp, '\\', c)
				case 'n':
					tmp = append(tmp, '\n')
				case 'r':
					tmp = append(tmp, '\r')
				case 'b':
					tmp = append(tmp, '\b')
				case 't':
					tmp = append(tmp, '\t')
				case 'f':
					tmp = append(tmp, '\f')
				case '(', ')', '\\':
					tmp = append(tmp, c)
				case '\r':
					if b.readByte() != '\n' {
						b.unreadByte()
					}
					fallthrough
				case '\n':
					// no append
				case '0', '1', '2', '3', '4', '5', '6', '7':
					x := int(c - '0')
					for i := 0; i < 2; i++ {
						c = b.readByte()
						if c < '0' || c > '7' {
							b.unreadByte()
							break
						}
						x = x*8 + int(c-'0')
					}
					if x > 255 {
						b.errorf("invalid octal escape \\%03o", x)
					}
					tmp = append(tmp, byte(x))
				}
				continue Loop
			} else if c == '\r' || c == '\n' {
				// Newline in string is treated as \n?
				// Spec: "An end-of-line marker appearing within a literal string without a preceding backslash shall be treated as a byte value of (0A)h (LF)"
			}
			b.pos++
		}

		// Consumed buffer chunk
		if b.pos > chunkStart {
			tmp = append(tmp, b.buf[chunkStart:b.pos]...)
			b.realPos += int64(b.pos - chunkStart)
		}
	}
	b.tmp = tmp
	return Object{Kind: String, StringVal: string(tmp)}
}

func (b *buffer) readName() Object {
	tmp := b.tmp[:0]
	// Fast path: scan buffer
Loop:
	for {
		if b.pos >= len(b.buf) {
			if !b.reload() {
				break
			}
		}
		// Scan valid name chars in buffer
		chunkStart := b.pos
		for b.pos < len(b.buf) {
			c := b.buf[b.pos]
			if isDelim(c) || isSpace(c) {
				// End of name
				tmp = append(tmp, b.buf[chunkStart:b.pos]...)
				b.realPos += int64(b.pos - chunkStart)
				// b.pos is on the delimiter/space, leave it for next readToken
				break Loop
			}
			if c == '#' {
				// Hex escape, handle carefully
				// Append what we have
				tmp = append(tmp, b.buf[chunkStart:b.pos]...)
				b.realPos += int64(b.pos - chunkStart)
				b.pos++     // Skip '#'
				b.realPos++ // Update realPos for '#'

				// Read two hex digits
				x := unhex(b.readByte())<<4 | unhex(b.readByte())
				if x < 0 {
					b.errorf("malformed name")
				}
				tmp = append(tmp, byte(x))
				// Continue outer loop to restart scanning
				continue Loop
			}
			b.pos++
		}
		// Consumed everything up to end of buffer
		tmp = append(tmp, b.buf[chunkStart:b.pos]...)
		b.realPos += int64(b.pos - chunkStart)
	}
	b.tmp = tmp

	// Optimization: check for common names without allocating
	if len(tmp) == 2 {
		if string(tmp) == "ID" {
			return Object{Kind: Name, NameVal: "ID"}
		}
	} else if len(tmp) == 4 {
		if string(tmp) == "Type" {
			return Object{Kind: Name, NameVal: "Type"}
		}
		if string(tmp) == "Size" {
			return Object{Kind: Name, NameVal: "Size"}
		}
		if string(tmp) == "Root" {
			return Object{Kind: Name, NameVal: "Root"}
		}
		if string(tmp) == "Prev" {
			return Object{Kind: Name, NameVal: "Prev"}
		}
		if string(tmp) == "Info" {
			return Object{Kind: Name, NameVal: "Info"}
		}
		if string(tmp) == "Kids" {
			return Object{Kind: Name, NameVal: "Kids"}
		}
	} else if len(tmp) == 5 {
		if string(tmp) == "Pages" {
			return Object{Kind: Name, NameVal: "Pages"}
		}
		if string(tmp) == "Count" {
			return Object{Kind: Name, NameVal: "Count"}
		}
	} else if len(tmp) == 6 {
		if string(tmp) == "Filter" {
			return Object{Kind: Name, NameVal: "Filter"}
		}
		if string(tmp) == "Length" {
			return Object{Kind: Name, NameVal: "Length"}
		}
		if string(tmp) == "Parent" { // Fixed: Parent is 6 chars
			return Object{Kind: Name, NameVal: "Parent"}
		}
	} else if len(tmp) == 7 {
		if string(tmp) == "Catalog" {
			return Object{Kind: Name, NameVal: "Catalog"}
		}
		if string(tmp) == "Encrypt" {
			return Object{Kind: Name, NameVal: "Encrypt"}
		}
	} else if len(tmp) == 8 {
		if string(tmp) == "Contents" {
			return Object{Kind: Name, NameVal: "Contents"}
		}
		if string(tmp) == "MediaBox" {
			return Object{Kind: Name, NameVal: "MediaBox"}
		}
		if string(tmp) == "Producer" {
			return Object{Kind: Name, NameVal: "Producer"}
		}
	}

	return Object{Kind: Name, NameVal: string(tmp)}
}

func (b *buffer) readKeyword() Object {
	tmp := b.tmp[:0]
Loop:
	for {
		if b.pos >= len(b.buf) {
			if !b.reload() {
				break
			}
		}
		chunkStart := b.pos
		for b.pos < len(b.buf) {
			c := b.buf[b.pos]
			if isDelim(c) || isSpace(c) {
				tmp = append(tmp, b.buf[chunkStart:b.pos]...)
				b.realPos += int64(b.pos - chunkStart)
				break Loop
			}
			b.pos++
		}
		// Consumed buffer
		tmp = append(tmp, b.buf[chunkStart:b.pos]...)
		b.realPos += int64(b.pos - chunkStart)
	}
	b.tmp = tmp

	// Optimization: check for common keywords without allocating string
	if len(tmp) == 1 {
		if tmp[0] == 'R' {
			return Object{Kind: Keyword, KeywordVal: "R"}
		}
	} else if len(tmp) == 3 {
		if string(tmp) == "obj" {
			return Object{Kind: Keyword, KeywordVal: "obj"}
		}
	} else if len(tmp) == 4 {
		if string(tmp) == "true" {
			return Object{Kind: Bool, BoolVal: true}
		}
		if string(tmp) == "null" {
			return Object{Kind: Null}
		}
		if string(tmp) == "xref" {
			return Object{Kind: Keyword, KeywordVal: "xref"}
		}
	} else if len(tmp) == 5 {
		if string(tmp) == "false" {
			return Object{Kind: Bool, BoolVal: false}
		}
	} else if len(tmp) == 6 {
		if string(tmp) == "endobj" {
			return Object{Kind: Keyword, KeywordVal: "endobj"}
		}
		if string(tmp) == "stream" {
			return Object{Kind: Keyword, KeywordVal: "stream"}
		}
	} else if len(tmp) == 7 {
		if string(tmp) == "trailer" {
			return Object{Kind: Keyword, KeywordVal: "trailer"}
		}
	} else if len(tmp) == 9 {
		if string(tmp) == "endstream" {
			return Object{Kind: Keyword, KeywordVal: "endstream"}
		}
		if string(tmp) == "startxref" {
			return Object{Kind: Keyword, KeywordVal: "startxref"}
		}
	}

	// Optimization: parse numbers directly from tmp without allocation
	if isIntegerBytes(tmp) {
		x, err := parseIntBytes(tmp)
		if err == nil {
			return Object{Kind: Integer, Int64Val: x}
		}
	} else if isRealBytes(tmp) {
		x, err := parseFloatBytes(tmp)
		if err == nil {
			return Object{Kind: Real, Float64Val: x}
		}
	}

	return Object{Kind: Keyword, KeywordVal: string(tmp)}
}

func (b *buffer) readObject() Object {
	if len(b.unread) == 0 {
		// Optimization: Try to read indirect object/reference without boxing integers
		if obj, ok := b.tryReadIndirect(); ok {
			return obj
		}
	}

	tok := b.readToken()
	if tok.Kind == Keyword {
		kw := tok.KeywordVal
		switch kw {
		case "null":
			return Object{Kind: Null}
		case "endobj":
			b.unreadToken(tok)
			return Object{Kind: Null}
		case "<<":
			return b.readDict()
		case "[":
			return b.readArray()
		case "]", ">>", "}":
			return tok
		}

		b.errorf("unexpected keyword %q parsing object", kw)
		return Object{Kind: Null}
	}

	if tok.Kind == String && b.key != nil && b.objptr.id != 0 {
		if !b.decDisabled {
			str := tok.StringVal
			decrypted, err := decryptString(b.key, b.useAES, b.encVersion, b.objptr, str)
			if err != nil {
				panic(err)
			}
		} else {
			decrypted = tok.StringVal
		}
		return Object{Kind: String, StringVal: decrypted}
	}

	if !b.allowObjptr {
		return tok
	}

	if tok.Kind == Integer {
		t1 := tok.Int64Val
		if int64(uint32(t1)) == t1 {
			tok2 := b.readToken()
			if tok2.Kind == Integer {
				t2 := tok2.Int64Val
				if int64(uint16(t2)) == t2 {
					tok3 := b.readToken()
					if tok3.Kind == Keyword {
						switch tok3.KeywordVal {
						case "R":
							return Object{Kind: Indirect, PtrVal: objptr{uint32(t1), uint16(t2)}}
						case "obj":
							old := b.objptr
							b.objptr = objptr{uint32(t1), uint16(t2)}
							obj := b.readObject()
							if obj.Kind != Stream {
								tok4 := b.readToken()
								if tok4.Kind != Keyword || tok4.KeywordVal != "endobj" {
									b.errorf("missing endobj after indirect object definition")
									b.unreadToken(tok4)
								}
							}
							b.objptr = old
							// Re-use PtrVal for definition ID
							res := obj
							res.PtrVal = objptr{uint32(t1), uint16(t2)}
							return res
						}
					}
					b.unreadToken(tok3)
				}
				b.unreadToken(tok2)
			} else {
				// tok2 is not Integer, put it back
				b.unreadToken(tok2)
			}
		}
	}
	return tok
}

func (b *buffer) tryReadIndirect() (Object, bool) {
	// Snapshot state to rollback
	startPos := b.pos
	startRealPos := b.realPos
	var i1, i2 int64
	var c byte

	if b.pos >= len(b.buf) {
		return Object{}, false
	}

	// Skip space
	for b.pos < len(b.buf) && isSpace(b.buf[b.pos]) {
		b.pos++
		b.realPos++
	}
	if b.pos >= len(b.buf) {
		goto Fail
	}

	// Parse Int 1
	if !isDigit(b.buf[b.pos]) {
		goto Fail
	}
	// i1
	for b.pos < len(b.buf) && isDigit(b.buf[b.pos]) {
		i1 = i1*10 + int64(b.buf[b.pos]-'0')
		b.pos++
		b.realPos++
	}
	if b.pos >= len(b.buf) {
		goto Fail
	}
	if !isSpace(b.buf[b.pos]) {
		goto Fail
	}

	// Skip space
	for b.pos < len(b.buf) && isSpace(b.buf[b.pos]) {
		b.pos++
		b.realPos++
	}
	if b.pos >= len(b.buf) {
		goto Fail
	}

	// Parse Int 2
	if !isDigit(b.buf[b.pos]) {
		goto Fail
	}
	// i2
	for b.pos < len(b.buf) && isDigit(b.buf[b.pos]) {
		i2 = i2*10 + int64(b.buf[b.pos]-'0')
		b.pos++
		b.realPos++
	}
	if b.pos >= len(b.buf) {
		goto Fail
	}
	if !isSpace(b.buf[b.pos]) {
		goto Fail
	}

	// Skip space
	for b.pos < len(b.buf) && isSpace(b.buf[b.pos]) {
		b.pos++
		b.realPos++
	}
	if b.pos >= len(b.buf) {
		goto Fail
	}

	// Check for 'R' or 'obj'
	c = b.buf[b.pos]
	if c == 'R' {
		if b.pos+1 < len(b.buf) {
			next := b.buf[b.pos+1]
			if !isSpace(next) && !isDelim(next) {
				goto Fail
			}
		}
		b.pos++
		b.realPos++
		return Object{Kind: Indirect, PtrVal: objptr{uint32(i1), uint16(i2)}}, true
	} else if c == 'o' {
		if b.pos+2 < len(b.buf) && b.buf[b.pos+1] == 'b' && b.buf[b.pos+2] == 'j' {
			// obj
			if b.pos+3 < len(b.buf) {
				next := b.buf[b.pos+3]
				if !isSpace(next) && !isDelim(next) {
					goto Fail
				}
			}
			b.pos += 3
			b.realPos += 3

			old := b.objptr
			b.objptr = objptr{uint32(i1), uint16(i2)}
			obj := b.readObject()

			if obj.Kind != Stream {
				tok4 := b.readToken()
				if tok4.Kind != Keyword || tok4.KeywordVal != "endobj" {
					b.errorf("missing endobj after indirect object definition")
					b.unreadToken(tok4)
				}
			}
			b.objptr = old
			// Reuse PtrVal for definition ID
			obj.PtrVal = objptr{uint32(i1), uint16(i2)}
			return obj, true
		}
	}

Fail:
	b.pos = startPos
	b.realPos = startRealPos
	return Object{}, false
}

func isDigit(c byte) bool {
	return c >= '0' && c <= '9'
}

func (b *buffer) readArray() Object {
	x := make([]Object, 0, 8)
	for {
		obj := b.readObject()
		if obj.Kind == Keyword && obj.KeywordVal == "]" {
			break
		}
		if obj.Kind == Null && b.eof {
			break
		}
		x = append(x, obj)
	}
	return Object{Kind: Array, ArrayVal: x}
}

func (b *buffer) readDict() Object {
	x := make(map[string]Object)
	decDisabled := false
	for {
		tok := b.readToken()
		if tok.Kind == Keyword && tok.KeywordVal == ">>" {
			break
		}
		if tok.Kind == Null && b.eof {
			break
		} // Handle EOF in dict

		if tok.Kind != Name {
			b.errorf("unexpected non-name key %v parsing dictionary", tok)
			continue
		}
		n := tok.NameVal

		if decDisabled && (n == "Contents" || n == "ByteRange") {
			b.decDisabled = true
		}
		
		x[n] = b.readObject()

		b.decDisabled = false

		if n == "Type" && x[n] == "Sig" {
			decDisabled = true
		}
	}

	if !b.allowStream {
		return Object{Kind: Dict, DictVal: x}
	}

	b.allowEOF = true
	tok := b.readToken()
	if tok.Kind != Keyword || tok.KeywordVal != "stream" {
		b.unreadToken(tok)
		b.allowEOF = false // Reset for future reads if needed
		return Object{Kind: Dict, DictVal: x}
	}
	b.allowEOF = false // Found stream, reset for stream content reading

	switch b.readByte() {
	case '\r':
		if b.readByte() != '\n' {
			b.unreadByte()
		}
	case '\n':
		// ok
	default:
		b.errorf("stream keyword not followed by newline")
	}

	return Object{
		Kind:         Stream,
		DictVal:      x,
		StreamOffset: b.readOffset(),
	}
}

func isSpace(b byte) bool {
	switch b {
	case '\x00', '\t', '\n', '\f', '\r', ' ':
		return true
	}
	return false
}

func isDelim(b byte) bool {
	switch b {
	case '<', '>', '(', ')', '[', ']', '{', '}', '/', '%':
		return true
	}
	return false
}

func isIntegerBytes(b []byte) bool {
	if len(b) > 0 && (b[0] == '+' || b[0] == '-') {
		b = b[1:]
	}
	if len(b) == 0 {
		return false
	}
	for _, c := range b {
		if c < '0' || '9' < c {
			return false
		}
	}
	return true
}

func isRealBytes(b []byte) bool {
	if len(b) > 0 && (b[0] == '+' || b[0] == '-') {
		b = b[1:]
	}
	if len(b) == 0 {
		return false
	}
	ndot := 0
	for _, c := range b {
		if c == '.' {
			ndot++
			continue
		}
		if c < '0' || '9' < c {
			return false
		}
	}
	return ndot == 1
}

func parseIntBytes(b []byte) (int64, error) {
	var n int64
	var sign int64 = 1
	if len(b) > 0 {
		if b[0] == '-' {
			sign = -1
			b = b[1:]
		} else if b[0] == '+' {
			b = b[1:]
		}
	}
	for _, c := range b {
		if c < '0' || c > '9' {
			return 0, fmt.Errorf("invalid digit")
		}
		d := int64(c - '0')
		n = n*10 + d
	}
	return n * sign, nil
}

func parseFloatBytes(b []byte) (float64, error) {
	return strconv.ParseFloat(string(b), 64)
}
