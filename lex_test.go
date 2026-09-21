package pdf

import (
	"bytes"
	"io"
	"strings"
	"testing"
	"time"
)

func TestReadToken(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		wantKind Kind
		wantVal  interface{}
	}{
		{"Integer", "123 ", Integer, int64(123)},
		{"NegativeInteger", "-456 ", Integer, int64(-456)},
		{"Real", "1.23 ", Real, 1.23},
		{"BoolTrue", "true ", Bool, true},
		{"BoolFalse", "false ", Bool, false},
		{"KeywordXref", "xref ", Keyword, "xref"},
		{"KeywordR", "R ", Keyword, "R"},
		{"Name", "/Type ", Name, "Type"},
		{"NameWithHex", "/A#20B ", Name, "A B"},
		{"LiteralString", "(Hello World) ", String, "Hello World"},
		{"LiteralStringEscaped", "(Hello\\nWorld) ", String, "Hello\nWorld"},
		{"HexString", "<414243> ", String, "ABC"},
		{"Null", "null ", Null, nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := newBuffer(io.NewSectionReader(bytes.NewReader([]byte(tt.input)), 0, int64(len(tt.input))), 0, 0)
			obj := b.readToken()
			if obj.Kind != tt.wantKind {
				t.Errorf("readToken().Kind = %v, want %v", obj.Kind, tt.wantKind)
			}
			switch tt.wantKind {
			case Integer:
				if obj.Int64Val != tt.wantVal.(int64) {
					t.Errorf("readToken().Int64Val = %d, want %d", obj.Int64Val, tt.wantVal)
				}
			case Real:
				if obj.Float64Val != tt.wantVal.(float64) {
					t.Errorf("readToken().Float64Val = %f, want %f", obj.Float64Val, tt.wantVal)
				}
			case Bool:
				if obj.BoolVal != tt.wantVal.(bool) {
					t.Errorf("readToken().BoolVal = %v, want %v", obj.BoolVal, tt.wantVal)
				}
			case Keyword:
				if obj.KeywordVal != tt.wantVal.(string) {
					t.Errorf("readToken().KeywordVal = %q, want %q", obj.KeywordVal, tt.wantVal)
				}
			case Name:
				if obj.NameVal != tt.wantVal.(string) {
					t.Errorf("readToken().NameVal = %q, want %q", obj.NameVal, tt.wantVal)
				}
			case String:
				if obj.StringVal != tt.wantVal.(string) {
					t.Errorf("readToken().StringVal = %q, want %q", obj.StringVal, tt.wantVal)
				}
			}
		})
	}
}

func TestReadLiteralString(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"Simple", "(abc)", "abc"},
		{"Nested", "((abc))", "(abc)"},
		{"EscapedNewline", "(a\\\nb)", "ab"},
		{"OctalEscape", "(\\101)", "A"},
		{"MultiOctal", "(\\101\\102\\103)", "ABC"},
		{"SpecialEscapes", "(\\n\\r\\t\\b\\f)", "\n\r\t\b\f"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := newBuffer(io.NewSectionReader(bytes.NewReader([]byte(tt.input)), 0, int64(len(tt.input))), 0, 0)
			// skip '('
			b.readByte()
			obj := b.readLiteralString()
			if obj.StringVal != tt.want {
				t.Errorf("readLiteralString() = %q, want %q", obj.StringVal, tt.want)
			}
		})
	}
}

func TestReadHexString(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"Even", "<4142>", "AB"},
		{"Odd", "<414>", "A@"}, // 41 40 -> A@
		{"Spaces", "< 41 42 >", "AB"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := newBuffer(io.NewSectionReader(bytes.NewReader([]byte(tt.input)), 0, int64(len(tt.input))), 0, 0)
			// skip '<'
			b.readByte()
			obj := b.readHexString()
			if obj.StringVal != tt.want {
				t.Errorf("readHexString() = %q, want %q", obj.StringVal, tt.want)
			}
		})
	}
}

// runWithin reports whether f returns within half a second, failing the test if
// f panics. The time is short because parsers that loop forever also use memory.
func runWithin(t *testing.T, f func()) bool {
	t.Helper()
	done := make(chan any, 1)
	go func() {
		defer func() { done <- recover() }()
		f()
	}()
	select {
	case p := <-done:
		if p != nil {
			t.Errorf("panic: %v", p)
		}
		return true
	case <-time.After(500 * time.Millisecond):
		return false
	}
}

func TestReadObjectHexStringAtEOF(t *testing.T) {
	for _, src := range []string{"<< /Type /Catalog >>\n<ab", "<< /Type /Catalog >>\n<abc"} {
		var obj Object
		if !runWithin(t, func() { obj = newBuffer(strings.NewReader(src), 0, 0).readObject() }) {
			t.Fatalf("readObject(%q) did not return", src)
		}
		if obj.Kind != Dict || obj.DictVal["Type"].NameVal != "Catalog" {
			t.Errorf("readObject(%q) = %s, want the Catalog dictionary", src, objfmt(obj))
		}
	}
}

func TestReadObjectArrayOpenAtEndobj(t *testing.T) {
	for _, src := range []string{"[ 1 2", "<< /Kids [ 1 2 >>"} {
		r := &Reader{}
		setObjects(r, src)
		if !runWithin(t, func() { r.GetObject(1) }) {
			t.Fatalf("GetObject for %q did not return", src)
		}
	}
}
