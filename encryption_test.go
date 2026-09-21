package pdf

import (
	"bytes"
	"compress/zlib"
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"fmt"
	"io"
	"slices"
	"strings"
	"testing"
)

func TestCryptKey(t *testing.T) {
	key := []byte("secret")
	ptr := objptr{id: 10, gen: 0}

	ck1 := cryptKey(key, false, ptr)
	ck2 := cryptKey(key, false, ptr)
	if string(ck1) != string(ck2) {
		t.Error("cryptKey not deterministic")
	}

	ckAES := cryptKey(key, true, ptr)
	if string(ck1) == string(ckAES) {
		t.Error("cryptKey should differ for AES (salt)")
	}
}

func TestDecryptStringRC4(t *testing.T) {
	key := []byte("testkey")
	ptr := objptr{id: 5, gen: 0}
	data := "Hello PDF"

	// Encrypt manually using rc4 logic from read.go
	encrypted := decryptString(key, false, 2, ptr, data)
	// Decrypting again with same key/ptr should recover original because RC4 is XOR
	decrypted := decryptString(key, false, 2, ptr, encrypted)

	if decrypted != data {
		t.Errorf("RC4 Decryption failed: got %q, want %q", decrypted, data)
	}
}

func TestDecryptStringAES(t *testing.T) {
	key := make([]byte, 16) // 128-bit key
	ptr := objptr{id: 1, gen: 0}

	// Create valid AES-CBC encrypted block with padding
	// 16 bytes IV + data
	plaintext := "SecretMessage!!!" // 16 bytes
	iv := make([]byte, 16)
	for i := range iv {
		iv[i] = byte(i)
	}

	block, _ := aes.NewCipher(key) // This is not the derived key, but for simple test it's fine
	mode := cipher.NewCBCEncrypter(block, iv)

	ciphertext := make([]byte, 16)
	mode.CryptBlocks(ciphertext, []byte(plaintext))

	// Add padding block (16 bytes of 0x10)
	padding := make([]byte, 16)
	for i := range padding {
		padding[i] = 16
	}
	ciphertextPadded := make([]byte, 16)
	mode.CryptBlocks(ciphertextPadded, padding)

	full := append(iv, ciphertext...)
	full = append(full, ciphertextPadded...)

	// We need to bypass cryptKey for this unit test or use a pre-calculated derived key.
	// decryptString calls cryptKey(key, true, ptr) if encVersion < 5.
	// Let's use V5 logic which uses the key directly.

	decrypted := decryptString(key, true, 5, ptr, string(full))

	if decrypted != plaintext {
		t.Errorf("AES Decryption mismatch: got %q, want %q", decrypted, plaintext)
	}
}
func TestAuthenticateV5(t *testing.T) {
	// Vectors from gen_v5.go
	pwd := "user"
	uHex := "8a35e0ef6b995a3af7a084c7b39f3f9aa96f4ce6b961d27d5ee084a779b93ec331323334353637383837363534333231"
	ueHex := "fdf2ebcf67bd7c6f527008513dd4c01c4d5a3db53b16f3713ab07e58e67026e9"

	u, _ := hex.DecodeString(uHex)
	ue, _ := hex.DecodeString(ueHex)

	fek, ok := authenticateV5Password(5, pwd, u, ue, nil)
	if !ok {
		t.Fatal("Authentication failed")
	}

	expectedFEK := []byte("32-byte-fek-must-be-exactly-32-b")
	if !bytes.Equal(fek, expectedFEK) {
		t.Errorf("FEK mismatch: %q, want %q", string(fek), string(expectedFEK))
	}
}

func TestDecryptStream(t *testing.T) {
	key := make([]byte, 16)
	ptr := objptr{id: 1, gen: 0}

	data := []byte("0123456789ABCDEF") // 16 bytes, exactly one block
	// For simplicity, test with V5 logic (no crpytKey)
	// DecryptStream expects a derived key. If version < 5 it calls cryptKey.
	// We'll test version 5 to skip cryptKey derivation.

	// Create ciphertext
	block, _ := aes.NewCipher(key)
	iv := make([]byte, aes.BlockSize)
	// PKCS#7 adds a full block of 16 bytes if original data is 16 bytes
	padding := bytes.Repeat([]byte{16}, 16)
	padded := append(data, padding...)
	ciphertext := make([]byte, len(padded))
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext, padded)

	full := append(iv, ciphertext...)

	resultRd, err := decryptStream(key, true, 5, ptr, bytes.NewReader(full))
	if err != nil {
		t.Fatalf("decryptStream failed: %v", err)
	}

	got, err := io.ReadAll(resultRd)
	if err != nil {
		t.Fatalf("reading decrypted stream: %v", err)
	}
	if !bytes.Equal(got, data) {
		t.Errorf("Decrypted data mismatch: %q, want %q", string(got), string(data))
	}
}

func TestDecryptInvalidPadding(t *testing.T) {
	key := make([]byte, 32)
	iv := make([]byte, aes.BlockSize)
	block, _ := aes.NewCipher(key)

	for _, data := range []string{
		"0123456789ABCDE\x00",
		"0123456789ABCD\x01\x02",
		"0123456789ABCDE\n",
		"0123456789ABCDEF",
	} {
		ciphertext := make([]byte, len(data))
		cipher.NewCBCEncrypter(block, iv).CryptBlocks(ciphertext, []byte(data))
		encrypted := append(iv, ciphertext...)

		if got := decryptString(key, true, 5, objptr{id: 1}, string(encrypted)); got != data {
			t.Errorf("decryptString = %q, want %q", got, data)
		}
		rd, err := decryptStream(key, true, 5, objptr{id: 1}, bytes.NewReader(encrypted))
		if err != nil {
			t.Fatalf("decryptStream: %v", err)
		}
		if got, err := io.ReadAll(rd); string(got) != data || err != nil {
			t.Errorf("decryptStream = %q, %v; want %q", got, err, data)
		}
	}
}

func TestReaderEncryptStreamRoundTrip(t *testing.T) {
	tests := []struct {
		name       string
		key        []byte
		useAES     bool
		encVersion int
	}{
		{"RC4 V2", bytes.Repeat([]byte{0x33}, 5), false, 2},
		{"AES-128 V4", bytes.Repeat([]byte{0x11}, 16), true, 4},
		{"AES-256 V5", bytes.Repeat([]byte{0x22}, 32), true, 5},
	}
	content := []byte("BT /F1 12 Tf 20 100 Td (Hello secret world) Tj ET")

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &Reader{key: tt.key, useAES: tt.useAES, encVersion: tt.encVersion}
			for _, n := range []int{0, 1, 15, 16, 17, 38, len(content)} {
				data := content[:n]
				enc, err := r.Encrypt(NewPtr(12, 0), data)
				if err != nil {
					t.Fatalf("Encrypt: %v", err)
				}
				rd, err := decryptStream(tt.key, tt.useAES, tt.encVersion, objptr{12, 0}, bytes.NewReader(enc))
				if err != nil {
					t.Fatalf("decryptStream: %v", err)
				}
				got, err := io.ReadAll(rd)
				if err != nil {
					t.Fatalf("reading decrypted stream: %v", err)
				}
				if !bytes.Equal(got, data) {
					t.Errorf("%d bytes read back as %q, want %q", n, got, data)
				}
			}
		})
	}
}

// onceErrorReader reads data, but fails once after the first at bytes.
type onceErrorReader struct {
	data []byte
	at   int
	err  error
}

func (r *onceErrorReader) Read(b []byte) (int, error) {
	if r.at == 0 && r.err != nil {
		err := r.err
		r.err = nil
		return 0, err
	}
	if len(r.data) == 0 {
		return 0, io.EOF
	}
	if r.err != nil && len(b) > r.at {
		b = b[:r.at]
	}
	n := copy(b, r.data)
	r.data = r.data[n:]
	r.at -= n
	return n, nil
}

func TestDecryptStreamReadError(t *testing.T) {
	r := &Reader{key: bytes.Repeat([]byte{0x22}, 32), useAES: true, encVersion: 5}
	enc, err := r.Encrypt(NewPtr(12, 0), []byte("BT /F1 12 Tf 20 100 Td (Hello secret world) Tj ET"))
	if err != nil {
		t.Fatal(err)
	}
	failure := fmt.Errorf("read failure")
	// The failure comes in the middle of the first block after the IV.
	rd, err := decryptStream(r.key, true, 5, objptr{12, 0}, &onceErrorReader{data: enc, at: 24, err: failure})
	if err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 100)
	if _, err := rd.Read(buf); err != failure {
		t.Fatalf("Read: got %v, want %v", err, failure)
	}
	if n, err := rd.Read(buf); err == nil {
		t.Errorf("Read after a failure: got %d bytes and no error, want the failure", n)
	}
}

// TestDecryptStreamLengthWithEOL reads AES streams whose /Length also counts
// the end-of-line marker before endstream.
func TestDecryptStreamLengthWithEOL(t *testing.T) {
	const content = "BT /F1 12 Tf 20 100 Td (Hello secret world) Tj ET"
	var compressed bytes.Buffer
	zw := zlib.NewWriter(&compressed)
	zw.Write([]byte(content))
	zw.Close()

	tests := []struct {
		name   string
		data   []byte
		filter string
	}{
		{"FlateDecode", compressed.Bytes(), "FlateDecode"},
		{"no filter", []byte(content), ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &Reader{key: bytes.Repeat([]byte{0x11}, 16), useAES: true, encVersion: 4}
			enc, err := r.Encrypt(NewPtr(12, 0), tt.data)
			if err != nil {
				t.Fatal(err)
			}
			var dict map[string]Object
			if tt.filter != "" {
				dict = map[string]Object{"Filter": {Kind: Name, NameVal: tt.filter}}
			}
			if got, err := readStreamData(r, dict, append(enc, '\n')); got != content || err != nil {
				t.Errorf("read %q, %v; want %q, nil", got, err, content)
			}
		})
	}
}

func TestDecryptStreamShortLength(t *testing.T) {
	const content = "BT /F1 12 Tf 20 100 Td (Hello secret world) Tj ET"
	r := &Reader{key: bytes.Repeat([]byte{0x11}, 16), useAES: true, encVersion: 4}
	enc, err := r.Encrypt(NewPtr(12, 0), []byte(content))
	if err != nil {
		t.Fatal(err)
	}
	// A /Length that cuts off whole blocks cannot be told from a complete
	// stream, but one that ends in the middle of a block must not be read as
	// if the data ended there.
	for _, cut := range []int{1, 8, 15} {
		data := slices.Clone(enc[:len(enc)-cut])
		// The IV is random, so the bytes after the last complete block may
		// happen to be whitespace, which reads as an end-of-line marker.
		for i := len(data) - len(data)%aes.BlockSize; i < len(data); i++ {
			if isSpace(data[i]) {
				data[i] = 'x'
			}
		}
		got, err := readStreamData(r, nil, data)
		if err == nil {
			t.Errorf("read of a stream %d bytes short = %q, %v; want an error", cut, got, err)
		}
	}
}

func TestDecryptEmptyStreamWithEOL(t *testing.T) {
	r := &Reader{key: bytes.Repeat([]byte{0x11}, 16), useAES: true, encVersion: 4}
	for _, data := range []string{"", "\n", "\r\n"} {
		if got, err := readStreamData(r, nil, []byte(data)); got != "" || err != nil {
			t.Errorf("read of %q = %q, %v; want an empty stream", data, got, err)
		}
	}
	if got, err := readStreamData(r, nil, []byte("0123456789")); err == nil {
		t.Errorf("read of a stream shorter than the IV = %q, nil; want an error", got)
	}
}

func readStreamData(r *Reader, dict map[string]Object, data []byte) (string, error) {
	d := map[string]Object{"Length": {Kind: Integer, Int64Val: int64(len(data))}}
	for k, v := range dict {
		d[k] = v
	}
	r.f = bytes.NewReader(data)
	got, err := io.ReadAll(newStreamReader(Object{Kind: Stream, DictVal: d, PtrVal: objptr{12, 0}}, r))
	return string(got), err
}

// setObjects makes objects 1, 2, ... the content of the file that r reads.
func setObjects(r *Reader, objects ...string) {
	var buf bytes.Buffer
	buf.WriteString("%PDF-1.7\n")
	r.xref = make([]xref, len(objects)+1)
	for i, obj := range objects {
		id := uint32(i + 1)
		r.xref[id] = xref{ptr: objptr{id: id}, offset: int64(buf.Len())}
		fmt.Fprintf(&buf, "%d 0 obj\n%s\nendobj\n", id, obj)
	}
	r.f = bytes.NewReader(buf.Bytes())
	r.end = int64(buf.Len())
	r.objCache = make(map[uint32]Value)
}

func TestCryptFilter(t *testing.T) {
	const content = "BT /F1 12 Tf 20 100 Td (Hello secret world) Tj ET"
	r := &Reader{key: bytes.Repeat([]byte{0x11}, 16), useAES: true, encVersion: 4,
		cryptFilters: map[string]string{"StdCF": "AESV2"}}
	encrypted, err := r.Encrypt(NewPtr(12, 0), []byte(content))
	if err != nil {
		t.Fatal(err)
	}
	var compressed bytes.Buffer
	zw := zlib.NewWriter(&compressed)
	zw.Write([]byte(content))
	zw.Close()

	name := func(n string) Object { return Object{Kind: Name, NameVal: n} }
	tests := []struct {
		name string
		dict map[string]Object
		data []byte
	}{
		{"Identity by default", map[string]Object{"Filter": name("Crypt")}, []byte(content)},
		{
			"Identity before FlateDecode",
			map[string]Object{
				"Filter": {Kind: Array, ArrayVal: []Object{name("Crypt"), name("FlateDecode")}},
				"DecodeParms": {Kind: Array, ArrayVal: []Object{
					{Kind: Dict, DictVal: map[string]Object{"Type": name("CryptFilterDecodeParms"), "Name": name("Identity")}},
					{Kind: Null},
				}},
			},
			compressed.Bytes(),
		},
		{
			"document crypt filter",
			map[string]Object{
				"Filter":      {Kind: Array, ArrayVal: []Object{name("Crypt")}},
				"DecodeParms": {Kind: Array, ArrayVal: []Object{{Kind: Dict, DictVal: map[string]Object{"Name": name("StdCF")}}}},
			},
			encrypted,
		},
		{
			// One filter may have a single DecodeParms dictionary.
			"document crypt filter with a DecodeParms dictionary",
			map[string]Object{
				"Filter":      {Kind: Array, ArrayVal: []Object{name("Crypt")}},
				"DecodeParms": {Kind: Dict, DictVal: map[string]Object{"Name": name("StdCF")}},
			},
			encrypted,
		},
		{
			"document crypt filter with a DecodeParms array",
			map[string]Object{
				"Filter":      name("Crypt"),
				"DecodeParms": {Kind: Array, ArrayVal: []Object{{Kind: Dict, DictVal: map[string]Object{"Name": name("StdCF")}}}},
			},
			encrypted,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, err := readStreamData(r, tt.dict, tt.data); got != content || err != nil {
				t.Errorf("read %q, %v; want %q, nil", got, err, content)
			}
		})
	}
}

// TestNamedCryptFilterMethod reads streams that name a crypt filter of the
// document other than the one that /StmF names, which must be read with the
// method of the filter they name.
func TestNamedCryptFilterMethod(t *testing.T) {
	const content = "BT /F1 12 Tf 20 100 Td (Hello secret world) Tj ET"
	key := bytes.Repeat([]byte{0x11}, 16)
	name := func(n string) Object { return Object{Kind: Name, NameVal: n} }

	// The document encrypts its streams with AESV2 and also defines a crypt
	// filter for RC4 and one that does not encrypt.
	r := &Reader{key: key, useAES: true, encVersion: 4, cryptFilters: map[string]string{
		"StdCF": "AESV2", "RC4F": "V2", "NoneF": "None",
	}}
	aes, err := r.Encrypt(NewPtr(12, 0), []byte(content))
	if err != nil {
		t.Fatal(err)
	}
	rc4Doc := &Reader{key: key, useAES: false, encVersion: 4}
	rc4, err := rc4Doc.Encrypt(NewPtr(12, 0), []byte(content))
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		filter string
		data   []byte
	}{
		{"StdCF", aes},
		{"RC4F", rc4},
		{"NoneF", []byte(content)},
	}
	for _, tt := range tests {
		for _, params := range []struct {
			shape string
			parms Object
		}{
			{"DecodeParms array", Object{Kind: Array, ArrayVal: []Object{{Kind: Dict, DictVal: map[string]Object{"Name": name(tt.filter)}}}}},
			{"DecodeParms dictionary", Object{Kind: Dict, DictVal: map[string]Object{"Name": name(tt.filter)}}},
		} {
			t.Run(tt.filter+" with a "+params.shape, func(t *testing.T) {
				dict := map[string]Object{
					"Filter":      {Kind: Array, ArrayVal: []Object{name("Crypt")}},
					"DecodeParms": params.parms,
				}
				if got, err := readStreamData(r, dict, tt.data); got != content || err != nil {
					t.Errorf("read %q, %v; want %q, nil", got, err, content)
				}
			})
		}
	}

	t.Run("unknown filter", func(t *testing.T) {
		dict := map[string]Object{
			"Filter":      {Kind: Array, ArrayVal: []Object{name("Crypt")}},
			"DecodeParms": {Kind: Array, ArrayVal: []Object{{Kind: Dict, DictVal: map[string]Object{"Name": name("NoSuchCF")}}}},
		}
		if got, err := readStreamData(r, dict, aes); err == nil {
			t.Errorf("read %q, %v; want an error", got, err)
		}
	})
}

// TestNamedCryptFilterDocument reads a document whose page content stream names
// a crypt filter other than the one of /StmF, end to end. qpdf 12.4 decrypts
// this document to the same content.
func TestNamedCryptFilterDocument(t *testing.T) {
	const qpdfID = "31415926535897932384626433832795"
	const content = "BT /F1 12 Tf 20 100 Td (Hello secret world) Tj ET"
	// The file key of the AES-128 document that qpdf 12.4 wrote with user
	// password "userpw", whose /Encrypt dictionary this document reuses.
	rc4Doc := &Reader{key: mustHex(t, "567053e9cfea0f89ae6fbdb37334a454"), useAES: false, encVersion: 4}
	enc, err := rc4Doc.Encrypt(NewPtr(4, 0), []byte(content))
	if err != nil {
		t.Fatal(err)
	}

	objects := []string{
		"<< /Type /Catalog /Pages 2 0 R >>",
		"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
		"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] /Contents 4 0 R >>",
		fmt.Sprintf("<< /Length %d /Filter [/Crypt] /DecodeParms [<< /Type /CryptFilterDecodeParms /Name /RC4F >>] >>\nstream\n%s\nendstream",
			len(enc), enc),
		"<< /Filter /Standard /V 4 /R 4 /Length 128 /P -4" +
			" /O <07c02079e0d8d0c3404477e977b56ef1720b2f6be2a464225fb7e72ffc05cc7f>" +
			" /U <3eadea12150bd88e74ec04a486eabc780021446990b9e4114071a4d9104984c1>" +
			" /CF << /StdCF << /AuthEvent /DocOpen /CFM /AESV2 /Length 16 >>" +
			" /RC4F << /AuthEvent /DocOpen /CFM /V2 /Length 16 >> >> /StmF /StdCF /StrF /StdCF >>",
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
	fmt.Fprintf(&buf, "trailer\n<< /Size %d /Root 1 0 R /Encrypt 5 0 R /ID [<%s><%s>] >>\nstartxref\n%d\n%%%%EOF\n",
		len(objects)+1, qpdfID, qpdfID, xrefPos)

	data := buf.Bytes()
	r, err := NewReaderEncrypted(bytes.NewReader(data), int64(len(data)), passwordOnce("userpw"))
	if err != nil {
		t.Fatalf("NewReaderEncrypted: %v", err)
	}
	if got := string(r.Page(1).V.Key("Contents").Data()); got != content {
		t.Errorf("the page content is %q, want %q", got, content)
	}
}

// TestCleartextMetadata uses the dictionaries of documents encrypted by qpdf 12.4
// with user password "userpw", with and without --cleartext-metadata.
func TestCleartextMetadata(t *testing.T) {
	const xmp = `<x:xmpmeta xmlns:x="adobe:ns:meta/"/>`
	aesV2 := func(u string, cleartext bool) map[string]Object {
		encrypt := v4Encrypt(t, -4, 16, "07c02079e0d8d0c3404477e977b56ef1720b2f6be2a464225fb7e72ffc05cc7f", u)
		if cleartext {
			encrypt["EncryptMetadata"] = Object{Kind: Bool, BoolVal: false}
		}
		return encrypt
	}
	r6 := v5Encrypt(t, 6,
		"a86b1fc21944c04902e1f90318137d096d4eb74681b0e8886fb3f12f73546287f0faf49ee361de38325c9e6fc48b1143",
		"8aa8508836366fdc269b17303d9624c50b4e367817393837d3241c0767b21ca904251eeb6c0c5f126ca64c8aad2f3cc5",
		"cd3388e143803eb24255da906ed866278ca58a581824eba9e22c75abfb0669b5",
		"248e978b0d3b99864db319b0d4626960d2771d639f3b3361d8b05ca69decd4c7")
	r6["EncryptMetadata"] = Object{Kind: Bool, BoolVal: false}

	tests := []struct {
		name      string
		encrypt   map[string]Object
		cleartext bool
	}{
		{"R4", aesV2("3eadea12150bd88e74ec04a486eabc780021446990b9e4114071a4d9104984c1", false), false},
		{"R4-cleartext-metadata", aesV2("f28817bad2ec0570e790aba88ff407740021446990b9e4114071a4d9104984c1", true), true},
		{"R6-cleartext-metadata", r6, true},
	}
	stream := func(typ string, data []byte) string {
		return fmt.Sprintf("<< /Type /%s /Subtype /XML /Length %d >>\nstream\n%s\nendstream", typ, len(data), data)
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := encryptedReader(t, tt.encrypt, "31415926535897932384626433832795")
			if err := r.initEncrypt("userpw"); err != nil {
				t.Fatalf("initEncrypt: %v", err)
			}
			if got := r.EncryptsMetadata(); got == tt.cleartext {
				t.Errorf("EncryptsMetadata() = %v, want %v", got, !tt.cleartext)
			}
			encrypted := func(id uint32) []byte {
				data, err := r.Encrypt(NewPtr(id, 0), []byte(xmp))
				if err != nil {
					t.Fatal(err)
				}
				return data
			}
			// Only the metadata stream of the catalog is left unencrypted.
			documentMetadata := encrypted(2)
			if tt.cleartext {
				documentMetadata = []byte(xmp)
			}
			setObjects(r,
				"<< /Type /Catalog /Metadata 2 0 R >>",
				stream("Metadata", documentMetadata),
				stream("XObject", encrypted(3)),
				stream("Metadata", encrypted(4)),
			)
			r.trailer.DictVal["Root"] = Object{Kind: Indirect, PtrVal: objptr{id: 1}}

			for id := uint32(2); id <= 4; id++ {
				v, err := r.GetObject(id)
				if err != nil {
					t.Fatal(err)
				}
				if got, err := io.ReadAll(v.Reader()); string(got) != xmp || err != nil {
					t.Errorf("stream %d = %q, %v; want %q, nil", id, got, err, xmp)
				}
			}
		})
	}
}

func TestXRefStreamNotDecrypted(t *testing.T) {
	const id = "0123456789abcdef0123456789abcdef"
	src := "%PDF-1.7\n8 0 obj\n<< /Type /XRef /ID [<" + id + "> <" + id + ">] /Size 9 /W [1 2 1] /Length 4 >>\nstream\n\x01\x00\x0f\x00\nendstream\nendobj\n"
	r := &Reader{
		f:          bytes.NewReader([]byte(src)),
		end:        int64(len(src)),
		xref:       make([]xref, 9),
		objCache:   make(map[uint32]Value),
		key:        bytes.Repeat([]byte{0x11}, 16),
		useAES:     true,
		encVersion: 4,
	}
	r.xref[8] = xref{ptr: objptr{id: 8}, offset: int64(len("%PDF-1.7\n"))}

	v, err := r.GetObject(8)
	if err != nil || v.Err() != nil {
		t.Fatalf("GetObject: %v, %v", err, v.Err())
	}
	if got := v.Key("ID").Index(0).RawString(); got != string(mustHex(t, id)) {
		t.Errorf("ID = %x, want %s", got, id)
	}
	if got, _ := io.ReadAll(v.Reader()); string(got) != "\x01\x00\x0f\x00" {
		t.Errorf("stream data = %x, want 01000f00", got)
	}
}

func TestReaderEncryptRoundTrip(t *testing.T) {
	aes128Key := bytes.Repeat([]byte{0x11}, 16)
	aes256Key := bytes.Repeat([]byte{0x22}, 32)
	rc4Key := bytes.Repeat([]byte{0x33}, 5)

	tests := []struct {
		name       string
		key        []byte
		useAES     bool
		encVersion int
	}{
		{"RC4 V2", rc4Key, false, 2},
		{"AES-128 V4", aes128Key, true, 4},
		{"AES-256 V5", aes256Key, true, 5},
	}

	ptr := NewPtr(12, 0)
	inputs := [][]byte{
		{},
		[]byte("Signature 1"),
		[]byte("exactly16bytes!!"),
		{0xFE, 0xFF, 0x06, 0x28, 0x06, 0x29, 0x00, 0x5C},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &Reader{key: tt.key, useAES: tt.useAES, encVersion: tt.encVersion}
			if !r.IsEncrypted() {
				t.Fatal("IsEncrypted() = false, want true")
			}
			for _, in := range inputs {
				enc, err := r.Encrypt(ptr, in)
				if err != nil {
					t.Fatalf("Encrypt(%q): %v", in, err)
				}
				if tt.useAES {
					if len(enc)%aes.BlockSize != 0 || len(enc) < 2*aes.BlockSize {
						t.Fatalf("Encrypt(%q): AES output length %d, want IV plus padded blocks", in, len(enc))
					}
				}
				if len(in) > 0 && bytes.Contains(enc, in) {
					t.Errorf("Encrypt(%q): output contains the plaintext", in)
				}
				if dec := decryptString(tt.key, tt.useAES, tt.encVersion, objptr{12, 0}, string(enc)); dec != string(in) {
					t.Errorf("round trip: got %q, want %q", dec, in)
				}
			}
		})
	}
}

// TestRC4ShortKeyQpdf uses the /Title string of a document encrypted by qpdf 12.4 with 40-bit RC4.
func TestRC4ShortKeyQpdf(t *testing.T) {
	r := &Reader{key: mustHex(t, "ae3a3ff2a0"), encVersion: 1}
	ptr := objptr{id: 2, gen: 0}
	plain := "Signature 1"
	cipher := string(mustHex(t, "933bef0d8834d672f32189"))

	if got := decryptString(r.key, false, r.encVersion, ptr, cipher); got != plain {
		t.Errorf("decryptString = %q, want %q", got, plain)
	}
	enc, err := r.Encrypt(NewPtr(2, 0), []byte(plain))
	if err != nil {
		t.Fatal(err)
	}
	if string(enc) != cipher {
		t.Errorf("Encrypt = %x, want %x", enc, cipher)
	}
}

func TestReaderEncryptUsesObjectKey(t *testing.T) {
	r := &Reader{key: bytes.Repeat([]byte{0x11}, 16), useAES: true, encVersion: 4}
	enc, err := r.Encrypt(NewPtr(7, 0), []byte("hello"))
	if err != nil {
		t.Fatal(err)
	}
	dec := decryptString(r.key, true, 4, objptr{8, 0}, string(enc))
	if dec == "hello" {
		t.Error("V4 encryption does not depend on the object number")
	}
}

func TestReaderEncryptUnencrypted(t *testing.T) {
	r := &Reader{}
	if r.IsEncrypted() || r.EncryptsMetadata() {
		t.Fatal("IsEncrypted() or EncryptsMetadata() = true for a reader without a key")
	}
	if _, err := r.Encrypt(NewPtr(1, 0), []byte("x")); err == nil {
		t.Error("Encrypt on an unencrypted document: want error, got nil")
	}
}

func readEncryptedObject(t *testing.T, r *Reader, src string) Object {
	t.Helper()
	b := newBuffer(bytes.NewReader([]byte(src)), 0, r.encVersion)
	b.key = r.key
	b.useAES = r.useAES
	return b.readObject()
}

func TestSignatureContentsNotDecrypted(t *testing.T) {
	r := &Reader{key: bytes.Repeat([]byte{0x22}, 32), useAES: true, encVersion: 5}
	enc := func(s string) string {
		out, err := r.Encrypt(NewPtr(9, 0), []byte(s))
		if err != nil {
			t.Fatal(err)
		}
		return hex.EncodeToString(out)
	}
	contents := "3082ABCD0000"

	tests := []struct {
		name         string
		src          string
		wantContents string
	}{
		{
			name:         "signature dictionary",
			src:          "9 0 obj\n<< /Type /Sig /Filter /Adobe.PPKLite /ByteRange [0 10 20 30] /Contents <" + contents + "> /Name <" + enc("John") + "> >>\nendobj\n",
			wantContents: string(mustHex(t, contents)),
		},
		{
			name:         "signature dictionary without Type",
			src:          "9 0 obj\n<< /Filter /Adobe.PPKLite /ByteRange [0 10 20 30] /Contents <" + contents + "> /Name <" + enc("John") + "> >>\nendobj\n",
			wantContents: string(mustHex(t, contents)),
		},
		{
			name:         "document timestamp dictionary",
			src:          "9 0 obj\n<< /Type /DocTimeStamp /ByteRange [0 10 20 30] /Contents <" + contents + "> /Name <" + enc("John") + "> >>\nendobj\n",
			wantContents: string(mustHex(t, contents)),
		},
		{
			name:         "annotation Contents is still decrypted",
			src:          "9 0 obj\n<< /Type /Annot /Contents <" + enc("note") + "> /Name <" + enc("John") + "> >>\nendobj\n",
			wantContents: "note",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			obj := readEncryptedObject(t, r, tt.src)
			if got := obj.DictVal["Contents"].StringVal; got != tt.wantContents {
				t.Errorf("Contents = %x, want %x", got, tt.wantContents)
			}
			if got := obj.DictVal["Name"].StringVal; got != "John" {
				t.Errorf("Name = %q, want %q", got, "John")
			}
		})
	}
}

func TestNestedContentsDecrypted(t *testing.T) {
	r := &Reader{key: bytes.Repeat([]byte{0x22}, 32), useAES: true, encVersion: 5}
	enc := func(s string) string {
		out, err := r.Encrypt(NewPtr(9, 0), []byte(s))
		if err != nil {
			t.Fatal(err)
		}
		return hex.EncodeToString(out)
	}

	tests := []struct {
		name string
		src  string
		get  func(contents Object) Object
	}{
		{
			name: "array",
			src:  "9 0 obj\n<< /Contents [<" + enc("other") + "> <" + enc("note") + ">] >>\nendobj\n",
			get:  func(contents Object) Object { return contents.ArrayVal[1] },
		},
		{
			name: "dictionary",
			src:  "9 0 obj\n<< /Contents << /Text <" + enc("note") + "> >> /Type /Sig /ByteRange [0 10 20 30] >>\nendobj\n",
			get:  func(contents Object) Object { return contents.DictVal["Text"] },
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			obj := readEncryptedObject(t, r, tt.src)
			if got := tt.get(obj.DictVal["Contents"]).StringVal; got != "note" {
				t.Errorf("string in Contents = %q, want %q", got, "note")
			}
		})
	}
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func encryptedReader(t *testing.T, encrypt map[string]Object, id string) *Reader {
	t.Helper()
	idString := Object{Kind: String, StringVal: string(mustHex(t, id))}
	return &Reader{trailer: Object{Kind: Dict, DictVal: map[string]Object{
		"Encrypt": {Kind: Dict, DictVal: encrypt},
		"ID":      {Kind: Array, ArrayVal: []Object{idString, idString}},
	}}}
}

// v4Encrypt returns an AES-128 encryption dictionary as written by qpdf or pdfcpu.
func v4Encrypt(t *testing.T, p, cfLength int64, o, u string) map[string]Object {
	t.Helper()
	return map[string]Object{
		"Filter": {Kind: Name, NameVal: "Standard"},
		"V":      {Kind: Integer, Int64Val: 4},
		"R":      {Kind: Integer, Int64Val: 4},
		"Length": {Kind: Integer, Int64Val: 128},
		"P":      {Kind: Integer, Int64Val: p},
		"O":      {Kind: String, StringVal: string(mustHex(t, o))},
		"U":      {Kind: String, StringVal: string(mustHex(t, u))},
		"CF": {Kind: Dict, DictVal: map[string]Object{
			"StdCF": {Kind: Dict, DictVal: map[string]Object{
				"AuthEvent": {Kind: Name, NameVal: "DocOpen"},
				"CFM":       {Kind: Name, NameVal: "AESV2"},
				"Length":    {Kind: Integer, Int64Val: cfLength},
			}},
		}},
		"StmF": {Kind: Name, NameVal: "StdCF"},
		"StrF": {Kind: Name, NameVal: "StdCF"},
	}
}

// v5Encrypt returns an AES-256 encryption dictionary as written by qpdf.
func v5Encrypt(t *testing.T, r int64, o, u, oe, ue string) map[string]Object {
	t.Helper()
	return map[string]Object{
		"Filter": {Kind: Name, NameVal: "Standard"},
		"V":      {Kind: Integer, Int64Val: 5},
		"R":      {Kind: Integer, Int64Val: r},
		"Length": {Kind: Integer, Int64Val: 256},
		"P":      {Kind: Integer, Int64Val: -4},
		"O":      {Kind: String, StringVal: string(mustHex(t, o))},
		"U":      {Kind: String, StringVal: string(mustHex(t, u))},
		"OE":     {Kind: String, StringVal: string(mustHex(t, oe))},
		"UE":     {Kind: String, StringVal: string(mustHex(t, ue))},
		"CF": {Kind: Dict, DictVal: map[string]Object{
			"StdCF": {Kind: Dict, DictVal: map[string]Object{
				"AuthEvent": {Kind: Name, NameVal: "DocOpen"},
				"CFM":       {Kind: Name, NameVal: "AESV3"},
				"Length":    {Kind: Integer, Int64Val: 32},
			}},
		}},
		"StmF": {Kind: Name, NameVal: "StdCF"},
		"StrF": {Kind: Name, NameVal: "StdCF"},
	}
}

// TestGetObjectDecryptsStrings uses the /Info dictionaries of documents
// encrypted by qpdf 12.4 with user password "userpw", whose Title is
// "Signature 1". qpdf uses V=4 with the V2 method for RC4 and --cleartext-metadata.
func TestGetObjectDecryptsStrings(t *testing.T) {
	const qpdfID = "31415926535897932384626433832795"
	rc4 := v4Encrypt(t, -4, 16, "07c02079e0d8d0c3404477e977b56ef1720b2f6be2a464225fb7e72ffc05cc7f",
		"f28817bad2ec0570e790aba88ff407740021446990b9e4114071a4d9104984c1")
	rc4["CF"].DictVal["StdCF"].DictVal["CFM"] = Object{Kind: Name, NameVal: "V2"}
	rc4["EncryptMetadata"] = Object{Kind: Bool, BoolVal: false}

	tests := []struct {
		name    string
		encrypt map[string]Object
		title   string
	}{
		{"RC4 V4", rc4, "ef4033ba0e6ad0dab0b6c3"},
		{"AES-128", v4Encrypt(t, -4, 16, "07c02079e0d8d0c3404477e977b56ef1720b2f6be2a464225fb7e72ffc05cc7f",
			"3eadea12150bd88e74ec04a486eabc780021446990b9e4114071a4d9104984c1"),
			"5cd9dbb47ff2a3a32e1c5839a3a76899dbd33e662410c2344e7e56e263243210"},
		{"AES-256", v5Encrypt(t, 6,
			"f7131d65852c547493a020743e99c2b03f604ed0ee694cdea35168373176555ab5f7e46d5e4a968b27ba510952606789",
			"8ed39e3692831bf8971f6907cd1fae4ac544f7f1292b0c109e0c6c1f3f40bca3fcb4ff932fa9aff1003e2e89927e02de",
			"4a06f5d875f1085b61113cf875f9913b4ef41dd24ed5d1918c051a625ee24604",
			"e31212ee32d4529fd325fec3b71ce67157a0ba690f6fa0a1bbaedb636f72c4d1"),
			"3db932fe1ac419d88a380c41e52014ca392cd8580b7719e4887bfa2fb1f6dae8"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := encryptedReader(t, tt.encrypt, qpdfID)
			if err := r.initEncrypt("userpw"); err != nil {
				t.Fatalf("initEncrypt: %v", err)
			}
			setObjects(r, "null", "<< /Title <"+tt.title+"> >>")
			v, err := r.GetObject(2)
			if err != nil {
				t.Fatal(err)
			}
			if got := v.Key("Title").RawString(); got != "Signature 1" {
				t.Errorf("Title = %q, want %q", got, "Signature 1")
			}
		})
	}
}

// TestInitEncryptPdfcpu uses the dictionary of a document encrypted by pdfcpu 0.15
// with AES-128, user password "userpw" and owner password "ownerpw".
func TestInitEncryptPdfcpu(t *testing.T) {
	encrypt := v4Encrypt(t, -1849, 128,
		"07c02079e0d8d0c3404477e977b56ef1720b2f6be2a464225fb7e72ffc05cc7f",
		"0913852372888068a8e5d6342e70fb1e00000000000000000000000000000000")
	for _, pw := range []string{"userpw", "ownerpw"} {
		t.Run(pw, func(t *testing.T) {
			r := encryptedReader(t, encrypt, "31415926535897932384626433832795")
			if err := r.initEncrypt(pw); err != nil {
				t.Fatalf("initEncrypt: %v", err)
			}
			if got := hex.EncodeToString(r.key); got != "f35c45c84ceebd98dc32f4bace840215" {
				t.Errorf("file key = %s, want f35c45c84ceebd98dc32f4bace840215", got)
			}
		})
	}
}

// TestInitEncryptNonASCIIPassword uses documents encrypted with user password
// "pässwörd" and owner password "öwner" by qpdf 12.4, which stores passwords in
// PDFDocEncoding, and by pdfcpu 0.15, which stores them in UTF-8.
func TestInitEncryptNonASCIIPassword(t *testing.T) {
	tests := []struct {
		name    string
		encrypt map[string]Object
		key     string
	}{
		{
			name: "qpdf",
			encrypt: v4Encrypt(t, -4, 16,
				"098f8b7084aa57ff45bb49f89099906ead78c543b62c5f3f5ba5038a89b5c8bb",
				"0d9a2d92f01c926c31861285d6bc273d0021446990b9e4114071a4d9104984c1"),
			key: "7963e451fbf1b558b5bef9448e8a7f39",
		},
		{
			name: "pdfcpu",
			encrypt: v4Encrypt(t, -1849, 128,
				"62023f079055e5898d709728bbf2a4306831cc7ebbdebe254f008cbc6f7c2c9b",
				"fa91d7b073315a249dac95236c91dd0200000000000000000000000000000000"),
			key: "a2d004a8f8ab9d45e620cb181dd9a34d",
		},
	}
	for _, tt := range tests {
		for _, pw := range []string{"pässwörd", "öwner"} {
			t.Run(tt.name+"/"+pw, func(t *testing.T) {
				r := encryptedReader(t, tt.encrypt, "31415926535897932384626433832795")
				if err := r.initEncrypt(pw); err != nil {
					t.Fatalf("initEncrypt: %v", err)
				}
				if got := hex.EncodeToString(r.key); got != tt.key {
					t.Errorf("file key = %s, want %s", got, tt.key)
				}
			})
		}
	}
}

// TestInitEncryptEmptyOwnerPassword uses documents with user password "userpw"
// and an empty owner password that qpdf 12.4 accepts: R6 written by qpdf with
// --allow-insecure, R3 computed separately because writers replace an empty
// owner password with the user password.
func TestInitEncryptEmptyOwnerPassword(t *testing.T) {
	const id = "0123456789abcdef0123456789abcdef"
	tests := []struct {
		name    string
		encrypt map[string]Object
		key     string
	}{
		{
			name: "R3",
			encrypt: map[string]Object{
				"Filter": {Kind: Name, NameVal: "Standard"},
				"V":      {Kind: Integer, Int64Val: 2},
				"R":      {Kind: Integer, Int64Val: 3},
				"Length": {Kind: Integer, Int64Val: 128},
				"P":      {Kind: Integer, Int64Val: -4},
				"O":      {Kind: String, StringVal: string(mustHex(t, "6b8930ffa3779982374e920f5d5d0352c48bca7361549bfd47299a27818f11ed"))},
				"U":      {Kind: String, StringVal: string(mustHex(t, "1be53d1c9a65d0df81920924cf52d20428bf4e5e4e758a4164004e56fffa0108"))},
			},
			key: "68be1b06a445fe451bc8ef02e9719378",
		},
		{
			name: "R6",
			encrypt: v5Encrypt(t, 6,
				"25a9ee6a237bc9f4ef4098a18aff7d31634fa1044835c6c289c11ddfc4f43f96a309583bd9049a9e4a7fa3cf20e0d6a8",
				"6460983ec0d44265b9049573b24f37e6c7ccd49345d2c1fb15bf75b1d9a2ae603688f74c6a5d95c332a1ccda5b69d09d",
				"68642dbe4169f56f80abcb7b9376627043e32a66af12c9156d927b33ea84aec0",
				"6e8b24fb291ca64856228f751a8b8607e1721d2dc5a74d9d67f4a3b53aa71300"),
			key: "274e63b07c8cd30be1aefdf8da6dc47c40d2edc95138a4d0e86533cebc9ee33c",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := encryptedReader(t, tt.encrypt, id).initEncrypt(""); err != ErrInvalidPassword {
				t.Errorf("initEncrypt with the empty owner password: got %v, want ErrInvalidPassword", err)
			}
			r := encryptedReader(t, tt.encrypt, id)
			if err := r.initEncrypt("userpw"); err != nil {
				t.Fatalf("initEncrypt with the user password: %v", err)
			}
			if got := hex.EncodeToString(r.key); got != tt.key {
				t.Errorf("file key = %s, want %s", got, tt.key)
			}
		})
	}
}

// TestInitEncryptV5 uses the encryption dictionaries and file keys of documents
// encrypted by qpdf 12.4 with user password "userpw" and owner password "ownerpw".
func TestInitEncryptV5(t *testing.T) {
	vectors := []struct {
		r            int64
		o, u, oe, ue string
		key          string
	}{
		{
			r:   5,
			o:   "07f15ffe1da1ac82f848ac48a1b659c1c70863ab9380d074ba0754566feaf8b589ef3966a79af18ff9e3c99347e9d082",
			u:   "17058ce2c42dd34ea6d20e08cad47fcbf3af2fa2084e58bc32282d58ef368198ad60c69b7d11bf319284e34a3c939fd2",
			oe:  "0226dd92be5514b38daa43f91ed347386c38186550aedf75f5f9649c725c1cb1",
			ue:  "8534e9c65154157c60ff24aeaae2f3067ba571b6e5b463293109e81cfcae7e53",
			key: "51aa22be60e08c27f4f6abe372da0a5cd1a0bd3b67411f9bc1f703cad09f2fd4",
		},
		{
			r:   6,
			o:   "e114a96599d7c356bb84d7d1a56004647def05293febfbb185f97392bc315b71b073a75480d46fe574bc456867b1d500",
			u:   "fe581cc952505cb9fec19f79da88ea6e57d032ee07418883b956b846a09a0e5c055411b9151e6c0d3ff3db5abcb1cba3",
			oe:  "33f75067d5500d527b29730253ffec8d91f304a7ef8ca148fa1f6d0c0aa75b86",
			ue:  "52a430954929217428efe203e3b7a04a8c7c67ca5ac818cc64417f376d5fb765",
			key: "f9ad866a0dc40412e65fa482beee77e0b7b461c9e82836575f70457a4585f627",
		},
	}

	const id = "00000000000000000000000000000000"
	for _, v := range vectors {
		encrypt := v5Encrypt(t, v.r, v.o, v.u, v.oe, v.ue)
		for _, pw := range []string{"userpw", "ownerpw"} {
			t.Run(fmt.Sprintf("R%d/%s", v.r, pw), func(t *testing.T) {
				r := encryptedReader(t, encrypt, id)
				if err := r.initEncrypt(pw); err != nil {
					t.Fatalf("initEncrypt: %v", err)
				}
				if got := hex.EncodeToString(r.key); got != v.key {
					t.Errorf("file key = %s, want %s", got, v.key)
				}
			})
		}
		t.Run(fmt.Sprintf("R%d/wrong password", v.r), func(t *testing.T) {
			if err := encryptedReader(t, encrypt, id).initEncrypt("wrong"); err != ErrInvalidPassword {
				t.Errorf("initEncrypt with a wrong password: got %v, want ErrInvalidPassword", err)
			}
		})

		variants := []struct {
			name      string
			modify    func(r *Reader, encrypt map[string]Object)
			supported bool
		}{
			// A writer bug that Acrobat, qpdf and pdf.js accept.
			{"AESV2 method", func(r *Reader, encrypt map[string]Object) {
				encrypt["CF"].DictVal["StdCF"].DictVal["CFM"] = Object{Kind: Name, NameVal: "AESV2"}
			}, true},
			{"length in bytes", func(r *Reader, encrypt map[string]Object) {
				encrypt["Length"] = Object{Kind: Integer, Int64Val: 32}
			}, true},
			// Longer values, which some scanners write, are used by their prefix.
			{"padded password entries", func(r *Reader, encrypt map[string]Object) {
				for key, size := range map[string]int{"O": 127, "U": 127, "OE": 48, "UE": 48} {
					pad := strings.Repeat("\x00", size-len(encrypt[key].StringVal))
					encrypt[key] = Object{Kind: String, StringVal: encrypt[key].StringVal + pad}
				}
			}, true},
			{"indirect crypt filters", func(r *Reader, encrypt map[string]Object) {
				setObjects(r, "<< /StdCF << /AuthEvent /DocOpen /CFM /AESV3 /Length 32 >> >>")
				encrypt["CF"] = Object{Kind: Indirect, PtrVal: objptr{id: 1}}
			}, true},
			// Strings and streams are not encrypted when only embedded files are.
			{"Identity filters", func(r *Reader, encrypt map[string]Object) {
				encrypt["StmF"] = Object{Kind: Name, NameVal: "Identity"}
				encrypt["StrF"] = Object{Kind: Name, NameVal: "Identity"}
				encrypt["EFF"] = Object{Kind: Name, NameVal: "StdCF"}
			}, false},
			{"Identity string filter", func(r *Reader, encrypt map[string]Object) {
				encrypt["StrF"] = Object{Kind: Name, NameVal: "Identity"}
			}, false},
			// The default method is None.
			{"no method", func(r *Reader, encrypt map[string]Object) {
				delete(encrypt["CF"].DictVal["StdCF"].DictVal, "CFM")
			}, false},
		}
		for _, u := range variants {
			for _, pw := range []string{"userpw", "ownerpw"} {
				t.Run(fmt.Sprintf("R%d/%s/%s", v.r, u.name, pw), func(t *testing.T) {
					encrypt := v5Encrypt(t, v.r, v.o, v.u, v.oe, v.ue)
					r := encryptedReader(t, encrypt, id)
					u.modify(r, encrypt)
					err := r.initEncrypt(pw)
					switch {
					case u.supported && err != nil:
						t.Errorf("initEncrypt: %v", err)
					case u.supported && hex.EncodeToString(r.key) != v.key:
						t.Errorf("file key = %x, want %s", r.key, v.key)
					case !u.supported && (err == nil || err == ErrInvalidPassword):
						t.Errorf("initEncrypt: got %v, want an unsupported PDF error", err)
					}
				})
			}
		}
	}
}

// TestInitEncryptLegacy uses the encryption dictionaries and file keys of
// documents encrypted by qpdf 12.4, or by PDFBox 3.0.8 where noted, with user
// password "userpw" and owner password "ownerpw". A zero length omits /Length
// from the dictionary.
func TestInitEncryptLegacy(t *testing.T) {
	const qpdfID = "31415926535897932384626433832795"
	vectors := []struct {
		name              string
		v, r, length      int64
		o, u, id          string
		key               string
		cleartextMetadata bool
	}{
		{
			name: "R2", v: 1, r: 2, length: 40, id: qpdfID,
			o:   "fd7d1bc157fcf76e079d3daf15981cc03686819d8ffd9ea5836d4fec05b4f0aa",
			u:   "822e53f6d8f7ae0fafc96202511f90efa14ed1c7f8bb0ba04cc28f60f52859b0",
			key: "92ec6cac2d",
		},
		{
			// PDFBox: encrypt -keyLength=40 uses R3, unlike qpdf.
			name: "R3-40-bit", v: 1, r: 3, length: 40, id: "0123456789abcdef0123456789abcdef",
			o:   "68dbca4666a2877bc572da0efdc5103d708a525de32c51996040a12d589ac0db",
			u:   "6fcee67fc2461d7920e1d2d2e6745e3c28bf4e5e4e758a4164004e56fffa0108",
			key: "f22af71140",
		},
		{
			name: "R3", v: 2, r: 3, length: 128, id: qpdfID,
			o:   "07c02079e0d8d0c3404477e977b56ef1720b2f6be2a464225fb7e72ffc05cc7f",
			u:   "3eadea12150bd88e74ec04a486eabc780021446990b9e4114071a4d9104984c1",
			key: "567053e9cfea0f89ae6fbdb37334a454",
		},
		{
			name: "R4", v: 4, r: 4, length: 128, id: qpdfID,
			o:   "07c02079e0d8d0c3404477e977b56ef1720b2f6be2a464225fb7e72ffc05cc7f",
			u:   "3eadea12150bd88e74ec04a486eabc780021446990b9e4114071a4d9104984c1",
			key: "567053e9cfea0f89ae6fbdb37334a454",
		},
		{
			name: "R4-no-length", v: 4, r: 4, length: 0, id: qpdfID,
			o:   "07c02079e0d8d0c3404477e977b56ef1720b2f6be2a464225fb7e72ffc05cc7f",
			u:   "3eadea12150bd88e74ec04a486eabc780021446990b9e4114071a4d9104984c1",
			key: "567053e9cfea0f89ae6fbdb37334a454",
		},
		// Revision 2 and AESV2 do not use /Length; qpdf ignores a wrong value.
		{
			name: "R2-length-256", v: 1, r: 2, length: 256, id: qpdfID,
			o:   "fd7d1bc157fcf76e079d3daf15981cc03686819d8ffd9ea5836d4fec05b4f0aa",
			u:   "822e53f6d8f7ae0fafc96202511f90efa14ed1c7f8bb0ba04cc28f60f52859b0",
			key: "92ec6cac2d",
		},
		{
			name: "R4-length-256", v: 4, r: 4, length: 256, id: qpdfID,
			o:   "07c02079e0d8d0c3404477e977b56ef1720b2f6be2a464225fb7e72ffc05cc7f",
			u:   "3eadea12150bd88e74ec04a486eabc780021446990b9e4114071a4d9104984c1",
			key: "567053e9cfea0f89ae6fbdb37334a454",
		},
		{
			name: "R4-length-in-bytes", v: 4, r: 4, length: 16, id: qpdfID,
			o:   "07c02079e0d8d0c3404477e977b56ef1720b2f6be2a464225fb7e72ffc05cc7f",
			u:   "3eadea12150bd88e74ec04a486eabc780021446990b9e4114071a4d9104984c1",
			key: "567053e9cfea0f89ae6fbdb37334a454",
		},
		{
			// qpdf --cleartext-metadata
			name: "R4-cleartext-metadata", v: 4, r: 4, length: 128, id: qpdfID, cleartextMetadata: true,
			o:   "07c02079e0d8d0c3404477e977b56ef1720b2f6be2a464225fb7e72ffc05cc7f",
			u:   "f28817bad2ec0570e790aba88ff407740021446990b9e4114071a4d9104984c1",
			key: "16e6d20be3a1099040705481cc9caa68",
		},
	}

	for _, v := range vectors {
		encrypt := map[string]Object{
			"Filter": {Kind: Name, NameVal: "Standard"},
			"V":      {Kind: Integer, Int64Val: v.v},
			"R":      {Kind: Integer, Int64Val: v.r},
			"Length": {Kind: Integer, Int64Val: v.length},
			"P":      {Kind: Integer, Int64Val: -4},
			"O":      {Kind: String, StringVal: string(mustHex(t, v.o))},
			"U":      {Kind: String, StringVal: string(mustHex(t, v.u))},
		}
		if v.length == 0 {
			delete(encrypt, "Length")
		}
		if v.cleartextMetadata {
			encrypt["EncryptMetadata"] = Object{Kind: Bool, BoolVal: false}
		}
		if v.v == 4 {
			encrypt["StmF"] = Object{Kind: Name, NameVal: "StdCF"}
			encrypt["StrF"] = Object{Kind: Name, NameVal: "StdCF"}
			encrypt["CF"] = Object{Kind: Dict, DictVal: map[string]Object{
				"StdCF": {Kind: Dict, DictVal: map[string]Object{
					"AuthEvent": {Kind: Name, NameVal: "DocOpen"},
					"CFM":       {Kind: Name, NameVal: "AESV2"},
					"Length":    {Kind: Integer, Int64Val: 16},
				}},
			}}
		}
		for _, pw := range []string{"userpw", "ownerpw"} {
			t.Run(v.name+"/"+pw, func(t *testing.T) {
				r := encryptedReader(t, encrypt, v.id)
				if err := r.initEncrypt(pw); err != nil {
					t.Fatalf("initEncrypt: %v", err)
				}
				if got := hex.EncodeToString(r.key); got != v.key {
					t.Errorf("file key = %s, want %s", got, v.key)
				}
			})
		}
		t.Run(v.name+"/wrong password", func(t *testing.T) {
			if err := encryptedReader(t, encrypt, v.id).initEncrypt("wrong"); err != ErrInvalidPassword {
				t.Errorf("initEncrypt with a wrong password: got %v, want ErrInvalidPassword", err)
			}
		})
	}
}

// TestInitEncryptV4R2 uses the qpdf R4 dictionary with revision 2 and a U
// computed separately for a 128-bit key, which qpdf 12.4 accepts for V=4.
func TestInitEncryptV4R2(t *testing.T) {
	encrypt := v4Encrypt(t, -4, 16, "07c02079e0d8d0c3404477e977b56ef1720b2f6be2a464225fb7e72ffc05cc7f",
		"ff65aca8de2306a183036b2f327e3c131181a5b5ff9c1ffaf7bf981c2835e474")
	encrypt["R"] = Object{Kind: Integer, Int64Val: 2}
	r := encryptedReader(t, encrypt, "31415926535897932384626433832795")
	if err := r.initEncrypt("userpw"); err != nil {
		t.Fatalf("initEncrypt: %v", err)
	}
	if got := hex.EncodeToString(r.key); got != "5564120f9a88f020d6ec5413adae1100" {
		t.Errorf("file key = %s, want 5564120f9a88f020d6ec5413adae1100", got)
	}
}

func TestInitEncryptKeyTooLong(t *testing.T) {
	encrypt := map[string]Object{
		"Filter": {Kind: Name, NameVal: "Standard"},
		"V":      {Kind: Integer, Int64Val: 2},
		"R":      {Kind: Integer, Int64Val: 3},
		"Length": {Kind: Integer, Int64Val: 256},
		"P":      {Kind: Integer, Int64Val: -4},
		"O":      {Kind: String, StringVal: string(mustHex(t, "07c02079e0d8d0c3404477e977b56ef1720b2f6be2a464225fb7e72ffc05cc7f"))},
		"U":      {Kind: String, StringVal: string(mustHex(t, "3eadea12150bd88e74ec04a486eabc780021446990b9e4114071a4d9104984c1"))},
	}
	err := encryptedReader(t, encrypt, "31415926535897932384626433832795").initEncrypt("userpw")
	if err == nil || err == ErrInvalidPassword {
		t.Errorf("initEncrypt with a 256-bit RC4 key: got %v, want a malformed PDF error", err)
	}
}

// TestDecryptAESStringWithoutCiphertext uses an annotation of a qpdf 12.4 AES-256
// document whose Contents is only a 16-byte IV, which qpdf reads as "".
func TestDecryptAESStringWithoutCiphertext(t *testing.T) {
	r := &Reader{key: mustHex(t, "5faddd3caabab9051e11efffc75f3f985d7ae49ca59d92aa5dd941634e6b880c"), useAES: true, encVersion: 5}
	obj := readEncryptedObject(t, r, "4 0 obj\n<< /Contents <00112233445566778899aabbccddeeff> "+
		"/NM <6c3392ae357456d13d3ce3e04744c5eca25b27dc8d5be5e16eb4e1b92c692b36> "+
		"/T <990cd2b7c6a931d57865be6e4ed3f8366b86559ba063aae52a85772e0f6cfef2> /Type /Annot >>\nendobj\n")
	for key, want := range map[string]string{"Contents": "", "NM": "NameMarkerQQ", "T": "MarkerTitleABC"} {
		if got := obj.DictVal[key].StringVal; got != want {
			t.Errorf("%s = %q, want %q", key, got, want)
		}
	}
}
