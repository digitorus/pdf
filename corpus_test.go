package pdf

import (
	"archive/zip"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var (
	corpusPath     = flag.String("corpus", "", "path to local PDF corpus directory")
	downloadCorpus = flag.Bool("download-corpus", false, "download PDF Association corpora for testing")
)

// CorpusSource defines a downloadable PDF corpus
type CorpusSource struct {
	Name      string   // Human-readable name
	URL       string   // Download URL (GitHub archive)
	SubPath   string   // Subdirectory within archive containing PDFs
	KnownGood bool     // If true, all files must parse successfully
	Malicious bool     // If true, files may be malicious - extra caution
	SkipFiles []string // File patterns to skip
}

// Known PDF Association and community corpora
var corpora = []CorpusSource{
	{
		Name:      "veraPDF-corpus",
		URL:       "https://github.com/veraPDF/veraPDF-corpus/archive/refs/heads/master.zip",
		SubPath:   "veraPDF-corpus-master",
		KnownGood: false, // Contains intentionally malformed files to test validators
	},
	{
		Name:      "bfo-pdfa-testsuite",
		URL:       "https://github.com/bfosupport/pdfa-testsuite/archive/refs/heads/master.zip",
		SubPath:   "pdfa-testsuite-master",
		KnownGood: false, // Contains both pass and fail test cases
	},
	{
		Name:      "pdf-cabinet-of-horrors",
		URL:       "https://github.com/openpreserve/format-corpus/archive/refs/heads/master.zip",
		SubPath:   "format-corpus-master/pdfCabinetOfHorrors",
		KnownGood: false, // Intentionally problematic files
	},
}

func TestCorpus(t *testing.T) {
	path := *corpusPath
	if path == "" {
		t.Skip("skipping corpus test: use -corpus flag to specify path, or -download-corpus for remote corpora")
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Skipf("skipping corpus test: %v", err)
	}

	var files []string
	if info.IsDir() {
		filepath.Walk(path, func(p string, info os.FileInfo, err error) error {
			if err == nil && !info.IsDir() && filepath.Ext(p) == ".pdf" {
				files = append(files, p)
			}
			return nil
		})
	} else {
		files = append(files, path)
	}

	if len(files) == 0 {
		t.Skip("no PDF files found in corpus path")
	}

	t.Logf("Running corpus test on %d files in %s", len(files), path)

	for _, f := range files {
		t.Run(filepath.Base(f), func(t *testing.T) {
			// Local test files may include intentional failure cases
			// The key requirement is: no panics on any input
			testPDFFile(t, f, false)
		})
	}
}

// TestPDFAssociationCorpora downloads and tests PDF Association corpora
// PDFs are parsed directly from the zip archive without extraction to disk.
// Run with: go test -v -download-corpus -timeout 30m
func TestPDFAssociationCorpora(t *testing.T) {
	if !*downloadCorpus {
		t.Skip("skipping corpus download test (use -download-corpus to enable)")
	}

	cacheDir := os.Getenv("PDF_CORPUS_CACHE")
	if cacheDir == "" {
		var err error
		cacheDir, err = os.MkdirTemp("", "pdf-corpus-*")
		if err != nil {
			t.Fatalf("failed to create cache dir: %v", err)
		}
		defer os.RemoveAll(cacheDir)
	}

	for _, corpus := range corpora {
		t.Run(corpus.Name, func(t *testing.T) {
			zipPath := filepath.Join(cacheDir, corpus.Name+".zip")

			// Download if not cached
			if _, err := os.Stat(zipPath); os.IsNotExist(err) {
				if err := downloadFile(corpus.URL, zipPath); err != nil {
					t.Fatalf("failed to download corpus: %v", err)
				}
			}

			// Parse PDFs directly from zip archive
			testZipCorpus(t, zipPath, corpus.SubPath, corpus.KnownGood, corpus.SkipFiles)
		})
	}
}

// testZipCorpus tests PDFs directly from a zip archive without extraction
func testZipCorpus(t *testing.T, zipPath, subPath string, expectSuccess bool, skipFiles []string) {
	t.Helper()

	r, err := zip.OpenReader(zipPath)
	if err != nil {
		t.Fatalf("failed to open zip: %v", err)
	}
	defer r.Close()

	var pdfCount int
	for _, f := range r.File {
		// Check if file is in the desired subpath
		if subPath != "" && !strings.HasPrefix(f.Name, subPath) {
			continue
		}

		// Only process PDF files
		if f.FileInfo().IsDir() || strings.ToLower(filepath.Ext(f.Name)) != ".pdf" {
			continue
		}

		// Check skip patterns
		skip := false
		for _, pattern := range skipFiles {
			if strings.Contains(f.Name, pattern) {
				skip = true
				break
			}
		}
		if skip {
			continue
		}

		pdfCount++
		relName := strings.TrimPrefix(f.Name, subPath+"/")

		t.Run(relName, func(t *testing.T) {
			testZipPDFFile(t, f, expectSuccess)
		})
	}

	t.Logf("Tested %d PDF files from %s", pdfCount, filepath.Base(zipPath))
}

// safeCall executes fn and recovers from any panic, reporting it as a test error
func safeCall(t *testing.T, filename, operation string, fn func()) {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("SECURITY: panic in %s during %s: %v", filename, operation, r)
		}
	}()
	fn()
}

// testZipPDFFile tests a single PDF file from a zip archive with comprehensive checks
func testZipPDFFile(t *testing.T, zf *zip.File, expectSuccess bool) {
	t.Helper()

	// CRITICAL: Recover from any panic - we must NEVER panic on malformed input
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("SECURITY: panic on file %s: %v", zf.Name, r)
		}
	}()

	// Open the file from the zip archive
	rc, err := zf.Open()
	if err != nil {
		t.Fatalf("failed to open zip entry: %v", err)
	}
	defer rc.Close()

	// Read entire file into memory for ReaderAt interface
	data, err := io.ReadAll(rc)
	if err != nil {
		t.Fatalf("failed to read zip entry: %v", err)
	}

	ra := &bytesReaderAt{data: data}
	testPDFReaderAt(t, ra, int64(len(data)), zf.Name, expectSuccess)
}

// testPDFReaderAt performs comprehensive in-depth testing of a PDF
func testPDFReaderAt(t *testing.T, ra io.ReaderAt, size int64, name string, expectSuccess bool) {
	t.Helper()

	// Try to parse the PDF
	r, err := NewReader(ra, size)
	if err != nil {
		if expectSuccess {
			t.Errorf("expected successful parse but got: %v", err)
		}
		return
	}

	// === Basic Structure ===
	safeCall(t, name, "NumPage", func() { _ = r.NumPage() })
	safeCall(t, name, "Trailer", func() { _ = r.Trailer() })
	safeCall(t, name, "Outline", func() { _ = r.Outline() })

	// === All Pages (comprehensive) ===
	numPages := r.NumPage()
	for i := 1; i <= numPages; i++ {
		pageNum := i
		safeCall(t, name, fmt.Sprintf("Page(%d)", pageNum), func() {
			page := r.Page(pageNum)
			if page.V.Kind() == Null {
				return
			}

			// Resources and fonts
			_ = page.Resources()
			fonts := page.Fonts()
			for _, fontName := range fonts {
				font := page.Font(fontName)
				_ = font.BaseFont()
				_ = font.FirstChar()
				_ = font.LastChar()
				_ = font.Widths()
				_ = font.Encoder()
			}

			// Content extraction
			content := page.Content()
			_ = content.Text
			_ = content.Rect
		})
	}

	// === All Xref Objects ===
	xrefs := r.Xref()
	for _, x := range xrefs {
		ptr := x.Ptr()
		safeCall(t, name, fmt.Sprintf("GetObject(%d)", ptr.GetID()), func() {
			val, err := r.GetObject(ptr.GetID())
			if err != nil {
				return
			}
			// Exercise value accessors
			_ = val.Kind()
			_ = val.String()
			if val.Kind() == Dict {
				_ = val.Keys()
			}
			if val.Kind() == Array {
				for j := 0; j < val.Len(); j++ {
					_ = val.Index(j)
				}
			}
			if val.Kind() == Stream {
				// Try to read stream data
				rd := val.Reader()
				buf := make([]byte, 1024)
				rd.Read(buf)
				rd.Close()
			}
		})
	}
}

// testPDFFile tests a single PDF file from disk with comprehensive checks
func testPDFFile(t *testing.T, path string, expectSuccess bool) {
	t.Helper()

	// CRITICAL: Recover from any panic - we must NEVER panic on malformed input
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("SECURITY: panic on file %s: %v", path, r)
		}
	}()

	file, err := os.Open(path)
	if err != nil {
		t.Fatalf("failed to open file: %v", err)
	}
	defer file.Close()

	stat, err := file.Stat()
	if err != nil {
		t.Fatalf("failed to stat file: %v", err)
	}

	testPDFReaderAt(t, file, stat.Size(), path, expectSuccess)
}

// bytesReaderAt wraps a byte slice to implement io.ReaderAt
type bytesReaderAt struct {
	data []byte
}

func (b *bytesReaderAt) ReadAt(p []byte, off int64) (n int, err error) {
	if off < 0 {
		return 0, fmt.Errorf("negative offset")
	}
	if off >= int64(len(b.data)) {
		return 0, io.EOF
	}
	n = copy(p, b.data[off:])
	if n < len(p) {
		err = io.EOF
	}
	return
}

func downloadFile(url, destPath string) error {
	resp, err := http.Get(url)
	if err != nil {
		return fmt.Errorf("download failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download failed with status: %s", resp.Status)
	}

	// Ensure directory exists
	if err := os.MkdirAll(filepath.Dir(destPath), 0755); err != nil {
		return fmt.Errorf("failed to create cache directory: %w", err)
	}

	out, err := os.Create(destPath)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, resp.Body)
	return err
}
