package tripwire

import (
	"archive/zip"
	"bytes"
	"crypto/rand"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
)

// Planted is one decoy written by PlantCanaries.
type Planted struct {
	Path   string
	SHA256 string
}

// Config is the line to add to tripwire_canaries for this decoy.
func (p Planted) Config() string { return p.Path + "@sha256:" + p.SHA256 }

// PlantCanaries writes four decoy files into dir (created if needed): a
// password list, an accounts spreadsheet export, a tax return and a contract.
// Each is a valid file of its type with invented contents that differ on
// every run. It refuses to overwrite anything.
func PlantCanaries(dir string) ([]Planted, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	files := []struct {
		name string
		make func() ([]byte, error)
	}{
		{"Passwords.txt", decoyPasswords},
		{"Bank accounts.csv", decoyAccounts},
		{"Tax return 2025.pdf", decoyPDF},
		{"Contract (signed).docx", decoyDocx},
	}
	var out []Planted
	for _, f := range files {
		data, err := f.make()
		if err != nil {
			return out, err
		}
		path := filepath.Join(dir, f.name)
		fh, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
		if err != nil {
			return out, fmt.Errorf("%s: %w", path, err)
		}
		if _, err := fh.Write(data); err != nil {
			fh.Close()
			return out, err
		}
		if err := fh.Chmod(0o644); err != nil {
			fh.Close()
			return out, err
		}
		if err := fh.Close(); err != nil {
			return out, err
		}
		sum, _, err := fileHash(path)
		if err != nil {
			return out, err
		}
		out = append(out, Planted{Path: path, SHA256: sum})
	}
	return out, nil
}

const alnum = "abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"

func token(n int) string {
	var b strings.Builder
	for i := 0; i < n; i++ {
		k, _ := rand.Int(rand.Reader, big.NewInt(int64(len(alnum))))
		b.WriteByte(alnum[k.Int64()])
	}
	return b.String()
}

func digits(n int) string {
	var b strings.Builder
	for i := 0; i < n; i++ {
		k, _ := rand.Int(rand.Reader, big.NewInt(10))
		b.WriteByte(byte('0' + k.Int64()))
	}
	return b.String()
}

var services = []string{"Email", "Bank (checking)", "Bank (savings)", "Brokerage", "Payroll portal",
	"Health insurance", "Utilities", "Mobile carrier", "Cloud storage", "Router admin", "Tax software", "Retirement 401k"}

func decoyPasswords() ([]byte, error) {
	var b strings.Builder
	b.WriteString("PASSWORDS - keep private\n\n")
	for _, s := range services {
		fmt.Fprintf(&b, "%-18s user: %s  pass: %s\n", s, strings.ToLower(token(7)), token(14))
	}
	b.WriteString("\nWifi (home): " + token(16) + "\n")
	return []byte(b.String()), nil
}

func decoyAccounts() ([]byte, error) {
	var b strings.Builder
	b.WriteString("Institution,Account type,Routing,Account number,Online login,Online password\n")
	for _, s := range []string{"First National", "Credit Union", "Online Savings", "Brokerage"} {
		fmt.Fprintf(&b, "%s,%s,%s,%s,%s,%s\n", s, "Checking", digits(9), digits(12), strings.ToLower(token(8)), token(12))
	}
	return []byte(b.String()), nil
}

func decoyPDF() ([]byte, error) {
	text := fmt.Sprintf("Form 1040 (2025) - Return %s - Refund due: $%s.%s", digits(8), digits(4), digits(2))
	content := fmt.Sprintf("BT /F1 12 Tf 72 720 Td (%s) Tj ET", text)
	objs := []string{
		"<< /Type /Catalog /Pages 2 0 R >>",
		"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
		"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>",
		fmt.Sprintf("<< /Length %d >>\nstream\n%s\nendstream", len(content), content),
		"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
	}
	var b bytes.Buffer
	b.WriteString("%PDF-1.4\n")
	offsets := make([]int, len(objs))
	for i, o := range objs {
		offsets[i] = b.Len()
		fmt.Fprintf(&b, "%d 0 obj\n%s\nendobj\n", i+1, o)
	}
	xref := b.Len()
	fmt.Fprintf(&b, "xref\n0 %d\n0000000000 65535 f \n", len(objs)+1)
	for _, off := range offsets {
		fmt.Fprintf(&b, "%010d 00000 n \n", off)
	}
	fmt.Fprintf(&b, "trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n", len(objs)+1, xref)
	return b.Bytes(), nil
}

func decoyDocx() ([]byte, error) {
	var b bytes.Buffer
	z := zip.NewWriter(&b)
	parts := []struct{ name, body string }{
		{"[Content_Types].xml", `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/></Types>`},
		{"_rels/.rels", `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/></Relationships>`},
		{"word/document.xml", fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8" standalone="yes"?><w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body><w:p><w:r><w:t>Service agreement no. %s. Signed copy. Payment account %s.</w:t></w:r></w:p></w:body></w:document>`, digits(6), digits(12))},
	}
	for _, p := range parts {
		w, err := z.Create(p.name)
		if err != nil {
			return nil, err
		}
		if _, err := w.Write([]byte(p.body)); err != nil {
			return nil, err
		}
	}
	if err := z.Close(); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}
