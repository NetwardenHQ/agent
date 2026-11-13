package tripwire

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func randomBytes(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}

func TestSuspicious(t *testing.T) {
	jpeg := append([]byte{0xFF, 0xD8, 0xFF, 0xE0}, bytes.Repeat([]byte{1}, 60)...)
	zip := append([]byte("PK\x03\x04"), bytes.Repeat([]byte{2}, 60)...)
	text := bytes.Repeat([]byte("Quarterly numbers, as agreed on the call.\n"), 100)
	enc := randomBytes(t, 4096)
	for _, c := range []struct {
		name string
		head []byte
		want string
	}{
		{"IMG_0001.jpg", jpeg, ""},
		{"IMG_0001.jpg", enc, "content does not match .jpg"},
		{"Report.docx", zip, ""},
		{"Report.docx", enc, "content does not match .docx"},
		{"notes.md", text, ""},
		{"notes.md", enc, "text file looks encrypted"},
		{"tiny.txt", []byte("hi"), ""},
		{"Report.docx.lockbit", enc, "ransomware extension .lockbit"},
		{"budget.xlsx.encrypted", enc, "ransomware extension .encrypted"},
		{"HOW_TO_DECRYPT.txt", []byte("pay us"), "ransom note name"},
		{"_readme.txt", []byte("pay us"), "ransom note name"},
		{"README.txt", []byte("plain readme"), ""},
		// Compressed formats look random by nature: not judged on entropy.
		{"archive.7z", enc, ""},
		{"movie.mp4", append(append([]byte{0, 0, 0, 0x20}, "ftypisom"...), bytes.Repeat([]byte{3}, 60)...), ""},
		{"movie.mp4", enc, "content does not match .mp4"},
		// A PDF may carry bytes before its header.
		{"scan.pdf", append([]byte("\n\n%PDF-1.7\n"), bytes.Repeat([]byte{4}, 60)...), ""},
		{"scan.pdf", enc, "content does not match .pdf"},
	} {
		if got := suspicious(c.name, c.head); got != c.want {
			t.Errorf("%s: got %q, want %q", c.name, got, c.want)
		}
	}
}

func TestEntropy(t *testing.T) {
	if e := entropy(bytes.Repeat([]byte("a"), 1000)); e != 0 {
		t.Errorf("one byte value: %v", e)
	}
	if e := entropy(randomBytes(t, 4096)); e < 7.8 {
		t.Errorf("random: %v", e)
	}
}

// Files a NAS share is full of that are not what their name says.
func TestHousekeepingFilesAreNotSuspicious(t *testing.T) {
	junk := []byte("\x00\x05\x16\x07\x00\x02\x00\x00Mac OS X        resource fork data")
	for _, name := range []string{"._IMG_0001.jpg", "~$Report.docx", ".~lock.Budget.ods#", "Thumbs.db", ".DS_Store"} {
		if got := suspicious(name, junk); got != "" {
			t.Errorf("%s flagged: %s", name, got)
		}
	}
}

func TestRansomNamesNeedTheirShape(t *testing.T) {
	enc := randomBytes(t, 64)
	for name, want := range map[string]string{
		"ransomware-report.pdf":    "content does not match .pdf",
		"decrypt.py":               "",
		"HOW_TO_DECRYPT.html":      "ransom note name",
		"restore_files.hta":        "ransom note name",
		"game.hive":                "",
		"Report.docx.hive":         "ransomware extension .hive",
		"photo.jpg.Abc123.lockbit": "ransomware extension .lockbit",
	} {
		if got := suspicious(name, enc); got != want {
			t.Errorf("%s: got %q, want %q", name, got, want)
		}
	}
}
