package tripwire

import (
	"bytes"
	"math"
	"path/filepath"
	"strings"
)

// headBytes is how much of a changed file is read to judge it.
const headBytes = 4096

// ransomExtensions are extensions ransomware families append to the files
// they encrypt. Generic ones that real programs also use (.enc, .key) are
// left out: a false alarm here pages someone.
var ransomExtensions = map[string]bool{
	".locked": true, ".encrypted": true, ".crypt": true, ".crypted": true, ".cry": true,
	".lockbit": true, ".lockbit3": true, ".ryk": true, ".conti": true, ".akira": true,
	".basta": true, ".blacksuit": true, ".royal": true, ".clop": true, ".cl0p": true,
	".phobos": true, ".eking": true, ".wncry": true, ".wnry": true, ".wncryt": true,
	".cerber": true, ".locky": true, ".zepto": true, ".odin": true, ".thor": true,
	".aesir": true, ".zzzzz": true, ".micro": true, ".vvv": true, ".ecc": true,
	".ezz": true, ".exx": true, ".crab": true, ".krab": true, ".gdcb": true,
	".medusa": true, ".rhysida": true, ".8base": true, ".hive": true, ".darkness": true,
	".rapid": true, ".kraken": true,
}

// ransomNoteWords mark a file name as a ransom note.
var ransomNoteWords = []string{
	"decrypt", "ransom", "files_are_encrypted", "files-are-encrypted", "restore_my_files",
	"restore-my-files", "restore_files", "recover_files", "recovery_instructions",
}

// ransomNoteNames are exact names notes use that carry none of those words.
var ransomNoteNames = map[string]bool{"_readme.txt": true, "!!!readme!!!.txt": true}

// noteExtensions are what ransom notes are written as. A "decrypt.py" or a
// "ransomware-report.pdf" is somebody's work, not a note.
var noteExtensions = map[string]bool{"": true, ".txt": true, ".html": true, ".htm": true, ".hta": true, ".rtf": true, ".url": true}

// notJudged reports files that are not what their name says and never were:
// macOS resource forks on network shares ("._IMG_0001.jpg"), Office and
// LibreOffice lock files, Windows thumbnail caches, Finder metadata.
func notJudged(base string) bool {
	return strings.HasPrefix(base, "._") || strings.HasPrefix(base, "~$") || strings.HasPrefix(base, ".~lock.") ||
		base == "thumbs.db" || base == ".ds_store" || base == "desktop.ini"
}

// magic is what the start of a file must look like for its extension.
type magic struct {
	prefixes [][]byte
	// at, when set, is where the single prefix must appear instead of 0.
	at int
	// within, when set, allows the prefix anywhere in the first within bytes.
	within int
}

var (
	zipMagic  = magic{prefixes: [][]byte{[]byte("PK\x03\x04"), []byte("PK\x05\x06"), []byte("PK\x07\x08")}}
	ole2Magic = magic{prefixes: [][]byte{{0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1}}}
	ftypMagic = magic{prefixes: [][]byte{[]byte("ftyp")}, at: 4}
)

var magics = map[string]magic{
	".jpg": {prefixes: [][]byte{{0xFF, 0xD8, 0xFF}}}, ".jpeg": {prefixes: [][]byte{{0xFF, 0xD8, 0xFF}}},
	".png":  {prefixes: [][]byte{{0x89, 'P', 'N', 'G'}}},
	".gif":  {prefixes: [][]byte{[]byte("GIF87a"), []byte("GIF89a")}},
	".pdf":  {prefixes: [][]byte{[]byte("%PDF")}, within: 1024},
	".docx": zipMagic, ".xlsx": zipMagic, ".pptx": zipMagic, ".odt": zipMagic, ".ods": zipMagic,
	".odp": zipMagic, ".zip": zipMagic, ".epub": zipMagic,
	".doc": ole2Magic, ".xls": ole2Magic, ".ppt": ole2Magic,
	".mp4": ftypMagic, ".mov": ftypMagic, ".m4a": ftypMagic, ".heic": ftypMagic, ".heif": ftypMagic,
	// Not ".db": Windows' Thumbs.db and many apps' stores use it for other formats.
	".sqlite": {prefixes: [][]byte{[]byte("SQLite format 3\x00")}},
}

// textExtensions are formats that are plain text; encrypted, they become
// random bytes. Compressed formats (photos, archives, video) already look
// random, so they are judged only by their magic bytes.
var textExtensions = map[string]bool{
	".txt": true, ".md": true, ".csv": true, ".tsv": true, ".json": true, ".xml": true,
	".html": true, ".htm": true, ".log": true, ".yaml": true, ".yml": true, ".ini": true,
	".conf": true, ".go": true, ".py": true, ".js": true, ".ts": true, ".java": true,
	".c": true, ".h": true, ".rb": true, ".sh": true, ".sql": true, ".rtf": true, ".tex": true,
}

// encryptedEntropy is the bits per byte above which a text file's start is
// taken as encrypted. English text sits near 4.5, source code under 6,
// encrypted or random data at 7.9 and above.
const encryptedEntropy = 7.2

// suspicious returns why a changed file looks like ransomware's work, or ""
// when it does not. head is the start of the file.
func suspicious(name string, head []byte) string {
	base := strings.ToLower(filepath.Base(name))
	if notJudged(base) {
		return ""
	}
	ext := filepath.Ext(base)
	stem := strings.TrimSuffix(base, ext)
	// Ransomware appends its extension to the file's own ("Report.docx.lockbit"),
	// so a lone ".hive" or ".royal" is some program's file, not a victim.
	if ransomExtensions[ext] && strings.Contains(stem, ".") {
		return "ransomware extension " + ext
	}
	if ransomNoteNames[base] {
		return "ransom note name"
	}
	if noteExtensions[ext] {
		for _, w := range ransomNoteWords {
			if strings.Contains(stem, w) {
				return "ransom note name"
			}
		}
	}
	if m, ok := magics[ext]; ok && len(head) >= 16 && !m.matches(head) {
		return "content does not match " + ext
	}
	if textExtensions[ext] && len(head) >= 512 && entropy(head) > encryptedEntropy {
		return "text file looks encrypted"
	}
	return ""
}

func (m magic) matches(head []byte) bool {
	for _, p := range m.prefixes {
		switch {
		case m.within > 0:
			n := m.within
			if n > len(head) {
				n = len(head)
			}
			if bytes.Contains(head[:n], p) {
				return true
			}
		case len(head) >= m.at+len(p) && bytes.Equal(head[m.at:m.at+len(p)], p):
			return true
		}
	}
	return false
}

// entropy is the Shannon entropy of b in bits per byte.
func entropy(b []byte) float64 {
	if len(b) == 0 {
		return 0
	}
	var counts [256]int
	for _, c := range b {
		counts[c]++
	}
	e := 0.0
	n := float64(len(b))
	for _, k := range counts {
		if k > 0 {
			p := float64(k) / n
			e -= p * math.Log2(p)
		}
	}
	return e
}
