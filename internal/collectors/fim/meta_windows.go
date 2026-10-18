//go:build windows

package fim

import (
	"os"

	"golang.org/x/sys/windows"
)

// fileMeta reports no mode or owner on Windows. Go synthesizes a POSIX mode
// from the read-only attribute, and ownership lives in an ACL, so either
// would be a made-up value; FIM tracks content and size there instead.
func fileMeta(_ os.FileInfo) (mode string, uid, gid *uint32) { return "", nil, nil }

// deviceOf is unavailable on Windows; mount points (junctions) are reparse
// points, which the walk never enters.
func deviceOf(_ os.FileInfo) (uint64, bool) { return 0, false }

func isPseudoFS(_ string) bool { return false }

// openNoFollow opens path without following a reparse point
// (FILE_FLAG_OPEN_REPARSE_POINT), then refuses anything that is not a plain
// on-disk file: a symlink or junction swapped in after the listing, a
// directory, or a non-disk handle such as a named pipe.
func openNoFollow(path string) (*os.File, error) {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	h, err := windows.CreateFile(p, windows.GENERIC_READ,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil, windows.OPEN_EXISTING,
		windows.FILE_FLAG_OPEN_REPARSE_POINT|windows.FILE_FLAG_SEQUENTIAL_SCAN, 0)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}

	var d windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(h, &d); err != nil {
		windows.CloseHandle(h)
		return nil, &os.PathError{Op: "stat", Path: path, Err: err}
	}
	ft, _ := windows.GetFileType(h)
	if d.FileAttributes&(windows.FILE_ATTRIBUTE_REPARSE_POINT|windows.FILE_ATTRIBUTE_DIRECTORY) != 0 ||
		ft != windows.FILE_TYPE_DISK {
		windows.CloseHandle(h)
		return nil, errNotRegular
	}
	return os.NewFile(uintptr(h), path), nil
}
