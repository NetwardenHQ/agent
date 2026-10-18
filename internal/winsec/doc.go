// Package winsec answers one question on Windows: could anyone other than
// SYSTEM or an administrator have planted or altered this file or directory?
// It is the Windows counterpart of the POSIX "owned by root, not group/world
// writable" check, and it is empty on every other platform.
package winsec
