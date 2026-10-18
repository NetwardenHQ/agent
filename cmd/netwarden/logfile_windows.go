//go:build windows

package main

// openNoFollow is zero on Windows, which has no O_NOFOLLOW; the default log
// lives next to the executable in a directory only administrators can write.
const openNoFollow = 0
