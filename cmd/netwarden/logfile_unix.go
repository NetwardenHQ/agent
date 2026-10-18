//go:build !windows

package main

import "syscall"

// openNoFollow makes the log open fail on a symlink instead of following it.
const openNoFollow = syscall.O_NOFOLLOW
