//go:build !windows

package main

// Version para Linux/Mac: solo existe para poder correr los tests fuera de Windows.

import (
	"os"
	"strconv"
	"strings"
	"syscall"
)

func freeDiskGB(dir string) int {
	var st syscall.Statfs_t
	if err := syscall.Statfs(dir, &st); err != nil {
		return -1
	}
	return int((uint64(st.Bavail) * uint64(st.Bsize)) >> 30)
}

func totalRAMGB() int {
	path := os.Getenv("TERO_MEMINFO")
	if path == "" {
		path = "/proc/meminfo"
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return -1
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "MemTotal:") {
			f := strings.Fields(line)
			if len(f) >= 2 {
				if kb, err := strconv.Atoi(f[1]); err == nil {
					return (kb + 524288) / 1048576
				}
			}
		}
	}
	return -1
}
