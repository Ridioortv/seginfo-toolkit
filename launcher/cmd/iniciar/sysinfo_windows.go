//go:build windows

package main

import (
	"syscall"
	"unsafe"
)

var (
	kernel32                 = syscall.NewLazyDLL("kernel32.dll")
	procGetDiskFreeSpaceExW  = kernel32.NewProc("GetDiskFreeSpaceExW")
	procGlobalMemoryStatusEx = kernel32.NewProc("GlobalMemoryStatusEx")
)

// freeDiskGB: GB libres para el usuario en el disco de `dir` (-1 si no se pudo leer).
func freeDiskGB(dir string) int {
	p, err := syscall.UTF16PtrFromString(dir)
	if err != nil {
		return -1
	}
	var freeAvail, total, totalFree uint64
	r, _, _ := procGetDiskFreeSpaceExW.Call(uintptr(unsafe.Pointer(p)),
		uintptr(unsafe.Pointer(&freeAvail)), uintptr(unsafe.Pointer(&total)), uintptr(unsafe.Pointer(&totalFree)))
	if r == 0 {
		return -1
	}
	return int(freeAvail >> 30)
}

type memoryStatusEx struct {
	Length               uint32
	MemoryLoad           uint32
	TotalPhys            uint64
	AvailPhys            uint64
	TotalPageFile        uint64
	AvailPageFile        uint64
	TotalVirtual         uint64
	AvailVirtual         uint64
	AvailExtendedVirtual uint64
}

// totalRAMGB: RAM fisica total en GB, redondeada (una PC de "8 GB" reporta ~7,7). -1 si no se pudo leer.
func totalRAMGB() int {
	var m memoryStatusEx
	m.Length = uint32(unsafe.Sizeof(m))
	r, _, _ := procGlobalMemoryStatusEx.Call(uintptr(unsafe.Pointer(&m)))
	if r == 0 {
		return -1
	}
	return int((m.TotalPhys + (1 << 29)) >> 30)
}
