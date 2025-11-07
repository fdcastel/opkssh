//go:build windows
// +build windows

package files

import (
	"fmt"
	"syscall"
	"unsafe"
)

var procLookupAccountName = advapi32.NewProc("LookupAccountNameW")

// ResolveAccountToSID resolves an account name (e.g. "Administrators") to a
// raw SID byte slice and returns the SID_NAME_USE (sidUse) value. Returns an
// error if resolution fails.
func ResolveAccountToSID(name string) ([]byte, uint32, error) {
	if name == "" {
		return nil, 0, fmt.Errorf("empty name")
	}
	pName, _ := syscall.UTF16PtrFromString(name)
	var sidSize uint32
	var domSize uint32
	var sidUse uint32
	// first call to determine sizes
	procLookupAccountName.Call(
		0,
		uintptr(unsafe.Pointer(pName)),
		0,
		uintptr(unsafe.Pointer(&sidSize)),
		0,
		uintptr(unsafe.Pointer(&domSize)),
		uintptr(unsafe.Pointer(&sidUse)),
	)
	if sidSize == 0 {
		return nil, 0, fmt.Errorf("LookupAccountNameW: could not determine SID buffer size for %s", name)
	}
	sid := make([]byte, sidSize)
	dom := make([]uint16, domSize)
	ret, _, err := procLookupAccountName.Call(
		0,
		uintptr(unsafe.Pointer(pName)),
		uintptr(unsafe.Pointer(&sid[0])),
		uintptr(unsafe.Pointer(&sidSize)),
		uintptr(unsafe.Pointer(&dom[0])),
		uintptr(unsafe.Pointer(&domSize)),
		uintptr(unsafe.Pointer(&sidUse)),
	)
	if ret == 0 {
		return nil, 0, fmt.Errorf("LookupAccountNameW failed for %s: %v", name, err)
	}
	return sid, sidUse, nil
}
