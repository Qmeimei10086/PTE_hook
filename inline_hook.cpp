#include "inline_hook.h"
#include "hde64.h"
#include <stdint.h>
//inline_hook_manager::inline_hook_manager(void* ori_fun, void* target_fun) {
//	this->ori_func_addr = (char*)ori_fun;
//	this->target_func_addr = (char*)target_fun;
//}
//

PFN pfn = nullptr;
HOOK_INFO hook_info;

NTSTATUS NTAPI My_NtCreateFile(
	_Out_ PHANDLE FileHandle,
	_In_ ACCESS_MASK DesiredAccess,
	_In_ POBJECT_ATTRIBUTES ObjectAttributes,
	_Out_ PIO_STATUS_BLOCK IoStatusBlock,
	_In_opt_ PLARGE_INTEGER AllocationSize,
	_In_ ULONG FileAttributes,
	_In_ ULONG ShareAccess,
	_In_ ULONG CreateDisposition,
	_In_ ULONG CreateOptions,
	_In_reads_bytes_opt_(EaLength) PVOID EaBuffer,
	_In_ ULONG EaLength
) {
	// 绝对不要在这里无条件地进行 DbgPrintEx 打印，否则瞬间卡死系统！

	bool block_access = false;

	// 必须使用 SEH 保护包围任何对 R3 指针的探测
	if (ObjectAttributes) {
		__try {
			// ProbeForRead 可以检测用户态地址是否可读，并在非法时抛出异常交由 __except 截获
			ProbeForRead(ObjectAttributes, sizeof(OBJECT_ATTRIBUTES), 1);

			if (ObjectAttributes->ObjectName) {
				ProbeForRead(ObjectAttributes->ObjectName, sizeof(UNICODE_STRING), 1);

				PWSTR uBuffer = ObjectAttributes->ObjectName->Buffer;
				USHORT uLen = ObjectAttributes->ObjectName->Length;

				if (uBuffer && uLen > 0) {
					ProbeForRead(uBuffer, uLen, 1);

					// 使用安全的分配，并避免溢出
					wchar_t* name = (wchar_t*)ExAllocatePoolWithTag(NonPagedPool, (SIZE_T)uLen + sizeof(wchar_t), 'kooH');
					if (name) {
						RtlZeroMemory(name, (SIZE_T)uLen + sizeof(wchar_t));
						RtlCopyMemory(name, uBuffer, uLen);

						if (wcsstr(name, L"tips.txt")) {
							block_access = true;
							uint64_t cr3 = __readcr3();
							DbgPrintEx(77, 0, "[PteHook] Blocked access to tips.txt Cr3: %X \r\n", cr3);
						}

						ExFreePoolWithTag(name, 'kooH');
					}
				}
			}
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			// 如果因为目标进程指针造假或内存被强行换出引发违例，这里会安全吃掉异常保护系统稳定
		}
	}

	if (block_access) {
		return STATUS_ACCESS_DENIED;
	}

	// 正常放行
	return pfn(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, AllocationSize, FileAttributes, ShareAccess, CreateDisposition, CreateOptions, EaBuffer, EaLength);
}


KIRQL wp_bit_off() {
	auto irql = KeRaiseIrqlToDpcLevel();
	UINT64 Cr0 = __readcr0();
	Cr0 &= 0xfffffffffffeffff;
	__writecr0(Cr0);
	_disable();
	return irql;
}

void wp_bit_on(KIRQL irql) {
	UINT64 Cr0 = __readcr0();
	Cr0 |= 0x10000;
	__writecr0(Cr0);
	_enable();
	KeLowerIrql(irql);
}


void* generate_tramp_line(char* ori_func, UINT64 break_bytes_count, unsigned char* break_bytes) {
	const ULONG TrampLineBreakBytesCount = 20;
	unsigned char* tramp_line_base = (unsigned char*)ExAllocatePoolWithTag(NonPagedPoolExecute, PAGE_SIZE, 'line');

	unsigned char TrampLineCode[TrampLineBreakBytesCount] = {
	0x6A, 0x00, 0x3E, 0xC7, 0x04, 0x24, 0x00, 0x00, 0x00, 0x00,
	0x3E, 0xC7, 0x44, 0x24, 0x04, 0x00, 0x00, 0x00, 0x00, 0xC3
	};

	*((PUINT32)&TrampLineCode[6]) = (UINT32)(((uint64_t)ori_func + break_bytes_count) & 0xFFFFFFFF);
	*((PUINT32)&TrampLineCode[15]) = (UINT32)((((uint64_t)ori_func + break_bytes_count) >> 32) & 0xFFFFFFFF);

	RtlCopyMemory(tramp_line_base, break_bytes, break_bytes_count);
	RtlCopyMemory(tramp_line_base + break_bytes_count, TrampLineCode, TrampLineBreakBytesCount);
	
	return tramp_line_base;

}

bool install_hook(char* ori_func, char* target_func) {
	UINT64 break_bytes_count = 0;
	hde64s hde{ 0 };
	while (break_bytes_count < 14) {
		hde64_disasm(ori_func + break_bytes_count, &hde);
		break_bytes_count += hde.len;
	}
	// save original code
	hook_info.ori_func_addr = (void*)ori_func;
	memcpy(hook_info.ori_code, ori_func, break_bytes_count);

	pfn = (PFN)(generate_tramp_line(ori_func, break_bytes_count, hook_info.ori_code));

	char jmp_code[14] = { 0xFF, 0x25, 0x00,0,0,0,0,0,0,0,0,0,0,0};
	*((ULONG64*)(&jmp_code[6])) = (ULONG64)target_func;

	KIRQL irql = wp_bit_off();
	memcpy(ori_func, jmp_code, 14);
	wp_bit_on(irql);
	
	return true;
}