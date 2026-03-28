#pragma once
#include <stdint.h>
#include <intrin.h>
#include <ntifs.h>



typedef struct _HOOK_INFO {
	void* ori_func_addr;
	unsigned char ori_code[32];
}HOOK_INFO;



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
);

using PFN = NTSTATUS(NTAPI*)(
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
);

void* generate_tramp_line(char* ori_func, UINT64 break_bytes_count, unsigned char* break_bytes);
bool install_hook(char* ori_func,char* target_func);

KIRQL wp_bit_off();
void wp_bit_on(KIRQL irql);
//class inline_hook_manager {
//
//public:
//	inline_hook_manager(void* ori_fun, void* target_fun);
//	void* generate_tramp_line(char* target_func,UINT64 break_bytes_count,char* break_bytes);
//	bool install_hook();
//	bool uninstall_hook();
//private:
//	void* ori_func_addr;
//	void* target_func_addr;
//	unsigned char* tramp_line_base;
//	HOOK_INFO hook_info;
//
//
//};


                                                                     