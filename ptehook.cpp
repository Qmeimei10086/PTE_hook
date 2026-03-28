#include "ptehook.h"
#include "inline_hook.h"

void logger(const char* info, bool is_err, LONG err_code) {
	if (is_err) {
		DbgPrintEx(77, 0, "[PteHook] Error: %s, Code: %d\n", info, err_code);
	}
	else {
		DbgPrintEx(77, 0, "[PteHook] Info: %s\n", info);
	}
}

bool isolation_pages(HANDLE process_id, void* va){
	PEPROCESS process{ 0 };
	NTSTATUS status = STATUS_SUCCESS;
	PHYSICAL_ADDRESS LowAddrPa{ 0 }, MaxAddrPa{ 0 };
	MaxAddrPa.QuadPart = MAXULONG64;
	KAPC_STATE apc{ 0 };
	void* replaceAlignAddr = PAGE_ALIGN(va);

	pdpte_64* fake_pdpt = nullptr;
	pde_64* fake_pdt = nullptr;
	pte_64* fake_pt = nullptr;
	unsigned char* fake_4kb_memory = nullptr;

	uint64_t pml4e_index, pdpte_index, pde_index, pte_index;
	PAGE_TABLE Table{ 0 };

	Table.LineAddress = (uint64_t)replaceAlignAddr;

	status = PsLookupProcessByProcessId(process_id, &process);
	if (!NT_SUCCESS(status)) {
		logger("Failed to lookup process by ID", true, status);
		return false;
	}

	KeStackAttachProcess(process, &apc);
	
	if (!getPagesTable(&Table)) {
		logger("Failed to get Page Table addresses! GetPml4Base likely returned -1.", true, 0);
		return false;
	}

	pml4e_index = ((uint64_t)replaceAlignAddr & 0x0000FF8000000000) >> 39;
	pdpte_index = ((uint64_t)replaceAlignAddr & 0x0000007FC0000000) >> 30;
	pde_index = ((uint64_t)replaceAlignAddr & 0x000000003FE00000) >> 21;
	pte_index = ((uint64_t)replaceAlignAddr & 0x00000000001FF000) >> 12;

	

	// 统一分配除了 fake_pt 以外必须的基础表
	fake_4kb_memory = (unsigned char*)MmAllocateContiguousMemorySpecifyCache(PAGE_SIZE, LowAddrPa, MaxAddrPa, LowAddrPa, MmCached);
	fake_pdt = (pde_64*)MmAllocateContiguousMemorySpecifyCache(PAGE_SIZE, LowAddrPa, MaxAddrPa, LowAddrPa, MmCached);
	fake_pdpt = (pdpte_64*)MmAllocateContiguousMemorySpecifyCache(PAGE_SIZE, LowAddrPa, MaxAddrPa, LowAddrPa, MmCached);

	if (!fake_4kb_memory || !fake_pdt || !fake_pdpt) {
		logger("Failed to allocate memory for fake page tables", true, STATUS_INSUFFICIENT_RESOURCES);
		if (fake_4kb_memory) MmFreeContiguousMemory(fake_4kb_memory);
		if (fake_pdt) MmFreeContiguousMemory(fake_pdt);
		if (fake_pdpt) MmFreeContiguousMemory(fake_pdpt);
		ObDereferenceObject(process);
		return false;
	}

	RtlZeroMemory(fake_4kb_memory, PAGE_SIZE);
	RtlZeroMemory(fake_pdt, PAGE_SIZE);
	RtlZeroMemory(fake_pdpt, PAGE_SIZE);

	// 处理大页逻辑
	pde_64 fake_pde_split_info = { 0 };
	// 使用位运算判断大页 (第 7 位为大页标志 PS)


	if (Table.PdeAddress->large_page) {
		logger("Meet large page, splitting...", false, 0);
		if (!split_large_pages(Table.PdeAddress, &fake_pde_split_info)) {
			logger("Failed to split large page", true, 0);
			// 释放已申请内存后退出
			MmFreeContiguousMemory(fake_4kb_memory);
			MmFreeContiguousMemory(fake_pdt);
			MmFreeContiguousMemory(fake_pdpt);
			ObDereferenceObject(process);
			return false;
		}
		// 拆分成功后，新的 PT 地址保留在 fake_pde_split_info 的物理页框中
		
		if(Table.PdeAddress->flags &= ~0x100) Table.PdeAddress->flags &= ~0x100;
		fake_pt = (pte_64*)pa_to_va((uint64_t)fake_pde_split_info.page_frame_number * PAGE_SIZE);
	}
	else {
		// 小页：正常分配并拷贝现有的 PT
		fake_pt = (pte_64*)MmAllocateContiguousMemorySpecifyCache(PAGE_SIZE, LowAddrPa, MaxAddrPa, LowAddrPa, MmCached);
		if(Table.PteAddress->global) Table.PteAddress->global;
		if (!fake_pt) {
			MmFreeContiguousMemory(fake_4kb_memory);
			MmFreeContiguousMemory(fake_pdt);
			MmFreeContiguousMemory(fake_pdpt);
			ObDereferenceObject(process);
			return false;
		}
		memcpy(fake_pt, Table.PteAddress - pte_index, PAGE_SIZE);
	}
	logger("splitting success", false, 0);
	// 拷贝数据并修正指针基址
	memcpy(fake_4kb_memory, replaceAlignAddr, PAGE_SIZE);
	memcpy(fake_pdt, Table.PdeAddress - pde_index, PAGE_SIZE);
	memcpy(fake_pdpt, Table.PdpteAddress - pdpte_index, PAGE_SIZE);



	// 替换目标内存的物理页
	fake_pt[pte_index].page_frame_number = va_to_pa((uint64_t)fake_4kb_memory) / PAGE_SIZE;

	// 连接链路
	fake_pdt[pde_index].page_frame_number = va_to_pa((uint64_t)fake_pt) / PAGE_SIZE;

	// 必须确保 PDE 不再是大页 并且不再具有全局属性
	fake_pdt[pde_index].large_page = 0;
	fake_pdt[pde_index].ignored_1 = 0; // 取消全局页标志 G
	fake_pdt[pde_index].page_level_cache_disable = 1; // 禁止 PDE 级别缓存，确保修改立即生效

	fake_pdpt[pdpte_index].page_frame_number = va_to_pa((uint64_t)fake_pdt) / PAGE_SIZE;

	
	_disable();

	uint64_t cr3_pa = __readcr3() & 0xFFFFFFFFFFFFF000;
	pml4e_64* cr3_va = (pml4e_64*)pa_to_va(cr3_pa);
	cr3_va[pml4e_index].page_frame_number = va_to_pa((uint64_t)fake_pdpt) / PAGE_SIZE;
	
	
	DbgPrintEx(77, 0, "[PteHook] Hooking NtCreateFile at VA: %p\n", va);

	__writecr3(__readcr3());
	__invlpg(replaceAlignAddr);
	install_hook((char*)va, (char*)My_NtCreateFile);
	_enable();
	
	
	
	KeUnstackDetachProcess(&apc);
	ObDereferenceObject(process);

	

	return true;
}