#include "pageUtils.h"

uint64_t va_to_pa(uint64_t va) {

	return MmGetPhysicalAddress((PVOID)va).QuadPart;
}

uint64_t pa_to_va(uint64_t pa) {
	PHYSICAL_ADDRESS phyAddr;
	phyAddr.QuadPart = pa;
	return (uint64_t)MmGetVirtualForPhysical(phyAddr);
}

ULONG64 GetPml4Base()
{
    cr3 cr3_pa{ 0 };
    cr3_pa.flags = __readcr3();
    pml4e_64* cr3_va = nullptr;

    cr3_va = (pml4e_64*)pa_to_va(cr3_pa.address_of_page_directory * PAGE_SIZE);

    if (!cr3_va) {
        DbgPrintEx(77, 0, "[PteHook] GetPml4Base Error: Failed to get valid CR3 VA.\n");
        return -1;
    }

    for (uint64_t i = 0; i < 512; i++) {
        // 如果页目录号相匹配，即找到了自映射项
        if (cr3_va[i].page_frame_number == cr3_pa.address_of_page_directory) {
            // 通过偏移生成真实的最高级页表虚拟基址
            ULONG64 pml4_base = (0xFFFF000000000000ull | (i << 39));
            DbgPrintEx(77, 0, "[PteHook] GetPml4Base Success: Found self-reference at index %llu, PML4_BASE=0x%llx\n",
                i, pml4_base);
            return pml4_base;
        }
    }

    DbgPrintEx(77, 0, "[PteHook] GetPml4Base Error: Failed to find self-reference entry (checked 512 items).\n");
    return -1;
}

// 根据单个功能剥离出的 PTE 物理地址计算
uint64_t get_pte_address_by_va(uint64_t va) {
    ULONG64 PML4_VirtualBase = GetPml4Base();
    if (PML4_VirtualBase == (ULONG64)-1) {
        return 0; // 失败
    }

    // 由 PML4_VirtualBase 逆向推算 self_reference index
    uint64_t i = (PML4_VirtualBase >> 39) & 0x1FF;

    // 重新得到 PTE_BASE
    uint64_t PTE_BASE = 0xFFFF000000000000ull | (i << 39);

    // 剥离出高位符号保留有效 36 位掩码，再乘以8得到条目地址
    uint64_t offset = ((va >> 12) & 0xFFFFFFFFF) * 8;
    return PTE_BASE + offset;
}

// 核心函数: 解析当前上下文下所有的页表结构
bool getPagesTable(PAGE_TABLE* table) {
    if (!table || !table->LineAddress) return false;

    uint64_t va = table->LineAddress;
    DbgPrintEx(77, 0, "[PteHook] getPagesTable: Parsing for target VA=0x%llx\n", va);

    // 1. 获取核心基址
    ULONG64 PML4_VirtualBase = GetPml4Base();
    if (PML4_VirtualBase == (ULONG64)-1) {
        return false;
    }

    // 2. 从刚才的 PML4_VirtualBase 中反推自引用 index `i`
    // 因为 PML4_VirtualBase = 0xFFFF000000000000 | (i << 39)
    uint64_t i = (PML4_VirtualBase >> 39) & 0x1FF;

    // 3. 基于自映射公式逐级推演所有的 Base
    uint64_t PTE_BASE = PML4_VirtualBase;                  // i << 39
    uint64_t PDE_BASE = PTE_BASE | (i << 30);              // i << 39 | i << 30
    uint64_t PDPTE_BASE = PDE_BASE | (i << 21);              // i << 39 | i << 30 | i << 21
    uint64_t PML4_BASE = PDPTE_BASE | (i << 12);            // ...

    DbgPrintEx(77, 0, "[PteHook] Bases: \n -> PTE_BASE=0x%llx\n -> PDE_BASE=0x%llx\n -> PDPTE_BASE=0x%llx\n -> PML4_BASE=0x%llx\n",
        PTE_BASE, PDE_BASE, PDPTE_BASE, PML4_BASE);

    // 4. 计算具体地址 (剥离符号 F 的干扰 + 乘以 8)
    table->PteAddress = (pte_64*)(PTE_BASE + ((va >> 12) & 0xFFFFFFFFF) * 8);
    table->PdeAddress = (pde_64*)(PDE_BASE + ((va >> 21) & 0x7FFFFFF) * 8);
    table->PdpteAddress = (pdpte_64*)(PDPTE_BASE + ((va >> 30) & 0x3FFFF) * 8);
    table->Pml4eAddress = (pml4e_64*)(PML4_BASE + ((va >> 39) & 0x1FF) * 8);

    DbgPrintEx(77, 0, "[PteHook] getPagesTable Result:\n --> PTE_Addr=0x%p\n --> PDE_Addr=0x%p\n --> PDPTE_Addr=0x%p\n --> PML4E_Addr=0x%p\n",
        table->PteAddress, table->PdeAddress, table->PdpteAddress, table->Pml4eAddress);

    return true;
}

bool split_large_pages(pde_64* in_pde, pde_64* out_pde) {

    PHYSICAL_ADDRESS MaxADDRPa{ 0 }, LowADDRPa{ 0 };
    MaxADDRPa.QuadPart = MAXULONG64;
    LowADDRPa.QuadPart = 0;
    pt_entry_64* Pt;

    // 【核心修复】：对于 2MB 大页，PFN 域的最低 9 位 (位12 - 20) 包含了 PAT 和保留位。 
    // 必须用 & ~0x1FFull 清除这 9 位，才能获得绝对纯净且对齐的 2MB 物理基址！
    auto start_pfn = in_pde->page_frame_number & ~0x1FFull;

    Pt = (pt_entry_64*)MmAllocateContiguousMemorySpecifyCache(PAGE_SIZE, LowADDRPa, MaxADDRPa, LowADDRPa, MmCached);

    if (!Pt) {
        DbgPrintEx(77, 0, "[PteHook] split_large_pages Error: Failed to allocate memory for new PT.\n");
        return false;
    }

    for (int i = 0; i < 512; i++) {
        // 先完全继承标志位
        Pt[i].flags = in_pde->flags;
        // 清理 G 位
        Pt[i].global = 0;
        // 清理大页位 (变成普通 4KB PTE, 同时这也是 PTE 的 PAT 位, 强制清 0 为标准 WriteBack 缓存)
        Pt[i].large_page = 0; 
        
        // 填入计算好的纯净页框号（这一步会自动覆盖掉标志位拷贝时带来的脏位12）
        Pt[i].page_frame_number = start_pfn + i;
    }

    out_pde->flags = in_pde->flags;
    out_pde->large_page = 0;
    out_pde->page_frame_number = va_to_pa((uint64_t)Pt) / PAGE_SIZE;

    return true;
}