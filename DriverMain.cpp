#include "ptehook.h"



EXTERN_C NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
	logger("Driver loaded", false, 0);
    if (isolation_pages((HANDLE)4960, (void*)NtCreateFile)) {
        logger("Isolation successful", false, 0);
    }
        
        
	else {
		logger("Isolation failed", true, 0);
	}
	return STATUS_SUCCESS;
}



/*

1: kd> !pte 0xfffff80456e23280
										   VA fffff80456e23280
PXE at FFFF8B45A2D16F80    PPE at FFFF8B45A2DF0088    PDE at FFFF8B45BE0115B8    PTE at FFFF8B7C022B7118
contains 0000000000E09063  contains 0000000000E0A063  contains 0000000000E1B063  contains 010000000361D121
pfn e09       ---DA--KWEV  pfn e0a       ---DA--KWEV  pfn e1b       ---DA--KWEV  pfn 361d      -G--A--KREV


PXE at FFFF8B45A2D16F80    PPE at FFFF8B45A2DF0088    PDE at FFFF8B45BE0115B8    PTE at FFFF8B7C022B7118
contains 000000007D7E6063  contains 000000007D7E7063  contains 000000007E4DB063  contains 010000007D7E8121
pfn 7d7e6     ---DA--KWEV  pfn 7d7e7     ---DA--KWEV  pfn 7e4db     ---DA--KWEV  pfn 7d7e8     -G--A--KREV

3: kd> !pte
										   VA 0000000000000000
PXE at FFFF8B45A2D16000    PPE at FFFF8B45A2C00000    PDE at FFFF8B4580000000    PTE at FFFF8B0000000000
contains 0A00000045B40867  contains 0A00000045AC1867  contains 0000000000000000
pfn 45b40     ---DA--UWEV  pfn 45ac1     ---DA--UWEV  contains 0000000000000000
not valid


[PteHook] Info: Driver loaded
[PteHook] getPagesTable: Parsing for target VA=0xfffff80456e23000
[PteHook] GetPml4Base Success: Found self-reference at index 278, PML4_BASE=0xffff8b0000000000
[PteHook] Bases:
 -> PTE_BASE=0xffff8b0000000000
 -> PDE_BASE=0xffff8b4580000000
 -> PDPTE_BASE=0xffff8b45a2c00000
 -> PML4_BASE=0xffff8b45a2d16000
[PteHook] getPagesTable Result:
 --> PTE_Addr=0xFFFF8B7C022B7118
 --> PDE_Addr=0xFFFF8B45BE0115B8
 --> PDPTE_Addr=0xFFFF8B45A2DF0088
 --> PML4E_Addr=0xFFFF8B45A2D16F80

 **** NT ACTIVE PROCESS DUMP ****
PROCESS ffffc98fd4c89080
    SessionId: none  Cid: 0004    Peb: 00000000  ParentCid: 0000
    DirBase: 001ad000  ObjectTable: ffffa582ad27ee40  HandleCount: 2517.
    Image: System

PROCESS ffffc98fd4d1f080
    SessionId: none  Cid: 006c    Peb: 00000000  ParentCid: 0004
    DirBase: 05248000  ObjectTable: ffffa582ad2528c0  HandleCount:   0.
    Image: Registry

PROCESS ffffc98fd742d040
    SessionId: none  Cid: 0148    Peb: 46c5394000  ParentCid: 0004
    DirBase: 07b65000  ObjectTable: ffffa582ad84e080  HandleCount:  53.
    Image: smss.exe

PROCESS ffffc98fd530b0c0
    SessionId: 0  Cid: 01b8    Peb: ddd05b7000  ParentCid: 01ac
    DirBase: 0491e000  ObjectTable: ffffa582b08fe980  HandleCount: 439.
    Image: csrss.exe

PROCESS ffffc98fd63a4080
    SessionId: 0  Cid: 0208    Peb: d35784000  ParentCid: 01ac
    DirBase: 125bf000  ObjectTable: ffffa582ad3c04c0  HandleCount: 163.
    Image: wininit.exe

PROCESS ffffc98fd63af140
    SessionId: 1  Cid: 0210    Peb: 3e1cf6d000  ParentCid: 0200
    DirBase: 12861000  ObjectTable: ffffa582ad3bf380  HandleCount: 395.
    Image: csrss.exe

PROCESS ffffc98fd63ef080
    SessionId: 1  Cid: 0254    Peb: 1adea37000  ParentCid: 0200
    DirBase: 10f88000  ObjectTable: ffffa582ad3bf500  HandleCount: 269.
    Image: winlogon.exe

PROCESS ffffc98fd5948080
    SessionId: 0  Cid: 029c    Peb: f9809fa000  ParentCid: 0208
    DirBase: 0d1a8000  ObjectTable: ffffa582ad3c0980  HandleCount: 387.
    Image: services.exe

PROCESS ffffc98fd5945080
    SessionId: 0  Cid: 02b0    Peb: 72a4365000  ParentCid: 0208
    DirBase: 15d63000  ObjectTable: ffffa582ad3bfd00  HandleCount: 1387.
    Image: lsass.exe

PROCESS ffffc98fd597c240
    SessionId: 0  Cid: 0330    Peb: 8e837cf000  ParentCid: 029c
    DirBase: 14aa0000  ObjectTable: ffffa582b0c34980  HandleCount: 931.
    Image: svchost.exe

PROCESS ffffc98fd59d8140
    SessionId: 1  Cid: 034c    Peb: c3d5815000  ParentCid: 0254
    DirBase: 149eb000  ObjectTable: ffffa582b0c33380  HandleCount:  39.
    Image: fontdrvhost.exe

PROCESS ffffc98fd59d6140
    SessionId: 0  Cid: 0354    Peb: ad9e76f000  ParentCid: 0208
    DirBase: 14981000  ObjectTable: ffffa582b0c339c0  HandleCount:  39.
    Image: fontdrvhost.exe

PROCESS ffffc98fd6a102c0
    SessionId: 0  Cid: 03a0    Peb: 660fdee000  ParentCid: 029c
    DirBase: 154fd000  ObjectTable: ffffa582b0c34340  HandleCount: 1039.
    Image: svchost.exe

PROCESS ffffc98fd6b0c080
    SessionId: 1  Cid: 0048    Peb: e7b7a5d000  ParentCid: 0254
    DirBase: 165c9000  ObjectTable: ffffa582b0cfe340  HandleCount: 1102.
    Image: dwm.exe

PROCESS ffffc98fd6b71240
    SessionId: 0  Cid: 0344    Peb: c25c4a7000  ParentCid: 029c
    DirBase: 15324000  ObjectTable: ffffa582b0dfa7c0  HandleCount: 2619.
    Image: svchost.exe

PROCESS ffffc98fd6b8e2c0
    SessionId: 0  Cid: 0408    Peb: 9979685000  ParentCid: 029c
    DirBase: 179e6000  ObjectTable: ffffa582b0ec24c0  HandleCount: 653.
    Image: svchost.exe

PROCESS ffffc98fd6bb2280
    SessionId: 0  Cid: 0434    Peb: 720edf9000  ParentCid: 029c
    DirBase: 1a07e000  ObjectTable: ffffa582b0ec2980  HandleCount: 657.
    Image: svchost.exe

PROCESS ffffc98fd6be32c0
    SessionId: 0  Cid: 0464    Peb: 6d5fbc2000  ParentCid: 029c
    DirBase: 15f5c000  ObjectTable: ffffa582b0ec2640  HandleCount: 398.
    Image: svchost.exe

PROCESS ffffc98fd6c202c0
    SessionId: 0  Cid: 04d0    Peb: 302c15d000  ParentCid: 029c
    DirBase: 16727000  ObjectTable: ffffa582b0fd86c0  HandleCount: 1086.
    Image: svchost.exe

PROCESS ffffc98fd6cf22c0
    SessionId: 0  Cid: 0568    Peb: b12f3a3000  ParentCid: 029c
    DirBase: 1985d000  ObjectTable: ffffa582b106d100  HandleCount: 869.
    Image: svchost.exe

PROCESS ffffc98fd6dc2040
    SessionId: none  Cid: 05cc    Peb: 00000000  ParentCid: 0004
    DirBase: 1a68f000  ObjectTable: ffffa582b106a6c0  HandleCount:   0.
    Image: MemCompression

PROCESS ffffc98fd6e432c0
    SessionId: 0  Cid: 0650    Peb: adf39b2000  ParentCid: 029c
    DirBase: 19580000  ObjectTable: ffffa582b106dd80  HandleCount: 225.
    Image: svchost.exe

PROCESS ffffc98fd6e552c0
    SessionId: 0  Cid: 0668    Peb: ae27d4000  ParentCid: 029c
    DirBase: 197b4000  ObjectTable: ffffa582b1234780  HandleCount: 335.
    Image: svchost.exe

PROCESS ffffc98fd6f21240
    SessionId: 0  Cid: 073c    Peb: ee892f5000  ParentCid: 029c
    DirBase: 1b73c000  ObjectTable: ffffa582b1232540  HandleCount: 314.
    Image: svchost.exe

PROCESS ffffc98fd6f7b2c0
    SessionId: 0  Cid: 076c    Peb: b6deda4000  ParentCid: 029c
    DirBase: 2063d000  ObjectTable: ffffa582b1232200  HandleCount: 126.
    Image: svchost.exe

PROCESS ffffc98fd6f7d080
    SessionId: 0  Cid: 0774    Peb: d8483ad000  ParentCid: 029c
    DirBase: 20761000  ObjectTable: ffffa582b1233b00  HandleCount: 357.
    Image: svchost.exe

PROCESS ffffc98fd7a1f200
    SessionId: 0  Cid: 0488    Peb: 0041a000  ParentCid: 029c
    DirBase: 226fa000  ObjectTable: ffffa582b106d280  HandleCount: 490.
    Image: spoolsv.exe

PROCESS ffffc98fd7a222c0
    SessionId: 0  Cid: 05a0    Peb: 2b060ce000  ParentCid: 029c
    DirBase: 21363000  ObjectTable: ffffa582b1235740  HandleCount: 429.
    Image: svchost.exe

PROCESS ffffc98fd4cf2080
    SessionId: 0  Cid: 0894    Peb: cb04e9c000  ParentCid: 029c
    DirBase: 1c212000  ObjectTable: ffffa582b176ddc0  HandleCount: 568.
    Image: svchost.exe

PROCESS ffffc98fd7b020c0
    SessionId: 0  Cid: 08e4    Peb: 222e425000  ParentCid: 029c
    DirBase: 1e6f2000  ObjectTable: ffffa582b176c640  HandleCount: 162.
    Image: VGAuthService.exe

PROCESS ffffc98fd7b05080
    SessionId: 0  Cid: 08ec    Peb: 22135c7000  ParentCid: 029c
    DirBase: 1e7bb000  ObjectTable: ffffa582b176c800  HandleCount: 117.
    Image: vm3dservice.exe

PROCESS ffffc98fd7b0b280
    SessionId: 0  Cid: 0904    Peb: 90839fb000  ParentCid: 029c
    DirBase: 25d51000  ObjectTable: ffffa582b176c980  HandleCount: 304.
    Image: vmtoolsd.exe

PROCESS ffffc98fd7b51280
    SessionId: 0  Cid: 0928    Peb: 100382000  ParentCid: 029c
    DirBase: 18e3e000  ObjectTable: ffffa582b176ce40  HandleCount: 835.
    Image: MsMpEng.exe

PROCESS ffffc98fd7bba2c0
    SessionId: 1  Cid: 0998    Peb: c3d903000  ParentCid: 08ec
    DirBase: 26bef000  ObjectTable: ffffa582b176b200  HandleCount: 128.
    Image: vm3dservice.exe

PROCESS ffffc98fd7d332c0
    SessionId: 0  Cid: 0af8    Peb: 8e2afa8000  ParentCid: 029c
    DirBase: 25f6d000  ObjectTable: ffffa582b176cc80  HandleCount: 200.
    Image: svchost.exe

PROCESS ffffc98fd7d91280
    SessionId: 0  Cid: 0b9c    Peb: 94ffa51000  ParentCid: 029c
    DirBase: 2f9cf000  ObjectTable: ffffa582b176b9c0  HandleCount: 276.
    Image: dllhost.exe

PROCESS ffffc98fda004240
    SessionId: 0  Cid: 02c4    Peb: 8961268000  ParentCid: 029c
    DirBase: 33550000  ObjectTable: ffffa582b176ea40  HandleCount: 640.
    Image: svchost.exe

PROCESS ffffc98fda033280
    SessionId: 0  Cid: 0b18    Peb: d006bad000  ParentCid: 029c
    DirBase: 383a5000  ObjectTable: ffffa582b1efb340  HandleCount: 233.
    Image: msdtc.exe

PROCESS ffffc98fda06a280
    SessionId: 1  Cid: 0310    Peb: d363cab000  ParentCid: 0344
    DirBase: 2b600000  ObjectTable: ffffa582b1efb500  HandleCount: 621.
    Image: sihost.exe

PROCESS ffffc98fda073300
    SessionId: 1  Cid: 0c14    Peb: ba3d03f000  ParentCid: 029c
    DirBase: 3bf64000  ObjectTable: ffffa582b1efb680  HandleCount: 908.
    Image: svchost.exe

PROCESS ffffc98fda0ee300
    SessionId: 0  Cid: 0c68    Peb: 0297b000  ParentCid: 0344
    DirBase: 36b9d000  ObjectTable: ffffa582b1efc7c0  HandleCount: 205.
    Image: MicrosoftEdgeUpdate.exe

PROCESS ffffc98fda119300
    SessionId: 1  Cid: 0cdc    Peb: f71642d000  ParentCid: 0344
    DirBase: 3ad6d000  ObjectTable: ffffa582b1efd100  HandleCount: 319.
    Image: taskhostw.exe

PROCESS ffffc98fda133280
    SessionId: 1  Cid: 0d44    Peb: 1002c9000  ParentCid: 0434
    DirBase: 2bbd1000  ObjectTable: ffffa582b1efdd80  HandleCount: 627.
    Image: ctfmon.exe

PROCESS ffffc98fd7f340c0
    SessionId: 1  Cid: 0e70    Peb: d63af1c000  ParentCid: 0254
    DirBase: 42c01000  ObjectTable: 00000000  HandleCount:   0.
    Image: userinit.exe

PROCESS ffffc98fda23d280
    SessionId: 0  Cid: 0f40    Peb: 6b11e6d000  ParentCid: 0330
    DirBase: 42096000  ObjectTable: ffffa582b276ab80  HandleCount: 685.
    Image: WmiPrvSE.exe

PROCESS ffffc98fda33e080
    SessionId: 1  Cid: 0ec8    Peb: d83a710000  ParentCid: 0330
    DirBase: 5c638000  ObjectTable: ffffa582b276a080  HandleCount: 135.
    Image: ChsIME.exe

PROCESS ffffc98fda440300
    SessionId: 0  Cid: 11c0    Peb: d0fc5d3000  ParentCid: 029c
    DirBase: 50c73000  ObjectTable: ffffa582b2769740  HandleCount: 181.
    Image: NisSrv.exe

PROCESS ffffc98fda5c72c0
    SessionId: 1  Cid: 0f98    Peb: a7d3a8c000  ParentCid: 029c
    DirBase: 6ed1b000  ObjectTable: ffffa582b3379d80  HandleCount: 296.
    Image: svchost.exe

PROCESS ffffc98fdaa8d300
    SessionId: 1  Cid: 136c    Peb: f6038a3000  ParentCid: 0330
    DirBase: 6c5fa000  ObjectTable: ffffa582b3379280  HandleCount: 279.
    Image: RuntimeBroker.exe

PROCESS ffffc98fda982080
    SessionId: 0  Cid: 147c    Peb: 82e190c000  ParentCid: 029c
    DirBase: 6d1ff000  ObjectTable: ffffa582b337a3c0  HandleCount: 677.
    Image: SearchIndexer.exe

PROCESS ffffc98fdac1c300
    SessionId: 1  Cid: 1488    Peb: cb76882000  ParentCid: 0330
    DirBase: 78672000  ObjectTable: ffffa582b33795c0  HandleCount: 480.
    Image: RuntimeBroker.exe

PROCESS ffffc98fdafad300
    SessionId: 1  Cid: 17bc    Peb: 5bcd0aa000  ParentCid: 0330
    DirBase: 06092000  ObjectTable: ffffa582b1efda80  HandleCount: 272.
    Image: RuntimeBroker.exe

PROCESS ffffc98fdb009080
    SessionId: 1  Cid: 096c    Peb: a94e968000  ParentCid: 0330
    DirBase: 257cd000  ObjectTable: ffffa582b0fda2c0  HandleCount: 243.
    Image: RuntimeBroker.exe

PROCESS ffffc98fdb21a080
    SessionId: 1  Cid: 1720    Peb: d68ce7f000  ParentCid: 0330
    DirBase: 70a64000  ObjectTable: ffffa582b337dc00  HandleCount: 410.
    Image: ApplicationFrameHost.exe

PROCESS ffffc98fdb216080
    SessionId: 1  Cid: 0edc    Peb: ec4cc54000  ParentCid: 0330
DeepFreeze
    DirBase: 6af18000  ObjectTable: ffffa582b337c7c0  HandleCount: 760.
    Image: WWAHost.exe

PROCESS ffffc98fdb2b8300
    SessionId: 1  Cid: 1890    Peb: 7b43dc5000  ParentCid: 0330
    DirBase: 211e3000  ObjectTable: ffffa582b337cc40  HandleCount: 466.
    Image: smartscreen.exe

PROCESS ffffc98fdb2ec080
    SessionId: 0  Cid: 18d8    Peb: cb4e415000  ParentCid: 147c
    DirBase: 52612000  ObjectTable: ffffa582b176d480  HandleCount: 364.
    Image: SearchProtocolHost.exe

PROCESS ffffc98fdb1b3240
    SessionId: 1  Cid: 19ac    Peb: 4564c2b000  ParentCid: 0330
    DirBase: 613a2000  ObjectTable: 00000000  HandleCount:   0.
    Image: backgroundTaskHost.exe

PROCESS ffffc98fd6e39080
    SessionId: 1  Cid: 1ae0    Peb: 8d4f0fb000  ParentCid: 0e9c
    DirBase: 73258000  ObjectTable: ffffa582b4134080  HandleCount: 170.
    Image: SecurityHealthSystray.exe

PROCESS ffffc98fda4b0300
    SessionId: 0  Cid: 1b04    Peb: 363227b000  ParentCid: 029c
    DirBase: 72148000  ObjectTable: ffffa582b4135e40  HandleCount: 395.
    Image: SecurityHealthService.exe

PROCESS ffffc98fda350080
    SessionId: 1  Cid: 1b54    Peb: e854dfd000  ParentCid: 0e9c
    DirBase: 6aeb1000  ObjectTable: ffffa582b4134d00  HandleCount: 264.
    Image: vmtoolsd.exe

PROCESS ffffc98fda39c300
    SessionId: 0  Cid: 1b70    Peb: 2f23e5f000  ParentCid: 0330
    DirBase: 652a8000  ObjectTable: ffffa582b4136140  HandleCount: 368.
    Image: WmiPrvSE.exe

PROCESS ffffc98fda5eb2c0
    SessionId: 0  Cid: 1bbc    Peb: aba5db4000  ParentCid: 029c
    DirBase: 74e93000  ObjectTable: ffffa582b41346c0  HandleCount: 217.
    Image: svchost.exe

PROCESS ffffc98fdb1b2080
    SessionId: 1  Cid: 061c    Peb: 8f1e522000  ParentCid: 0344
    DirBase: 3f856000  ObjectTable: ffffa582b4134e80  HandleCount: 149.
    Image: taskhostw.exe

PROCESS ffffc98fd6da7340
    SessionId: 1  Cid: 1a04    Peb: b1647f2000  ParentCid: 0330
    DirBase: 7058a000  ObjectTable: ffffa582b4134540  HandleCount: 289.
    Image: ChsIME.exe

PROCESS ffffc98fd7e042c0
    SessionId: 0  Cid: 1a24    Peb: 7e6927a000  ParentCid: 0668
    DirBase: 33e9b000  ObjectTable: ffffa582b4136480  HandleCount: 196.
    Image: audiodg.exe

PROCESS ffffc98fdb26e300
    SessionId: 1  Cid: 1a5c    Peb: 002f8000  ParentCid: 0e9c
    DirBase: 390a9000  ObjectTable: ffffa582b4135980  HandleCount: 469.
    Image: KmdManager.exe

PROCESS ffffc98fd7d56080
    SessionId: 1  Cid: 0fac    Peb: 25738a8000  ParentCid: 0330
DeepFreeze
    DirBase: 6fc94000  ObjectTable: ffffa582b4135040  HandleCount: 485.
    Image: WinStore.App.exe

PROCESS ffffc98fdb292340
    SessionId: 1  Cid: 1080    Peb: bf3daa6000  ParentCid: 0330
    DirBase: 16cd9000  ObjectTable: ffffa582b4035200  HandleCount: 138.
    Image: RuntimeBroker.exe

PROCESS ffffc98fdaf18080
    SessionId: 1  Cid: 0d64    Peb: 6604131000  ParentCid: 1930
    DirBase: 5a705000  ObjectTable: ffffa582b4035a00  HandleCount: 892.
    Image: OneDrive.exe

PROCESS ffffc98fdab0a080
    SessionId: 1  Cid: 19b0    Peb: 61a4c23000  ParentCid: 0330
DeepFreeze
    DirBase: 788d2000  ObjectTable: ffffa582b176bb80  HandleCount: 1082.
    Image: SkypeApp.exe

PROCESS ffffc98fd4d2b080
    SessionId: 0  Cid: 185c    Peb: 57841b4000  ParentCid: 0330
    DirBase: 30a37000  ObjectTable: ffffa582b413a300  HandleCount: 555.
    Image: MoUsoCoreWorker.exe

PROCESS ffffc98fdbf30080
    SessionId: 1  Cid: 0adc    Peb: eb08703000  ParentCid: 0330
    DirBase: 36e0d000  ObjectTable: ffffa582b276b800  HandleCount: 268.
    Image: RuntimeBroker.exe

PROCESS ffffc98fdb05f080
    SessionId: 0  Cid: 1c2c    Peb: 69282c9000  ParentCid: 0344
    DirBase: 6a364000  ObjectTable: ffffa582b3378300  HandleCount: 385.
    Image: taskhostw.exe

PROCESS ffffc98fdbe21080
    SessionId: 0  Cid: 1cd0    Peb: 9681dda000  ParentCid: 029c
    DirBase: 74c0f000  ObjectTable: ffffa582b2766200  HandleCount: 148.
    Image: TrustedInstaller.exe

PROCESS ffffc98fda6df080
    SessionId: 0  Cid: 1d24    Peb: 914994d000  ParentCid: 0330
    DirBase: 30a8f000  ObjectTable: ffffa582b3378480  HandleCount: 223.
    Image: TiWorker.exe

PROCESS ffffc98fdbe42080
    SessionId: 1  Cid: 1c6c    Peb: b4eb906000  ParentCid: 0330
DeepFreeze
    DirBase: 23288000  ObjectTable: ffffa582b4134a00  HandleCount: 144.
    Image: SkypeBackgroundHost.exe

PROCESS ffffc98fdbe38080
    SessionId: 0  Cid: 1af4    Peb: 11cbf2c000  ParentCid: 029c
    DirBase: 12f27000  ObjectTable: ffffa582b4036680  HandleCount: 491.
    Image: svchost.exe

PROCESS ffffc98fda32c080
    SessionId: 1  Cid: 1d34    Peb: eae6035000  ParentCid: 1e28
    DirBase: 10923000  ObjectTable: ffffa582b4136600  HandleCount: 512.
    Image: OneDrive.Sync.Service.exe

PROCESS ffffc98fdad8d080
    SessionId: 0  Cid: 18d0    Peb: 3ec2b5d000  ParentCid: 029c
    DirBase: 3e77d000  ObjectTable: ffffa582b4036e40  HandleCount: 415.
    Image: svchost.exe

PROCESS ffffc98fdc55a080
    SessionId: 0  Cid: 0e94    Peb: 78fe86b000  ParentCid: 029c
    DirBase: 61e54000  ObjectTable: ffffa582b4038a40  HandleCount: 103.
    Image: SgrmBroker.exe

PROCESS ffffc98fdcbab2c0
    SessionId: 0  Cid: 17f8    Peb: 89f5374000  ParentCid: 029c
    DirBase: 54561000  ObjectTable: ffffa582b4039d00  HandleCount: 217.
    Image: svchost.exe

PROCESS ffffc98fdb5c5340
    SessionId: 0  Cid: 069c    Peb: 1c8e3f4000  ParentCid: 147c
    DirBase: 42937000  ObjectTable: ffffa582b2766540  HandleCount: 135.
    Image: SearchFilterHost.exe
 */