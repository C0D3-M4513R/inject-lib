use winapi::shared::ntdef::{NTSTATUS, BOOLEAN, ULONG, USHORT, CHAR, UNICODE_STRING64, UCHAR};
use winapi::shared::basetsd::ULONG64;
use ntapi::ntapi_base::KPRIORITY;
use winapi::STRUCT;
use winapi::um::winnt::{ULARGE_INTEGER, LARGE_INTEGER, LIST_ENTRY64, FLS_MAXIMUM_AVAILABLE, ULONGLONG, PVOID64, HANDLE};
use ntapi::ntpsapi::GDI_HANDLE_BUFFER64;
use ntapi::ntldr::LDR_DLL_LOAD_REASON;


macro_rules! UNION {
    ($(#[$attrs:meta])* union $name:ident {
        $($variant:ident: $ftype:ty,)+
    }) => (
        #[repr(C)] $(#[$attrs])*
        pub union $name {
            $(pub $variant: $ftype,)+
        }
        impl Copy for $name {}
        impl Clone for $name {
            #[inline]
            fn clone(&self) -> $name { *self }
        }
        #[cfg(feature = "impl-default")]
        impl Default for $name {
            #[inline]
            fn default() -> $name { unsafe { $crate::_core::mem::zeroed() } }
        }
    );
}

STRUCT!{struct PROCESS_BASIC_INFORMATION_WOW64{
	ExitStatus:NTSTATUS,
	PebBaseAddress:ULONG64,
	AffinityMask:ULONG64,
	BasePriority:KPRIORITY,
	UniqueProcessId:ULONG64,
	InheritedFromUniqueProcessId:ULONG64,
}}

UNION!{union PEB64_u {
    KernelCallbackTable: ULONG64, // WOW64_POINTER
    UserSharedInfoPtr: ULONG64, // WOW64_POINTER
}}
STRUCT!{struct PEB64 {
    InheritedAddressSpace: BOOLEAN,
    ReadImageFileExecOptions: BOOLEAN,
    BeingDebugged: BOOLEAN,
    BitField: BOOLEAN,
    Mutant: ULONG64, // WOW64_POINTER
    ImageBaseAddress: ULONG64, // WOW64_POINTER
    Ldr: ULONG64, // WOW64_POINTER
    ProcessParameters: ULONG64, // WOW64_POINTER
    SubSystemData: ULONG64, // WOW64_POINTER
    ProcessHeap: ULONG64, // WOW64_POINTER
    FastPebLock: ULONG64, // WOW64_POINTER
    AtlThunkSListPtr: ULONG64, // WOW64_POINTER
    IFEOKey: ULONG64, // WOW64_POINTER
    CrossProcessFlags: ULONG,
    u: PEB64_u,
    SystemReserved: [ULONG; 1],
    AtlThunkSListPtr32: ULONG,
    ApiSetMap: ULONG64, // WOW64_POINTER
    TlsExpansionCounter: ULONG,
    TlsBitmap: ULONG64, // WOW64_POINTER
    TlsBitmapBits: [ULONG; 2],
    ReadOnlySharedMemoryBase: ULONG64, // WOW64_POINTER
    HotpatchInformation: ULONG64, // WOW64_POINTER
    ReadOnlyStaticServerData: ULONG64, // WOW64_POINTER
    AnsiCodePageData: ULONG64, // WOW64_POINTER
    OemCodePageData: ULONG64, // WOW64_POINTER
    UnicodeCaseTableData: ULONG64, // WOW64_POINTER
    NumberOfProcessors: ULONG,
    NtGlobalFlag: ULONG,
    CriticalSectionTimeout: LARGE_INTEGER,
    HeapSegmentReserve: ULONG,
    HeapSegmentCommit: ULONG,
    HeapDeCommitTotalFreeThreshold: ULONG,
    HeapDeCommitFreeBlockThreshold: ULONG,
    NumberOfHeaps: ULONG,
    MaximumNumberOfHeaps: ULONG,
    ProcessHeaps: ULONG64, // WOW64_POINTER
    GdiSharedHandleTable: ULONG64, // WOW64_POINTER
    ProcessStarterHelper: ULONG64, // WOW64_POINTER
    GdiDCAttributeList: ULONG,
    LoaderLock: ULONG64, // WOW64_POINTER
    OSMajorVersion: ULONG,
    OSMinorVersion: ULONG,
    OSBuildNumber: USHORT,
    OSCSDVersion: USHORT,
    OSPlatformId: ULONG,
    ImageSubsystem: ULONG,
    ImageSubsystemMajorVersion: ULONG,
    ImageSubsystemMinorVersion: ULONG,
    ActiveProcessAffinityMask: ULONG,
    GdiHandleBuffer: GDI_HANDLE_BUFFER64,
    PostProcessInitRoutine: ULONG64, // WOW64_POINTER
    TlsExpansionBitmap: ULONG64, // WOW64_POINTER
    TlsExpansionBitmapBits: [ULONG; 32],
    SessionId: ULONG,
    AppCompatFlags: ULARGE_INTEGER,
    AppCompatFlagsUser: ULARGE_INTEGER,
    pShimData: ULONG64, // WOW64_POINTER
    AppCompatInfo: ULONG64, // WOW64_POINTER
    CSDVersion: UNICODE_STRING64,
    ActivationContextData: ULONG64, // WOW64_POINTER
    ProcessAssemblyStorageMap: ULONG64, // WOW64_POINTER
    SystemDefaultActivationContextData: ULONG64, // WOW64_POINTER
    SystemAssemblyStorageMap: ULONG64, // WOW64_POINTER
    MinimumStackCommit: ULONG,
    FlsCallback: ULONG64, // WOW64_POINTER
    FlsListHead: LIST_ENTRY64,
    FlsBitmap: ULONG64, // WOW64_POINTER
    FlsBitmapBits: [ULONG; FLS_MAXIMUM_AVAILABLE as usize / (std::mem::size_of::<ULONG>() * 8)],
    FlsHighIndex: ULONG,
    WerRegistrationData: ULONG64, // WOW64_POINTER
    WerShipAssertPtr: ULONG64, // WOW64_POINTER
    pContextData: ULONG64, // WOW64_POINTER
    pImageHeaderHash: ULONG64, // WOW64_POINTER
    TracingFlags: ULONG,
    CsrServerReadOnlySharedMemoryBase: ULONGLONG,
    TppWorkerpListLock: ULONG64, // WOW64_POINTER
    TppWorkerpList: LIST_ENTRY64,
    WaitOnAddressHashTable: [ULONG64; 128], // WOW64_POINTER
    TelemetryCoverageHeader: ULONG64, // WOW64_POINTER
    CloudFileFlags: ULONG,
    CloudFileDiagFlags: ULONG,
    PlaceholderCompatibilityMode: CHAR,
    PlaceholderCompatibilityModeReserved: [CHAR; 7],
}}

STRUCT!{struct PEB_LDR_DATA64 {
    Length: ULONG,
    Initialized: BOOLEAN,
    SsHandle: HANDLE,
    InLoadOrderModuleList: LIST_ENTRY64,
    InMemoryOrderModuleList: LIST_ENTRY64,
    InInitializationOrderModuleList: LIST_ENTRY64,
    EntryInProgress: PVOID64,
    ShutdownInProgress: BOOLEAN,
    ShutdownThreadId: HANDLE,
}}
STRUCT!{struct RTL_BALANCED_NODE64_u_s {
    Left: ULONG64, // WOW64_POINTER
    Right: ULONG64, // WOW64_POINTER
}}
UNION!{union RTL_BALANCED_NODE64_u {
    Children: [ULONG64; 2], // WOW64_POINTER
    s: RTL_BALANCED_NODE64_u_s,
}}
STRUCT!{struct RTL_BALANCED_NODE64 {
    u: RTL_BALANCED_NODE64_u,
    ParentValue: ULONG64,//Pointer in normal ntdll, but not WOW64?
}}
UNION!{union LDR_DATA_TABLE_ENTRY64_u1 {
    InInitializationOrderLinks: LIST_ENTRY64,
    InProgressLinks: LIST_ENTRY64,
}}
UNION!{union LDR_DATA_TABLE_ENTRY64_u2 {
    FlagGroup: [UCHAR; 4],
    Flags: ULONG,
}}
STRUCT!{struct LDR_DATA_TABLE_ENTRY64 {
    InLoadOrderLinks: LIST_ENTRY64,
    InMemoryOrderLinks: LIST_ENTRY64,
    u1: LDR_DATA_TABLE_ENTRY64_u1,
    DllBase: ULONG64,//Pointer
    EntryPoint: ULONG64,//Pointer
    SizeOfImage: ULONG,
    FullDllName: UNICODE_STRING64,
    BaseDllName: UNICODE_STRING64,
    u2: LDR_DATA_TABLE_ENTRY64_u2,
    ObsoleteLoadCount: USHORT,
    TlsIndex: USHORT,
    HashLinks: LIST_ENTRY64,
    TimeDateStamp: ULONG,
    EntryPointActivationContext: ULONG64, //Pointer
    Lock: ULONG64,//Pointer
    DdagNode: ULONG64,//Pointer
    NodeModuleLink: LIST_ENTRY64,
    LoadContext: ULONG64,//Pointer
    ParentDllBase: ULONG64,//Pointer
    SwitchBackContext: ULONG64,//Pointer
    BaseAddressIndexNode: RTL_BALANCED_NODE64,
    MappingInfoIndexNode: RTL_BALANCED_NODE64,
    OriginalBase: ULONG64,//Pointer?
    LoadTime: LARGE_INTEGER,
    BaseNameHashValue: ULONG,
    LoadReason: LDR_DLL_LOAD_REASON,
    ImplicitPathOptions: ULONG,
    ReferenceCount: ULONG,
    DependentLoadFlags: ULONG,
    SigningLevel: UCHAR,
}}