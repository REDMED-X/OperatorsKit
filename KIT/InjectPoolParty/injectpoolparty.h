#pragma once

#include <windows.h>

#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004L)
#define WORKER_FACTORY_RELEASE_WORKER 0x0001
#define WORKER_FACTORY_WAIT 0x0002
#define WORKER_FACTORY_SET_INFORMATION 0x0004
#define WORKER_FACTORY_QUERY_INFORMATION 0x0008
#define WORKER_FACTORY_READY_WORKER 0x0010
#define WORKER_FACTORY_SHUTDOWN 0x0020
#define WORKER_FACTORY_ALL_ACCESS ( \
       STANDARD_RIGHTS_REQUIRED | \
       WORKER_FACTORY_RELEASE_WORKER | \
       WORKER_FACTORY_WAIT | \
       WORKER_FACTORY_SET_INFORMATION | \
       WORKER_FACTORY_QUERY_INFORMATION | \
       WORKER_FACTORY_READY_WORKER | \
       WORKER_FACTORY_SHUTDOWN \
)

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING, * PUNICODE_STRING;


typedef struct _TP_TASK_CALLBACKS
{
    void* ExecuteCallback;
    void* Unposted;
} TP_TASK_CALLBACKS, * PTP_TASK_CALLBACKS;

typedef struct _TP_TASK
{
    struct _TP_TASK_CALLBACKS* Callbacks;
    UINT32 NumaNode;
    UINT8 IdealProcessor;
    char Padding_242[3];
    struct _LIST_ENTRY ListEntry;
} TP_TASK, * PTP_TASK;

typedef struct _TPP_REFCOUNT
{
    volatile INT32 Refcount;
} TPP_REFCOUNT, * PTPP_REFCOUNT;

typedef struct _TPP_CALLER
{
    void* ReturnAddress;
} TPP_CALLER, * PTPP_CALLER;

typedef struct _TPP_PH
{
    struct _TPP_PH_LINKS* Root;
} TPP_PH, * PTPP_PH;

typedef struct _TP_DIRECT
{
    struct _TP_TASK Task;
    UINT64 Lock;
    struct _LIST_ENTRY IoCompletionInformationList;
    void* Callback;
    UINT32 NumaNode;
    UINT8 IdealProcessor;
    char __PADDING__[3];
} TP_DIRECT, * PTP_DIRECT;

typedef struct _TPP_TIMER_SUBQUEUE
{
    INT64 Expiration;
    struct _TPP_PH WindowStart;
    struct _TPP_PH WindowEnd;
    void* Timer;
    void* TimerPkt;
    struct _TP_DIRECT Direct;
    UINT32 ExpirationWindow;
    INT32 __PADDING__[1];
} TPP_TIMER_SUBQUEUE, * PTPP_TIMER_SUBQUEUE;

typedef struct _TPP_TIMER_QUEUE
{
    struct _RTL_SRWLOCK Lock;
    struct _TPP_TIMER_SUBQUEUE AbsoluteQueue;
    struct _TPP_TIMER_SUBQUEUE RelativeQueue;
    INT32 AllocatedTimerCount;
    INT32 __PADDING__[1];
} TPP_TIMER_QUEUE, * PTPP_TIMER_QUEUE;

typedef struct _TPP_NUMA_NODE
{
    INT32 WorkerCount;
} TPP_NUMA_NODE, * PTPP_NUMA_NODE;

typedef union _TPP_POOL_QUEUE_STATE
{
    union
    {
        INT64 Exchange;
        struct
        {
            INT32 RunningThreadGoal : 16;
            UINT32 PendingReleaseCount : 16;
            UINT32 QueueLength;
        };
    };
} TPP_POOL_QUEUE_STATE, * PTPP_POOL_QUEUE_STATE;

typedef struct _TPP_QUEUE
{
    struct _LIST_ENTRY Queue;
    struct _RTL_SRWLOCK Lock;
} TPP_QUEUE, * PTPP_QUEUE;

typedef struct _FULL_TP_POOL
{
    struct _TPP_REFCOUNT Refcount;
    long Padding_239;
    union _TPP_POOL_QUEUE_STATE QueueState;
    struct _TPP_QUEUE* TaskQueue[3];
    struct _TPP_NUMA_NODE* NumaNode;
    struct _GROUP_AFFINITY* ProximityInfo;
    void* WorkerFactory;
    void* CompletionPort;
    struct _RTL_SRWLOCK Lock;
    struct _LIST_ENTRY PoolObjectList;
    struct _LIST_ENTRY WorkerList;
    struct _TPP_TIMER_QUEUE TimerQueue;
    struct _RTL_SRWLOCK ShutdownLock;
    UINT8 ShutdownInitiated;
    UINT8 Released;
    UINT16 PoolFlags;
    long Padding_240;
    struct _LIST_ENTRY PoolLinks;
    struct _TPP_CALLER AllocCaller;
    struct _TPP_CALLER ReleaseCaller;
    volatile INT32 AvailableWorkerCount;
    volatile INT32 LongRunningWorkerCount;
    UINT32 LastProcCount;
    volatile INT32 NodeStatus;
    volatile INT32 BindingCount;
    UINT32 CallbackChecksDisabled : 1;
    UINT32 TrimTarget : 11;
    UINT32 TrimmedThrdCount : 11;
    UINT32 SelectedCpuSetCount;
    long Padding_241;
    struct _RTL_CONDITION_VARIABLE TrimComplete;
    struct _LIST_ENTRY TrimmedWorkerList;
} FULL_TP_POOL, * PFULL_TP_POOL;

typedef struct _ALPC_WORK_ON_BEHALF_TICKET
{
    UINT32 ThreadId;
    UINT32 ThreadCreationTimeLow;
} ALPC_WORK_ON_BEHALF_TICKET, * PALPC_WORK_ON_BEHALF_TICKET;

typedef union _TPP_WORK_STATE
{
    union
    {
        INT32 Exchange;
        UINT32 Insertable : 1;
        UINT32 PendingCallbackCount : 31;
    };
} TPP_WORK_STATE, * PTPP_WORK_STATE;

typedef struct _TPP_ITE_WAITER
{
    struct _TPP_ITE_WAITER* Next;
    void* ThreadId;
} TPP_ITE_WAITER, * PTPP_ITE_WAITER;

typedef struct _TPP_PH_LINKS
{
    struct _LIST_ENTRY Siblings;
    struct _LIST_ENTRY Children;
    INT64 Key;
} TPP_PH_LINKS, * PTPP_PH_LINKS;

typedef struct _TPP_ITE
{
    struct _TPP_ITE_WAITER* First;
} TPP_ITE, * PTPP_ITE;

typedef union _TPP_FLAGS_COUNT
{
    union
    {
        UINT64 Count : 60;
        UINT64 Flags : 4;
        INT64 Data;
    };
} TPP_FLAGS_COUNT, * PTPP_FLAGS_COUNT;

typedef struct _TPP_BARRIER
{
    volatile union _TPP_FLAGS_COUNT Ptr;
    struct _RTL_SRWLOCK WaitLock;
    struct _TPP_ITE WaitList;
} TPP_BARRIER, * PTPP_BARRIER;

typedef struct _TP_CLEANUP_GROUP
{
    struct _TPP_REFCOUNT Refcount;
    INT32 Released;
    struct _RTL_SRWLOCK MemberLock;
    struct _LIST_ENTRY MemberList;
    struct _TPP_BARRIER Barrier;
    struct _RTL_SRWLOCK CleanupLock;
    struct _LIST_ENTRY CleanupList;
} TP_CLEANUP_GROUP, * PTP_CLEANUP_GROUP;


typedef struct _TPP_CLEANUP_GROUP_MEMBER
{
    struct _TPP_REFCOUNT Refcount;
    long Padding_233;
    const struct _TPP_CLEANUP_GROUP_MEMBER_VFUNCS* VFuncs;
    struct _TP_CLEANUP_GROUP* CleanupGroup;
    void* CleanupGroupCancelCallback;
    void* FinalizationCallback;
    struct _LIST_ENTRY CleanupGroupMemberLinks;
    struct _TPP_BARRIER CallbackBarrier;
    union
    {
        void* Callback;
        void* WorkCallback;
        void* SimpleCallback;
        void* TimerCallback;
        void* WaitCallback;
        void* IoCallback;
        void* AlpcCallback;
        void* AlpcCallbackEx;
        void* JobCallback;
    };
    void* Context;
    struct _ACTIVATION_CONTEXT* ActivationContext;
    void* SubProcessTag;
    struct _GUID ActivityId;
    struct _ALPC_WORK_ON_BEHALF_TICKET WorkOnBehalfTicket;
    void* RaceDll;
    FULL_TP_POOL* Pool;
    struct _LIST_ENTRY PoolObjectLinks;
    union
    {
        volatile INT32 Flags;
        UINT32 LongFunction : 1;
        UINT32 Persistent : 1;
        UINT32 UnusedPublic : 14;
        UINT32 Released : 1;
        UINT32 CleanupGroupReleased : 1;
        UINT32 InCleanupGroupCleanupList : 1;
        UINT32 UnusedPrivate : 13;
    };
    long Padding_234;
    struct _TPP_CALLER AllocCaller;
    struct _TPP_CALLER ReleaseCaller;
    enum _TP_CALLBACK_PRIORITY CallbackPriority;
    INT32 __PADDING__[1];
} TPP_CLEANUP_GROUP_MEMBER, * PTPP_CLEANUP_GROUP_MEMBER;

typedef struct _FULL_TP_WORK
{
    struct _TPP_CLEANUP_GROUP_MEMBER CleanupGroupMember;
    struct _TP_TASK Task;
    volatile union _TPP_WORK_STATE WorkState;
    INT32 __PADDING__[1];
} FULL_TP_WORK, * PFULL_TP_WORK;


typedef struct _FULL_TP_TIMER
{
    struct _FULL_TP_WORK Work;
    struct _RTL_SRWLOCK Lock;
    union
    {
        struct _TPP_PH_LINKS WindowEndLinks;
        struct _LIST_ENTRY ExpirationLinks;
    };
    struct _TPP_PH_LINKS WindowStartLinks;
    INT64 DueTime;
    struct _TPP_ITE Ite;
    UINT32 Window;
    UINT32 Period;
    UINT8 Inserted;
    UINT8 WaitTimer;
    union
    {
        UINT8 TimerStatus;
        UINT8 InQueue : 1;
        UINT8 Absolute : 1;
        UINT8 Cancelled : 1;
    };
    UINT8 BlockInsert;
    INT32 __PADDING__[1];
} FULL_TP_TIMER, * PFULL_TP_TIMER;

typedef struct _FULL_TP_WAIT
{
    struct _FULL_TP_TIMER Timer;
    void* Handle;
    void* WaitPkt;
    void* NextWaitHandle;
    union _LARGE_INTEGER NextWaitTimeout;
    struct _TP_DIRECT Direct;
    union
    {
        union
        {
            UINT8 AllFlags;
            UINT8 NextWaitActive : 1;
            UINT8 NextTimeoutActive : 1;
            UINT8 CallbackCounted : 1;
            UINT8 Spare : 5;
        };
    } WaitFlags;
    char __PADDING__[7];
} FULL_TP_WAIT, * PFULL_TP_WAIT;

typedef struct _FULL_TP_IO
{
    struct _TPP_CLEANUP_GROUP_MEMBER CleanupGroupMember;
    struct _TP_DIRECT Direct;
    void* File;
    volatile INT32 PendingIrpCount;
    INT32 __PADDING__[1];
} FULL_TP_IO, * PFULL_TP_IO;

typedef struct _FULL_TP_ALPC
{
    struct _TP_DIRECT Direct;
    struct _TPP_CLEANUP_GROUP_MEMBER CleanupGroupMember;
    void* AlpcPort;
    INT32 DeferredSendCount;
    INT32 LastConcurrencyCount;
    union
    {
        UINT32 Flags;
        UINT32 ExTypeCallback : 1;
        UINT32 CompletionListRegistered : 1;
        UINT32 Reserved : 30;
    };
    INT32 __PADDING__[1];
} FULL_TP_ALPC, * PFULL_TP_ALPC;

typedef struct _T2_SET_PARAMETERS_V0
{
    ULONG Version;
    ULONG Reserved;
    LONGLONG NoWakeTolerance;
} T2_SET_PARAMETERS, * PT2_SET_PARAMETERS;

typedef enum _PROCESSINFOCLASS {
    ProcessBasicInformation = 0,
    ProcessDebugPort = 7,
    ProcessWow64Information = 26,
    ProcessImageFileName = 27,
    ProcessBreakOnTermination = 29
} PROCESSINFOCLASS;

typedef enum _OBJECT_INFORMATION_CLASS {
    ObjectBasicInformation = 0,
    ObjectTypeInformation = 2
} OBJECT_INFORMATION_CLASS;

typedef struct _PROCESS_HANDLE_TABLE_ENTRY_INFO
{
    HANDLE HandleValue;
    ULONG_PTR HandleCount;
    ULONG_PTR PointerCount;
    ACCESS_MASK GrantedAccess;
    ULONG ObjectTypeIndex;
    ULONG HandleAttributes;
    ULONG Reserved;
} PROCESS_HANDLE_TABLE_ENTRY_INFO, * PPROCESS_HANDLE_TABLE_ENTRY_INFO;

typedef struct _PROCESS_HANDLE_SNAPSHOT_INFORMATION
{
    ULONG_PTR NumberOfHandles;
    ULONG_PTR Reserved;
    PROCESS_HANDLE_TABLE_ENTRY_INFO Handles[ANYSIZE_ARRAY];
} PROCESS_HANDLE_SNAPSHOT_INFORMATION, * PPROCESS_HANDLE_SNAPSHOT_INFORMATION;

typedef enum
{
    ProcessHandleInformation = 51
} PROCESS_INFOCLASS;

typedef struct __PUBLIC_OBJECT_TYPE_INFORMATION {
    UNICODE_STRING TypeName;
    ULONG Reserved[22];    
} PUBLIC_OBJECT_TYPE_INFORMATION, * PPUBLIC_OBJECT_TYPE_INFORMATION;

typedef struct _WORKER_FACTORY_BASIC_INFORMATION
{
    LARGE_INTEGER Timeout;
    LARGE_INTEGER RetryTimeout;
    LARGE_INTEGER IdleTimeout;
    BOOLEAN Paused;
    BOOLEAN TimerSet;
    BOOLEAN QueuedToExWorker;
    BOOLEAN MayCreate;
    BOOLEAN CreateInProgress;
    BOOLEAN InsertedIntoQueue;
    BOOLEAN Shutdown;
    ULONG BindingCount;
    ULONG ThreadMinimum;
    ULONG ThreadMaximum;
    ULONG PendingWorkerCount;
    ULONG WaitingWorkerCount;
    ULONG TotalWorkerCount;
    ULONG ReleaseCount;
    LONGLONG InfiniteWaitGoal;
    PVOID StartRoutine;
    PVOID StartParameter;
    HANDLE ProcessId;
    SIZE_T StackReserve;
    SIZE_T StackCommit;
    NTSTATUS LastThreadCreationStatus;
} WORKER_FACTORY_BASIC_INFORMATION, * PWORKER_FACTORY_BASIC_INFORMATION;

typedef struct _CLIENT_ID {
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} CLIENT_ID, * PCLIENT_ID;

typedef struct _OBJECT_ATTRIBUTES {
    ULONG           Length;
    HANDLE          RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG           Attributes;
    PVOID           SecurityDescriptor;
    PVOID           SecurityQualityOfService;
} OBJECT_ATTRIBUTES, * POBJECT_ATTRIBUTES;


typedef NTSTATUS(WINAPI* NtOpenProcess_t)(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId);
typedef NTSTATUS(WINAPI* NtDelayExecution_t)(BOOLEAN, PLARGE_INTEGER);
typedef NTSTATUS(WINAPI* NtAllocateVirtualMemory_t)(HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect);
typedef NTSTATUS(WINAPI* NtWriteVirtualMemory_t)(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, ULONG NumberOfBytesToWrite, PULONG NumberOfBytesWritten);
typedef NTSTATUS(WINAPI* NtProtectVirtualMemory_t)(HANDLE ProcessHandle, PVOID* BaseAddress, PULONG NumberOfBytesToProtect, ULONG NewAccessProtection, PULONG OldAccessProtection);
typedef NTSTATUS(WINAPI* NtClose_t)(HANDLE Handle);

typedef NTSTATUS (NTAPI* NtSetTimer2_t)(HANDLE TimerHandle, PLARGE_INTEGER DueTime, PLARGE_INTEGER Period, PT2_SET_PARAMETERS Parameters);
typedef NTSTATUS (NTAPI* NtQueryInformationProcess_t)(IN HANDLE ProcessHandle, IN PROCESSINFOCLASS ProcessInformationClass, OUT PVOID ProcessInformation, IN ULONG ProcessInformationLength, OUT PULONG ReturnLength OPTIONAL);
typedef NTSTATUS (NTAPI* NtQueryObject_t)(HANDLE Handle, OBJECT_INFORMATION_CLASS ObjectInformationClass, PVOID ObjectInformation, ULONG ObjectInformationLength, PULONG ReturnLength);
typedef enum _QUERY_WORKERFACTORYINFOCLASS { WorkerFactoryBasicInformation = 7, } QUERY_WORKERFACTORYINFOCLASS, *PQUERY_WORKERFACTORYINFOCLASS;
typedef NTSTATUS (NTAPI* NtQueryInformationWorkerFactory_t)(HANDLE WorkerFactoryHandle, QUERY_WORKERFACTORYINFOCLASS WorkerFactoryInformationClass, PVOID WorkerFactoryInformation, ULONG WorkerFactoryInformationLength, PULONG ReturnLength);
typedef NTSTATUS (NTAPI * ZwSetIoCompletion_t)(HANDLE IoCompletionHandle, PVOID KeyContext, PVOID ApcContext, NTSTATUS IoStatus, ULONG_PTR IoStatusInformation);

WINBASEAPI void *__cdecl MSVCRT$realloc(void *_Memory, size_t _NewSize);
WINBASEAPI wchar_t *__cdecl MSVCRT$wcscmp(const wchar_t *_lhs,const wchar_t *_rhs);
WINBASEAPI HANDLE WINAPI KERNEL32$GetCurrentProcess (VOID);
WINBASEAPI BOOL WINAPI KERNEL32$DuplicateHandle(HANDLE hSourceProcessHandle, HANDLE hSourceHandle, HANDLE hTargetProcessHandle, LPHANDLE lpTargetHandle, DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwOptions);
WINBASEAPI HANDLE WINAPI KERNEL32$OpenProcess(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId);
WINBASEAPI LPVOID WINAPI KERNEL32$VirtualAllocEx(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
WINBASEAPI BOOL WINAPI KERNEL32$WriteProcessMemory(HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T *lpNumberOfBytesWritten);
WINBASEAPI PTP_TIMER  WINAPI KERNEL32$CreateThreadpoolTimer( PTP_TIMER_CALLBACK pfnti, PVOID pv, PTP_CALLBACK_ENVIRON pcbe);
WINBASEAPI BOOL WINAPI KERNEL32$SetInformationJobObject(HANDLE hJob, JOBOBJECTINFOCLASS JobObjectInformationClass, LPVOID lpJobObjectInformation, DWORD cbJobObjectInformationLength);
WINBASEAPI BOOL WINAPI KERNEL32$VirtualProtectEx(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect);
WINBASEAPI BOOL WINAPI KERNEL32$VirtualFreeEx(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType);
WINBASEAPI BOOL WINAPI KERNEL32$CloseHandle(HANDLE hObject);
WINBASEAPI int __cdecl MSVCRT$strcmp(const char *str1, const char *str2);
WINBASEAPI void __cdecl MSVCRT$free(void *ptr);
WINBASEAPI BOOL WINAPI KERNEL32$ReadProcessMemory(HANDLE hProcess, LPCVOID lpBaseAddress, LPVOID lpBuffer, SIZE_T nSize, SIZE_T *lpNumberOfBytesRead);
WINBASEAPI PTP_WORK WINAPI KERNEL32$CreateThreadpoolWork(PTP_WORK_CALLBACK pfnwk, PVOID pv, PTP_CALLBACK_ENVIRON pcbe);
WINBASEAPI void * __cdecl MSVCRT$memset(void *dest, int ch, size_t count);