#include "includes.hpp"
#define ABSOLUTE(wait) (wait)

#define RELATIVE(wait) (-(wait))

#define NANOSECONDS(nanos) \
(((signed __int64)(nanos)) / 100L)

#define MICROSECONDS(micros) \
(((signed __int64)(micros)) * NANOSECONDS(1000L))

#define MILLISECONDS(milli) \
(((signed __int64)(milli)) * MICROSECONDS(1000L))

#define SECONDS(seconds) \
(((signed __int64)(seconds)) * MILLISECONDS(1000L))
EXTERN_C int _fltused = 0;




UINT NtUserQueryWindow_idx = 0, NtUserFindWindowEx_idx = 0, NtUserWindowFromPoint_idx = 0, NtUserBuildHwndList_idx = 0, NtUserGetForegroundWindow_idx = 0;
UINT NtQueryInformationAtom_idx = 0;

#define DebugPrint( X, ... ) DbgPrintEx( DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, X, __VA_ARGS__ )




/*
 * This checks your usermode process' PEB for an available msg
 * this function will call your existing drv control function
 */

const ULONG PebPortOffset = 0x900;
const ULONG64 MagicValue = 0x123456789;
VOID ProcessPort(PEPROCESS Process)
{
	KAPC_STATE State;
	KeStackAttachProcess(Process, &State);

	// Get process port information
	ULONG_PTR Peb = PsGetProcessPeb(Process);
	PPORT_INFORMATION PortInformation = PPORT_INFORMATION(ULONG_PTR(Peb) + PebPortOffset);

	// Has a port been built in this process?

	const ULONG64 MagicValue = 0x123456789;

	// Is there a msg available for reading?

	if (PortInformation->Lock == 0)
	{
		KeUnstackDetachProcess(&State);
		return;
	}

	// Does struct ptr exist?

	if (PortInformation->BufferStruct == nullptr)
	{
		KeUnstackDetachProcess(&State);
		return;
	}



	auto pData = reinterpret_cast<comms::PMEMORY_OPERATION>(reinterpret_cast<comms::PINOUT_SHAREDDATA>(PortInformation->BufferStruct));
	
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "c_base_request->cookie %lu\n", pData->cookie);
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "c_base_request->control_code %lu\n", pData->control_code);

	PortInformation->Lock = 0;
	comms::ProcessRequest(pData);
	


	KeUnstackDetachProcess(&State);

	return;
}

/*
 * Uncomment the hidden thread call
 * Replace util_client.exe with whatever you're injecting into
 */

 VOID PortThread(PVOID Context)
{
	UNREFERENCED_PARAMETER(Context);
	CID_TABLE_HIDDEN_THREAD Entry = { 0 };
	if (!hide::HideThreadPspCidTable(PsGetCurrentThreadId(), &Entry))
		return;
	DebugPrint("[-] PortThread\n");
	ULONG Counter = 0;


	//rustclient.exe //notepad.exe, 27420, , , 3.01 MB, DESKTOP-28394\Jordan, Notepad

	ULONG UniqueProcessId = FindProcess(L"RustClient.exe");
	if (!UniqueProcessId)
		return;

	PEPROCESS Process = NULL;
	NTSTATUS  Status = PsLookupProcessByProcessId(HANDLE(UniqueProcessId), &Process);

	if (!NT_SUCCESS(Status))
		return;

	while (1)
	{
		

	
		DebugPrint( "[-] Kernel thread tick %lu \n",Counter );
		
		if (!UniqueProcessId)
		{
			ULONG UniqueProcessId = FindProcess(L"RustClient.exe");
			return;
		}

		if (!NT_SUCCESS(Status))
		{
			 Status = PsLookupProcessByProcessId(HANDLE(UniqueProcessId), &Process);
			return;
		}
			
	
	
		// Main routine that parses the message

		ProcessPort(Process);
		Counter++;
		hide::RestoreThreadHandlePspCidTable(PsGetCurrentThreadId(), &Entry);
	}
	hide::RestoreThreadHandlePspCidTable(PsGetCurrentThreadId(), &Entry);
	PsTerminateSystemThread(STATUS_SUCCESS);
}

/*
 * Call this in driver entry
 *
 */

NTSTATUS CreatePortThread()
{
	HANDLE hThread = NULL;

	NTSTATUS Status = PsCreateSystemThread(
		&hThread,
		THREAD_ALL_ACCESS,
		NULL,
		NULL,
		NULL,
		PortThread,
		NULL
	);

	if (!NT_SUCCESS(Status))
	{
		DebugPrint("[!] Failed to start thread\n");
		return NULL;
	}

	return STATUS_SUCCESS;
}


EXTERN_C NTSTATUS DriverEntry( PVOID pArgs )
{
	UNREFERENCED_PARAMETER( pArgs );

	if ( !funcs::SetupFunctions() )
		return STATUS_FAILED_DRIVER_ENTRY;

	/*
	if ( !kaspersky::SetupKaspersky() )
		return STATUS_FAILED_DRIVER_ENTRY;

	DbgOut( "Kaspersky was correctly set-up!" );

	DbgOut( "Trying to hook syscalls" );
	Get_SSDTIndexes();
	Setup_ShadowSSDT();
	*/
	
	hide::CreateThreadSpoofed(CreatePortThread);
	

#if DRIVER_DEBUG_MODE
	const auto DriverObject = PDRIVER_OBJECT( pArgs );
	DriverObject->DriverUnload = DriverUnload;
#else


	hide::UInitialize();
	//hide::ClearPiDDBCache( pData->ToCleanTimeStamp );
	//hide::NullPFN( pData->BaseAddress, pData->ModuleSize );

	//memset( pData, 0, sizeof( MAPPED_DRIVER_DATA ) );
	//ExFreePool( pData );
#endif

	return STATUS_SUCCESS;
}