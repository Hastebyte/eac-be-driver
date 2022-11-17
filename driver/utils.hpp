#pragma once

#include "hash.hpp"
#include "ntifs.h"
namespace utils
{
	inline PUCHAR win32u = nullptr, ntdll = nullptr;

	inline bool valid( const uintptr_t address )
	{
		return ( ( address > 0x10000 ) && ( address < 0x7ffffffeffff ) );
	}

	inline bool valid_x86( const uint32_t address )
	{
		return ( ( address > 0x10000 ) && ( address < 0xffff0000 ) );
	}

	inline bool valid_buffer( void* buffer, const size_t size )
	{
		return ( valid( reinterpret_cast< uintptr_t >( buffer ) ) && valid( reinterpret_cast< uintptr_t >( buffer ) + size ) );
	}

	template <typename T = uint8_t*>
	inline T resolve_jxx( uint8_t* address )
	{
		return reinterpret_cast< T >( address + *reinterpret_cast< int8_t* >( address + 1 ) + 2 );
	}

	template <typename T = uint8_t*>
	inline T resolve_call( uint8_t* address )
	{
		return reinterpret_cast< T >( address + *reinterpret_cast< int32_t* >( address + 1 ) + 5 );
	}

	template <typename T = uint8_t*>
	inline T resolve_mov( uint8_t* address )
	{
		return reinterpret_cast< T >( address + *reinterpret_cast< int32_t* >( address + 3 ) + 7 );
	}

	inline PEPROCESS GetWinlogon()
	{
		for ( int i = 0; i < 0xFFFFFF; i += 4 )
		{
			PEPROCESS process{ };
			if ( NT_SUCCESS( PsLookupProcessByProcessId( HANDLE( i ), &process ) ) )
			{
				if ( strstr( PsGetProcessImageFileName( process ), XS( "winlogon" ) ) )
					return process;

				ObDereferenceObject( process );
			}
		}
		return nullptr;
	}

	inline __forceinline void XorBuffer( PUCHAR Buffer, ULONG len )
	{
		for ( auto i = 0ul; i < len; ++i )
		{
			Buffer[ i ] ^= 94;
			Buffer[ i ] ^= 47;
		}
	}

	inline BOOLEAN FindModuleByName( LPCSTR modname, SIZE_T* base = nullptr, SIZE_T* size = nullptr )
	{
		if ( !modname )
			return FALSE;

		ULONG bytes = 0;

		auto Status = ZwQuerySystemInformation( SystemModuleInformation, NULL, bytes, &bytes );
		if ( !bytes )
			return FALSE;

		const auto info = PRTL_PROCESS_MODULES( ExAllocatePool( NonPagedPool, bytes ) );

		Status = ZwQuerySystemInformation( SystemModuleInformation, info, bytes, &bytes );
		if ( !NT_SUCCESS( Status ) )
		{
			ExFreePool( info );
			return FALSE;
		}

		BOOLEAN bResult = FALSE;

		for ( ULONG i = 0; i < info->NumberOfModules; i++ )
		{
			const auto pModule = &info->Modules[ i ];

			if ( strstr( PCHAR( pModule->FullPathName ), modname ) )
			{
				if ( base )
					*base = SIZE_T( pModule->ImageBase );

				if ( size )
					*size = SIZE_T( pModule->ImageSize );

				bResult = true;
				break;
			}
		}

		if ( info )
			ExFreePool( info );

		return bResult;
	}

	inline NTSTATUS SuperCopyMemory( IN VOID UNALIGNED* Destination, IN CONST VOID UNALIGNED* Source, IN ULONG Length )
	{
		PMDL g_pmdl = IoAllocateMdl( Destination, Length, 0, 0, NULL );
		if ( !g_pmdl )
			return STATUS_UNSUCCESSFUL;
		MmBuildMdlForNonPagedPool( g_pmdl );
		unsigned int* Mapped = ( unsigned int* )MmMapLockedPages( g_pmdl, KernelMode );
		if ( !Mapped )
		{
			IoFreeMdl( g_pmdl );
			return STATUS_UNSUCCESSFUL;
		}
		KIRQL kirql = KeRaiseIrqlToDpcLevel();
		RtlCopyMemory( Mapped, Source, Length );
		KeLowerIrql( kirql );
		//Restore memory properties.
		MmUnmapLockedPages( ( PVOID )Mapped, g_pmdl );
		IoFreeMdl( g_pmdl );
		return STATUS_SUCCESS;
	}

	inline ULONG_PTR FindCodeCave( LPCSTR modname, LPCSTR secname, UINT len )
	{
		SIZE_T base = NULL;

		if ( !modname || !secname || len <= 0 )
			return NULL;

		if ( !FindModuleByName( modname, &base ) )
			return NULL;

		auto nth = RtlImageNtHeader( PVOID( base ) );
		if ( !nth )
			return NULL;

		PIMAGE_SECTION_HEADER pSection = nullptr;

		auto sec = IMAGE_FIRST_SECTION( nth );
		for ( auto i = 0; i < nth->FileHeader.NumberOfSections; i++, sec++ )
		{
			if ( !_strnicmp( reinterpret_cast< char* >( sec->Name ), secname, IMAGE_SIZEOF_SHORT_NAME ) )
			{
				pSection = sec;
				//	DbgOut( "FindCodeCave at module = 0x%p ( %s ), found section %s at RVA = 0x%X ( Size = 0x%X )", base, modname, PCHAR( sec->Name ), sec->VirtualAddress, sec->Misc.VirtualSize );
				break;
			}
		}

		if ( pSection )
		{
			PUCHAR cur = PUCHAR( base + pSection->VirtualAddress );

			for ( auto i = 0ul, j = 0ul; i < pSection->Misc.VirtualSize; ++i )
			{
				if ( cur[ i ] == 0xCC || cur[ i ] == 0xC3 || cur[ i ] == 0x90 )
					j++;
				else
					j = 0;

				if ( j == len )
				{
					auto ullAddress = ( ULONG_PTR( base + pSection->VirtualAddress ) + ( 1 + i ) - len + 1 );
					DbgOut( "FindCodeCave result at module = 0x%p ( %s ), found at section %s, address = 0x%llX", base, modname, PCHAR( sec->Name ), ullAddress );
					return ullAddress;
				}
			}
		}
		else
			DbgOut( "FindCodeCave at module = 0x%p ( %s ), section = %s not found!", base, modname, secname );

		return NULL;
	}

	inline BOOLEAN bDataCompare( const UCHAR* pData, const UCHAR* bMask, const char* szMask )
	{
		for ( ; *szMask; ++szMask, ++pData, ++bMask )
			if ( *szMask == 'x' && *pData != *bMask )
				return 0;

		return ( *szMask ) == 0;
	}

	inline SIZE_T FindPattern( LPCSTR modname, LPCSTR secname, UCHAR* bMask, const char* szMask )
	{
		SIZE_T base = NULL;

		if ( !modname || !secname || !bMask || !szMask )
			return NULL;

		if ( !FindModuleByName( modname, &base ) )
			return NULL;

		if ( !base )
			return NULL;

		auto nth = RtlImageNtHeader( PVOID( base ) );
		if ( !nth )
			return NULL;

		PIMAGE_SECTION_HEADER pSection = nullptr;

		auto sec = IMAGE_FIRST_SECTION( nth );
		for ( auto i = 0; i < nth->FileHeader.NumberOfSections; i++, sec++ )
		{
			if ( !_strnicmp( reinterpret_cast< char* >( sec->Name ), secname, IMAGE_SIZEOF_SHORT_NAME ) )
			{
				pSection = sec;
				//	DbgOut( "FindPattern at module = 0x%p ( %s ), found section %s at RVA = 0x%X ( Size = 0x%X )", base, modname, PCHAR( sec->Name ), sec->VirtualAddress, sec->Misc.VirtualSize );
				break;
			}
		}

		if ( pSection )
		{
			auto dwAddress = ( SIZE_T )( base + pSection->VirtualAddress );

			//DbgOut( "FindPattern at module = 0x%p ( %s ), found section VA = 0x%llX", base, modname, dwAddress );

			for ( auto i = 0ul; i < pSection->Misc.VirtualSize; ++i )
			{
				if ( bDataCompare( ( UCHAR* )( dwAddress + i ), bMask, szMask ) )
				{
					auto ullResult = ( SIZE_T )( dwAddress + i );
					DbgOut( "FindPattern at module = 0x%p ( %s ), found pattern at section = %s, address = 0x%llX", base, modname, PCHAR( pSection->Name ), ullResult );
					return ullResult;
				}
			}
		}
		else
			DbgOut( "FindPattern at module = 0x%p ( %s ), section = %s not found!", base, modname, secname );

		return NULL;
	}

	inline SIZE_T FindExport( const char* modname, const char* exportname )
	{
		SIZE_T base = NULL;

		if ( !FindModuleByName( modname, &base ) )
			return NULL;

		return SIZE_T( RtlFindExportedRoutineByName( PVOID( base ), exportname ) );
	}

	inline BOOL GetProcessBaseName( PEPROCESS Process, PANSI_STRING ProcessImageName )
	{
		BOOL bResult = FALSE;

		BOOL bAttach = FALSE;
		KAPC_STATE apc{ };
		if ( Process != PsGetCurrentProcess() )
		{
			bAttach = TRUE;
			KeStackAttachProcess( Process, &apc );
		}

		wchar_t lpModuleName[ MAX_PATH ]{ };
		auto status = ZwQueryVirtualMemory( NtCurrentProcess(), PsGetProcessSectionBaseAddress( Process ), ( MEMORY_INFORMATION_CLASS )2, lpModuleName, sizeof( lpModuleName ), NULL );
		if ( NT_SUCCESS( status ) )
		{
			PUNICODE_STRING pModuleName = PUNICODE_STRING( lpModuleName );
			if ( pModuleName->Length > 0 )
			{
				RtlUnicodeStringToAnsiString( ProcessImageName, pModuleName, TRUE );
				bResult = TRUE;
			}
		}
		else
			DbgOut( "GetProcessBaseName failed with = 0x%X", status );

		if ( bAttach )
			KeUnstackDetachProcess( &apc );

		return bResult;
	}

	inline NTSTATUS LoadFile( PUNICODE_STRING FileName, PUCHAR* pImageBase )
	{
		if ( !FileName )
			return STATUS_INVALID_PARAMETER;

		OBJECT_ATTRIBUTES oa{ };
		InitializeObjectAttributes( &oa, FileName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL );

		if ( KeGetCurrentIrql() != PASSIVE_LEVEL )
		{
			DbgOut( "[ LoadFile ] IRQL too high for IO operations!\n" );
			return STATUS_UNSUCCESSFUL;
		}

		HANDLE FileHandle = NULL;

		IO_STATUS_BLOCK IoStatusBlock{ };
		auto res = ZwCreateFile( &FileHandle,
			GENERIC_READ,
			&oa,
			&IoStatusBlock, NULL,
			FILE_ATTRIBUTE_NORMAL,
			FILE_SHARE_READ,
			FILE_OPEN,
			FILE_SYNCHRONOUS_IO_NONALERT,
			NULL, 0 );

		if ( !NT_SUCCESS( res ) )
		{
			DbgOut( "[ LoadFile ] ZwCreateFile failed 0x%X\n", res );
			return STATUS_UNSUCCESSFUL;
		}

		FILE_STANDARD_INFORMATION StandardInformation{ };
		res = ZwQueryInformationFile( FileHandle, &IoStatusBlock, &StandardInformation, sizeof( FILE_STANDARD_INFORMATION ), FileStandardInformation );
		if ( !NT_SUCCESS( res ) )
		{
			DbgOut( "[ LoadFile ] ZwQueryInformationFile failed 0x%X\n", res );
			ZwClose( FileHandle );
			return STATUS_UNSUCCESSFUL;
		}

		auto FileSize = StandardInformation.EndOfFile.LowPart;
		auto FileBuffer = PUCHAR( ExAllocatePool( NonPagedPool, FileSize ) );

		if ( !FileBuffer )
		{
			DbgOut( "[ LoadFile ] ExAllocatePoolWithTag failed\n" );
			ZwClose( FileHandle );
			return STATUS_SUCCESS;
		}

		LARGE_INTEGER li{ };
		res = ZwReadFile( FileHandle,
			NULL, NULL, NULL,
			&IoStatusBlock,
			FileBuffer,
			FileSize,
			&li, NULL );
		if ( !NT_SUCCESS( res ) )
		{
			DbgOut( "[ LoadFile ] ZwReadFile failed 0x%X\n", res );
			ExFreePool( FileBuffer );
			ZwClose( FileHandle );
			return STATUS_SUCCESS;
		}

		auto dos = PIMAGE_DOS_HEADER( FileBuffer );
		if ( dos->e_magic != IMAGE_DOS_SIGNATURE )
		{
			DbgOut( "[ LoadFile ] Invalid DOS signature!\n" );
			ExFreePool( FileBuffer );
			ZwClose( FileHandle );
			return STATUS_SUCCESS;
		}

		auto nt = PIMAGE_NT_HEADERS64( FileBuffer + dos->e_lfanew );
		if ( nt->Signature != IMAGE_NT_SIGNATURE )
		{
			DbgOut( "[ LoadFile ] Invalid NT signature!\n" );
			ExFreePool( FileBuffer );
			ZwClose( FileHandle );
			return STATUS_SUCCESS;
		}

		auto Image = PUCHAR( ExAllocatePool( NonPagedPool, nt->OptionalHeader.SizeOfImage ) );
		if ( !Image )
		{
			DbgOut( "[ LoadFile ] ExAllocatePoolWithTag[1] failed!\n" );
			ExFreePool( FileBuffer );
			ZwClose( FileHandle );
			return STATUS_SUCCESS;
		}

		memcpy( Image, FileBuffer, nt->OptionalHeader.SizeOfHeaders );

		auto pISH = IMAGE_FIRST_SECTION( nt );
		for ( unsigned i = 0; i < nt->FileHeader.NumberOfSections; i++ )
			memcpy(
				Image + pISH[ i ].VirtualAddress,
				FileBuffer + pISH[ i ].PointerToRawData,
				pISH[ i ].SizeOfRawData );

		if ( pImageBase )
			*pImageBase = Image;
		else
			ExFreePool( Image );

		ExFreePool( FileBuffer );
		ZwClose( FileHandle );
		return STATUS_SUCCESS;
	}

	inline PVOID GetFunctionAddress( PVOID Module, LPCSTR FunctionName )
	{
		PIMAGE_DOS_HEADER pIDH;
		PIMAGE_NT_HEADERS pINH;
		PIMAGE_EXPORT_DIRECTORY pIED;

		PULONG Address, Name;
		PUSHORT Ordinal;

		ULONG i;

		pIDH = ( PIMAGE_DOS_HEADER )Module;
		pINH = ( PIMAGE_NT_HEADERS )( ( PUCHAR )Module + pIDH->e_lfanew );

		pIED = ( PIMAGE_EXPORT_DIRECTORY )( ( PUCHAR )Module + pINH->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT ].VirtualAddress );

		Address = ( PULONG )( ( PUCHAR )Module + pIED->AddressOfFunctions );
		Name = ( PULONG )( ( PUCHAR )Module + pIED->AddressOfNames );

		Ordinal = ( PUSHORT )( ( PUCHAR )Module + pIED->AddressOfNameOrdinals );

		for ( i = 0; i < pIED->AddressOfFunctions; i++ )
		{
			if ( !strcmp( FunctionName, ( char* )Module + Name[ i ] ) )
			{
				return ( PVOID )( ( PUCHAR )Module + Address[ Ordinal[ i ] ] );
			}
		}

		return NULL;
	}

	inline ULONG GetNtSyscall( LPCSTR FunctionName )
	{
		if ( !ntdll )
		{
			UNICODE_STRING FileName{ };
			RtlInitUnicodeString( &FileName, XS( L"\\SystemRoot\\System32\\ntdll.dll" ) );

			auto res = LoadFile( &FileName, &ntdll );
			if ( !NT_SUCCESS( res ) )
				DbgOut( "GetNtSyscall failed to load ntdll.dll = 0x%X\n", res );
		}

		if ( ntdll )
		{
			auto Fn = PUCHAR( GetFunctionAddress( ntdll, FunctionName ) );
			if ( Fn )
			{
				for ( int i = 0; i < 24; ++i )
				{
					if ( Fn[ i ] == 0xC2 || Fn[ i ] == 0xC3 )
						break;

					if ( Fn[ i ] == 0xB8 )
						return *( PULONG )( Fn + i + 1 );
				}
			}
		}
		return 0;
	}

	inline ULONG GetWin32Syscall( LPCSTR FunctionName )
	{
		if ( !win32u )
		{
			UNICODE_STRING FileName{ };
			RtlInitUnicodeString( &FileName, XS( L"\\SystemRoot\\System32\\win32u.dll" ) );

			auto res = LoadFile( &FileName, &win32u );
			if ( !NT_SUCCESS( res ) )
				DbgOut( "GetWin32Syscall failed to load win32u.dll = 0x%X\n", res );
		}

		if ( win32u )
		{
			auto Fn = PUCHAR( GetFunctionAddress( win32u, FunctionName ) );
			if ( Fn )
			{
				for ( int i = 0; i < 24; ++i )
				{
					if ( Fn[ i ] == 0xC2 || Fn[ i ] == 0xC3 )
						break;

					if ( Fn[ i ] == 0xB8 )
						return *( PULONG )( Fn + i + 1 );
				}
			}
		}
		return 0;
	}
};
typedef struct _SYSTEM_PROCESS_INFORMATION {
	ULONG NextEntryOffset;
	ULONG NumberOfThreads;
	BYTE Reserved1[48];
	UNICODE_STRING ImageName;
	KPRIORITY BasePriority;
	HANDLE UniqueProcessId;
	PVOID Reserved2;
	ULONG HandleCount;
	ULONG SessionId;
	PVOID Reserved3;
	SIZE_T PeakVirtualSize;
	SIZE_T VirtualSize;
	ULONG Reserved4;
	SIZE_T PeakWorkingSetSize;
	SIZE_T WorkingSetSize;
	PVOID Reserved5;
	SIZE_T QuotaPagedPoolUsage;
	PVOID Reserved6;
	SIZE_T QuotaNonPagedPoolUsage;
	SIZE_T PagefileUsage;
	SIZE_T PeakPagefileUsage;
	SIZE_T PrivatePageCount;
	LARGE_INTEGER Reserved7[6];
} SYSTEM_PROCESS_INFORMATION, * PSYSTEM_PROCESS_INFORMATION;
#pragma warning( push )
#pragma warning( disable : 4311 )
inline ULONG FindProcess(LPCWSTR ImageName)
{
	UNICODE_STRING ImageNameString;
	RtlInitUnicodeString(&ImageNameString, ImageName);

	ULONG buffer_size = 0;

	NTSTATUS status = ZwQuerySystemInformation(SystemProcessInformation, 0, buffer_size, &buffer_size);


	if (status != STATUS_INFO_LENGTH_MISMATCH)
	{
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[!] failed to allocate\n");
		return NULL;
	}
	buffer_size = 2 * buffer_size;
	PVOID buffer = ExAllocatePool(NonPagedPool, buffer_size);

	status = ZwQuerySystemInformation(SystemProcessInformation, buffer, buffer_size, &buffer_size);

	if (!NT_SUCCESS(status))
	{
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[!] failed to allocate2 : %X  \n", status);
		ExFreePool(buffer);
		return NULL;
	}

	PSYSTEM_PROCESS_INFORMATION current_process = reinterpret_cast<PSYSTEM_PROCESS_INFORMATION>(buffer);

	while (true)
	{
		current_process = reinterpret_cast<PSYSTEM_PROCESS_INFORMATION>(((unsigned char*)current_process) + current_process->NextEntryOffset);

		if (RtlEqualUnicodeString(&current_process->ImageName, &ImageNameString, TRUE))
		{
			HANDLE return_value = current_process->UniqueProcessId;


			ExFreePool(buffer);
			return (ULONG)(return_value);
		}

		if (current_process->NextEntryOffset == 0)
			break;
	}

	DbgPrintEx( DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[-] pid not found\n" );

	ExFreePool(buffer);

	return NULL;
}
#pragma warning( pop )
