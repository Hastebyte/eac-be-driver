#pragma once

using f_SetHvmEvent = NTSTATUS( * )( );

namespace kaspersky
{
	extern PVOID	GetNtRoutineByIndex		( UINT Index );
	extern PVOID	GetWin32kRoutineByIndex	( UINT Index );
	extern BOOLEAN	HookNtRoutine			( UINT Index, LPVOID lpDest, LPVOID* lpOriginal );
	extern BOOLEAN	HookWin32kRoutine		( UINT Index, LPVOID lpDest, LPVOID* lpOriginal );
	extern BOOLEAN	SetupKaspersky			( );
	extern BOOLEAN  IsKasperskyHooked		( );
}