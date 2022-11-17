#pragma once

struct Vector3
{
	float x, y, z;
};

struct Vector4
{
	float x, y, z, w;
};

struct TransformAccessReadOnly
{
	ULONGLONG pTransformData;
	int index;
};

struct TransformData
{
	ULONGLONG pTransformArray;
	ULONGLONG pTransformIndices;
};

struct Matrix34
{
	Vector4 vec0;
	Vector4 vec1;
	Vector4 vec2;
};

namespace process
{
	inline bool is_x86( const PEPROCESS process )
	{
		return ( PsGetProcessWow64Process( process ) != nullptr );
	}

	inline bool Read( const uintptr_t local_pid, const PEPROCESS kprocess, void* address, void* buffer, const size_t size )
	{

		if (local_pid == -1 || !kprocess || (EtwpIsProcessZombie && EtwpIsProcessZombie(kprocess)))
		{
			DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "if condition not met : %lu   %lu    \n", local_pid,kprocess);
			return false;
		}
		PEPROCESS lprocess{ };
		if ( !NT_SUCCESS( PsLookupProcessByProcessId( HANDLE( local_pid ), &lprocess ) ) )
			return false;

		unsigned __int64 out;
		//DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Reading : %X   %lu  %zu    \n", address, buffer, size);
		const auto res = MmCopyVirtualMemory( kprocess, address, lprocess, buffer, size, KernelMode, &out );
		ObDereferenceObject( lprocess );

		return NT_SUCCESS( res );
	}

	inline bool Write( const uintptr_t local_pid, const PEPROCESS kprocess, void* address, void* buffer, const size_t size )
	{
		if ( local_pid == -1 || !kprocess || ( EtwpIsProcessZombie && EtwpIsProcessZombie( kprocess ) ) || !MmIsAddressValid( kprocess ) )
			return false;

		PEPROCESS lprocess{ };
		if ( !NT_SUCCESS( PsLookupProcessByProcessId( HANDLE( local_pid ), &lprocess ) ) )
			return false;

		unsigned __int64 out;
		const auto res = MmCopyVirtualMemory( lprocess, buffer, kprocess, address, size, KernelMode, &out );
		ObDereferenceObject( lprocess );

		return NT_SUCCESS( res );
	}

	template <typename t>
	inline t Read( const uintptr_t local_pid, const PEPROCESS kprocess, const uintptr_t address )
	{
		t result = t();
		Read( local_pid, kprocess, reinterpret_cast< void* >( address ), &result, sizeof( t ) );
		return result;
	}

	template <typename t>
	inline bool Read( const uintptr_t local_pid, const PEPROCESS kprocess, const uintptr_t address, t buffer, const size_t size )
	{
		return Read( local_pid, kprocess, reinterpret_cast< void* >( address ), buffer, size );
	}

	inline bool ReadInjected( const uintptr_t local_pid, const PEPROCESS kprocess, uintptr_t transform, void* buffer )
	{
		__m128 result;

		const __m128 mulVec0 = { -2.000, 2.000, -2.000, 0.000 };
		const __m128 mulVec1 = { 2.000, -2.000, -2.000, 0.000 };
		const __m128 mulVec2 = { -2.000, -2.000, 2.000, 0.000 };

		TransformAccessReadOnly pTransformAccessReadOnly{ };
		pTransformAccessReadOnly = Read< TransformAccessReadOnly >( uintptr_t( PsGetCurrentProcessId() ), kprocess, uintptr_t( transform + 0x38 ) );

		TransformData transformData{ };
		transformData = Read< TransformData >( uintptr_t( PsGetCurrentProcessId() ), kprocess, uintptr_t( pTransformAccessReadOnly.pTransformData + 0x18 ) );

		size_t sizeMatriciesBuf = sizeof( Matrix34 ) * pTransformAccessReadOnly.index + sizeof( Matrix34 );
		size_t sizeIndicesBuf = sizeof( int ) * pTransformAccessReadOnly.index + sizeof( int );

		// Allocate memory for storing large amounts of data (matricies and indicies)
		PVOID pMatriciesBuf = ExAllocatePool( NonPagedPool, sizeof( ULONG_PTR ) + sizeMatriciesBuf );
		if ( !pMatriciesBuf )
			return false;

		PVOID pIndicesBuf = ExAllocatePool( NonPagedPool, sizeof( ULONG_PTR ) + sizeIndicesBuf );
		if ( !pIndicesBuf )
		{
			ExFreePool( pMatriciesBuf );
			return false;
		}

		if ( pMatriciesBuf && pIndicesBuf )
		{
			if ( !Read( uintptr_t( PsGetCurrentProcessId() ), kprocess, PVOID( transformData.pTransformArray ), pMatriciesBuf, sizeMatriciesBuf ) )
			{
				ExFreePool( pMatriciesBuf );
				ExFreePool( pIndicesBuf );
				return false;
			}

			if ( !Read( uintptr_t( PsGetCurrentProcessId() ), kprocess, PVOID( transformData.pTransformIndices ), pIndicesBuf, sizeIndicesBuf ) )
			{
				ExFreePool( pMatriciesBuf );
				ExFreePool( pIndicesBuf );
				return false;
			}

			result = *( __m128* )( ( ULONGLONG )pMatriciesBuf + 0x30 * pTransformAccessReadOnly.index );
			int transformIndex = *( int* )( ( ULONGLONG )pIndicesBuf + 0x4 * pTransformAccessReadOnly.index );

			while ( transformIndex >= 0 )
			{
				Matrix34 matrix34 = *( Matrix34* )( ( ULONGLONG )pMatriciesBuf + 0x30 * transformIndex );

				__m128 xxxx = _mm_castsi128_ps( _mm_shuffle_epi32( *( __m128i* )( &matrix34.vec1 ), 0x00 ) );	// xxxx
				__m128 yyyy = _mm_castsi128_ps( _mm_shuffle_epi32( *( __m128i* )( &matrix34.vec1 ), 0x55 ) );	// yyyy
				__m128 zwxy = _mm_castsi128_ps( _mm_shuffle_epi32( *( __m128i* )( &matrix34.vec1 ), 0x8E ) );	// zwxy
				__m128 wzyw = _mm_castsi128_ps( _mm_shuffle_epi32( *( __m128i* )( &matrix34.vec1 ), 0xDB ) );	// wzyw
				__m128 zzzz = _mm_castsi128_ps( _mm_shuffle_epi32( *( __m128i* )( &matrix34.vec1 ), 0xAA ) );	// zzzz
				__m128 yxwy = _mm_castsi128_ps( _mm_shuffle_epi32( *( __m128i* )( &matrix34.vec1 ), 0x71 ) );	// yxwy
				__m128 tmp7 = _mm_mul_ps( *( __m128* )( &matrix34.vec2 ), result );

				result = _mm_add_ps(
					_mm_add_ps(
						_mm_add_ps(
							_mm_mul_ps(
								_mm_sub_ps(
									_mm_mul_ps( _mm_mul_ps( xxxx, mulVec1 ), zwxy ),
									_mm_mul_ps( _mm_mul_ps( yyyy, mulVec2 ), wzyw ) ),
								_mm_castsi128_ps( _mm_shuffle_epi32( _mm_castps_si128( tmp7 ), 0xAA ) ) ),
							_mm_mul_ps(
								_mm_sub_ps(
									_mm_mul_ps( _mm_mul_ps( zzzz, mulVec2 ), wzyw ),
									_mm_mul_ps( _mm_mul_ps( xxxx, mulVec0 ), yxwy ) ),
								_mm_castsi128_ps( _mm_shuffle_epi32( _mm_castps_si128( tmp7 ), 0x55 ) ) ) ),
						_mm_add_ps(
							_mm_mul_ps(
								_mm_sub_ps(
									_mm_mul_ps( _mm_mul_ps( yyyy, mulVec0 ), yxwy ),
									_mm_mul_ps( _mm_mul_ps( zzzz, mulVec1 ), zwxy ) ),
								_mm_castsi128_ps( _mm_shuffle_epi32( _mm_castps_si128( tmp7 ), 0x00 ) ) ),
							tmp7 ) ), *( __m128* )( &matrix34.vec0 ) );

				transformIndex = *( int* )( ( ULONGLONG )pIndicesBuf + 0x4 * transformIndex );
			}

			ExFreePool( pMatriciesBuf );
			ExFreePool( pIndicesBuf );
		}

		PEPROCESS lprocess{ };
		if ( !NT_SUCCESS( PsLookupProcessByProcessId( HANDLE( local_pid ), &lprocess ) ) )
			return false;

		SIZE_T out{ };
		const auto res = MmCopyVirtualMemory( IoGetCurrentProcess(), &result.m128_f32[ 0 ], lprocess, buffer, sizeof( float ) * 3, KernelMode, &out );
		ObDereferenceObject( lprocess );

		//RtlCopyMemory( buffer, &result.m128_f32[ 0 ], sizeof( float ) * 3 );
		return res;
	}

	inline NTSTATUS ProtectVirtualMemory( UINT_PTR kprocess, PVOID address, SIZE_T size, ULONG protection_old )
	{
		NTSTATUS status1 = STATUS_SUCCESS;
		PEPROCESS target_process = nullptr;
		if ( !NT_SUCCESS( PsLookupProcessByProcessId( reinterpret_cast< HANDLE >( kprocess ), &target_process ) ) )
		{
			//DebugPrint("Process not found \n");
			return STATUS_NOT_FOUND;
		}

		KAPC_STATE state;
		KeStackAttachProcess( target_process, &state );
		status1 = ZwProtectVirtualMemory( NtCurrentProcess(), &address, &size, PAGE_EXECUTE_READWRITE, 0 );
		KeUnstackDetachProcess( &state );

		if ( NT_SUCCESS( status1 ) )
			protection_old = protection_old;

		ObDereferenceObject( target_process );
		//DebugPrint("Ntstatus return : %x\n", status1);
		return status1;
	}

	inline PEPROCESS find( const uint32_t hash )
	{
		if ( !PsGetNextProcess )
			return nullptr;

		PEPROCESS proc = nullptr;

		for (
			auto current_process = PsGetNextProcess( nullptr );
			current_process != nullptr;
			current_process = PsGetNextProcess( current_process ) )
		{
			if ( EtwpIsProcessZombie( current_process ) )
				continue;

			ANSI_STRING ProcName{ };
			if ( utils::GetProcessBaseName( current_process, &ProcName ) )
			{
				auto szExeName = strrchr( ProcName.Buffer, '\\' );
				if ( szExeName )
				{
					++szExeName;
					const auto Hash = crypto::hash( szExeName );

					if ( Hash == hash )
						proc = current_process;
				}
				RtlFreeAnsiString( &ProcName );
			}

			if ( proc )
				break;
		}
		return proc;
	}

	inline uintptr_t find_module_x86( const PEPROCESS kprocess, const uintptr_t peb, const uint32_t hash )
	{
		if ( !utils::valid_x86( static_cast< uint32_t >( peb ) ) )
			return 0;

		const auto peb_32 = ( peb + 0x1000 );
		const auto peb_ldr = Read<uint32_t>( uintptr_t( PsGetCurrentProcessId() ), kprocess, peb_32 + 0xc );

		if ( !utils::valid_x86( peb_ldr ) )
			return 0;

		const auto flink = Read<uint32_t>( uintptr_t( PsGetCurrentProcessId() ), kprocess, static_cast< uintptr_t >( peb_ldr ) + 0xc );
		if ( !utils::valid_x86( flink ) )
			return 0;

		auto current_module = flink;
		do
		{
			const auto name_ptr = Read<uint32_t>( uintptr_t( PsGetCurrentProcessId() ), kprocess, static_cast< uintptr_t >( current_module ) + 0x30 );
			if ( utils::valid_x86( name_ptr ) )
			{
				wchar_t name[ 256 ] = {};
				Read( uintptr_t( PsGetCurrentProcessId() ), kprocess, name_ptr, &name, sizeof( name ) );

				if ( crypto::hash( name ) == hash )
					return Read<uint32_t>( uintptr_t( PsGetCurrentProcessId() ), kprocess, static_cast< uintptr_t >( current_module ) + 0x18 );
			}
			current_module = Read<uint32_t>( uintptr_t( PsGetCurrentProcessId() ), kprocess, current_module );
		} while ( Read<uint32_t>( uintptr_t( PsGetCurrentProcessId() ), kprocess, static_cast< uintptr_t >( current_module ) + 0x18 ) != 0 );
		return 0;
	}

	inline uintptr_t find_module_x64( const PEPROCESS kprocess, const uintptr_t peb, const uint32_t hash )
	{
		if (!utils::valid(peb))
		{
			DbgOut("Fail 1\n");
			return 0;
		}


		const auto ldr = Read<uintptr_t>(uintptr_t(PsGetCurrentProcessId()), kprocess, peb + 0x18);
		if (!utils::valid(ldr))
		{
			DbgOut("Fail 2\n");
			return 0;
		}

		const auto flink = Read<uintptr_t>(uintptr_t(PsGetCurrentProcessId()), kprocess, ldr + 0x10);
		if (!utils::valid(flink))
		{
			DbgOut("Fail 3\n");
			return 0;
		}

		auto current_module = flink;
		do
		{
			const auto name_ptr = Read<uintptr_t>( uintptr_t( PsGetCurrentProcessId() ), kprocess, current_module + 0x60 );
			if ( utils::valid( name_ptr ) )
			{
				wchar_t name[ 256 ] = {};
				Read( uintptr_t( PsGetCurrentProcessId() ), kprocess, name_ptr, &name, sizeof( name ) );

				DbgOut( "FindModule module = %S, hash = 0x%X", name, crypto::hash( name ) );
				

				if ( crypto::hash( name ) == hash )
					return Read<uintptr_t>( uintptr_t( PsGetCurrentProcessId() ), kprocess, current_module + 0x30 );
			}
			current_module = Read<uintptr_t>( uintptr_t( PsGetCurrentProcessId() ), kprocess, current_module );
		} while ( Read<uintptr_t>( uintptr_t( PsGetCurrentProcessId() ), kprocess, current_module + 0x30 ) != 0 );
		return 0;
	}
}