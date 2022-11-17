//#include "includes.hpp"
//
////using FastIoDispatcher_ = BOOLEAN( NTAPI* )( struct _FILE_OBJECT*, BOOLEAN, PVOID, ULONG, PVOID, ULONG, ULONG, PIO_STATUS_BLOCK, struct _DEVICE_OBJECT* );
////FastIoDispatcher_ oFastIoDispatcher = NULL;
////
////BOOLEAN IoDispatcher( struct _FILE_OBJECT* FileObject, BOOLEAN Wait, PVOID InputBuffer, ULONG InputBufferLength, PVOID OutputBuffer, ULONG OutputBufferLenght, ULONG IoControlCode, PIO_STATUS_BLOCK IoStatus, struct _DEVICE_OBJECT* DeviceObject );
//
//namespace comms
//{
//	static PEPROCESS process = nullptr;
//
//	BOOLEAN HandleRequest( const PSEND_DATA_INFO& pBuf )
//	{
//		DbgOut( "HandleRequest - given id = %d", pBuf->id );
//
//		BOOLEAN bResult = FALSE;
//
//		switch ( pBuf->id )
//		{
//		case SendDataIds::HideWindow:
//		{
//			auto Ptr = reinterpret_cast< CHideWindowRequest* >( pBuf->Buffer );
//			if ( Ptr )
//			{
//				hooks::hMyHwndPid = Ptr->pid;
//				hooks::hMyHwnd = Ptr->hwnd;
//
//				/*if ( hooks::hMyHwnd )
//				{
//					const auto wnd = ValidateHwnd( reinterpret_cast< uintptr_t >( hooks::hMyHwnd ) );
//					if ( wnd )
//						*reinterpret_cast< uintptr_t* >( wnd + 0x68 ) = 0;
//				}*/
//
//				DbgOut( "HandleRequest - HideWindow pid = 0x%p, hwnd = 0x%p", hooks::hMyHwndPid, hooks::hMyHwnd );
//				bResult = TRUE;
//			}
//			break;
//		}
//
//		case SendDataIds::Attach:
//		{
//			auto pAttachProcess = reinterpret_cast< CAttachProcessRequest* >( pBuf->Buffer );
//			if ( pAttachProcess )
//			{
//				DbgOut( "HandleRequest - Attach with hash = 0x%X", pAttachProcess->hash );
//
//				process = process::find( pAttachProcess->hash );
//				if ( process )
//					bResult = TRUE;
//			}
//			break;
//		}
//
//		case SendDataIds::Detach:
//		{
//			if ( process )
//			{
//				DbgOut( "HandleRequest - Detach" );
//				process = nullptr;
//				bResult = TRUE;
//			}
//			break;
//		}
//
//		case SendDataIds::FindModule:
//		{
//			auto pFindModule = reinterpret_cast< CFindModuleRequest* >( pBuf->Buffer );
//			if ( process && pFindModule )
//			{
//				const auto peb = PsGetProcessPeb( process );
//				if ( process::is_x86( process ) )
//					*pFindModule->res = process::find_module_x86( process, peb, pFindModule->hash );
//				else
//					*pFindModule->res = process::find_module_x64( process, peb, pFindModule->hash );
//
//				DbgOut( "HandleRequest - FindModule with hash = 0x%X, res = 0x%llX", pFindModule->hash, *pFindModule->res );
//				bResult = TRUE;
//			}
//			break;
//		}
//
//		case SendDataIds::KeyState:
//		{
//			auto pGetKey = reinterpret_cast< CGetKeyStateRequest* >( pBuf->Buffer );
//			if ( pGetKey )
//			{
//				bool res = false;
//				auto key = pGetKey->key;
//
//				//KAPC_STATE apc{ };
//				//KeStackAttachProcess( process, &apc );
//				{
//					res = NtGetAsyncKeyState( key );
//				}
//				//KeUnstackDetachProcess( &apc );
//
//				*pGetKey->res = res;
//				bResult = TRUE;
//			}
//			break;
//		}
//
//		case SendDataIds::Read:
//		{
//			auto pRead = reinterpret_cast< CReadWriteRequest* >( pBuf->Buffer );
//			if ( pRead )
//			{
//				DbgOut( "HandleRequest - Read address = 0x%p, buffer = 0x%p, size = 0x%llX", pRead->address, pRead->buffer, pRead->size );
//				bResult = process::Read( uintptr_t( pBuf->sender_pid ), process, pRead->address, pRead->buffer, pRead->size );
//			}
//			break;
//		}
//
//		case SendDataIds::Write:
//		{
//			auto pWrite = reinterpret_cast< CReadWriteRequest* >( pBuf->Buffer );
//			if ( pWrite )
//			{
//				DbgOut( "HandleRequest - Write address = 0x%p, buffer = 0x%p, size = 0x%llX", pWrite->address, pWrite->buffer, pWrite->size );
//				bResult = process::Write( uintptr_t( pBuf->sender_pid ), process, pWrite->address, pWrite->buffer, pWrite->size );
//			}
//			break;
//		}
//
//		case SendDataIds::ReadInjected:
//		{
//			auto pRead = reinterpret_cast< CReadWriteRequest* >( pBuf->Buffer );
//			if ( pRead )
//			{
//				DbgOut( "HandleRequest - ReadInjected address = 0x%p, buffer = 0x%p, size = 0x%llX", pRead->address, pRead->buffer, pRead->size );
//				bResult = process::ReadInjected( uintptr_t( pBuf->sender_pid ), process, reinterpret_cast< uintptr_t >( pRead->address ), pRead->buffer );
//			}
//			break;
//		}
//
//		case SendDataIds::Status:
//		{
//			DbgOut( "HandleRequest - Status" );
//			bResult = TRUE;
//			break;
//		}
//		}
//
//		DbgOut( "HandleRequest - result = %d", bResult );
//		return bResult;
//	}
//
//	/*void HijackDispatcher()
//	{
//		UNICODE_STRING driver_name = RTL_CONSTANT_STRING( L"\\Driver\\klhk" );
//		PDRIVER_OBJECT driver_object = nullptr;
//
//		auto status = ObReferenceObjectByName(
//			&driver_name,
//			OBJ_CASE_INSENSITIVE,
//			nullptr,
//			0,
//			*IoDriverObjectType,
//			KernelMode,
//			nullptr,
//			( PVOID* )&driver_object
//		);
//
//		if ( !driver_object || !NT_SUCCESS( status ) )
//		{
//			DbgOut( "ObReferenceObjectByName returned 0x%08X driver_object: 0x%016X\n", status, driver_object );
//			return;
//		}
//
//		auto& device_control = driver_object->FastIoDispatch;
//		if ( device_control )
//		{
//			*( PVOID* )( jmp_rax + 2 ) = &IoDispatcher;
//			const auto pCave = utils::FindCodeCave( XS( "klhk.sys" ), XS( "_hvmcode" ), sizeof( jmp_rax ) );
//			if ( pCave )
//			{
//				utils::SuperCopyMemory( PVOID( pCave ), jmp_rax, sizeof( jmp_rax ) );
//				DbgOut( "Found and write cave at = 0x%llX", pCave );
//
//				oFastIoDispatcher = device_control->FastIoDeviceControl;
//				device_control->FastIoDeviceControl = PFAST_IO_DEVICE_CONTROL( pCave );
//
//				DbgOut( "Hijacked FastIoDispatch from = 0x%p, to = 0x%llX", oFastIoDispatcher, pCave );
//			}
//		}
//
//		ObDereferenceObject( driver_object );
//	}*/
//}

//BOOLEAN IoDispatcher( struct _FILE_OBJECT* FileObject, BOOLEAN Wait, PVOID InputBuffer, ULONG InputBufferLength, PVOID OutputBuffer, ULONG OutputBufferLenght, ULONG IoControlCode, PIO_STATUS_BLOCK IoStatus, struct _DEVICE_OBJECT* DeviceObject )
//{
//	DbgOut( "FastIoCtrl called cmd = 0x%X, input = 0x%p, in_len = 0x%X, output = 0x%p, out_len = 0x%X", IoControlCode, InputBuffer, InputBufferLength, OutputBuffer, OutputBufferLenght );
//
//	switch ( IoControlCode )
//	{
//	case IOCTL_ULTRADRV:
//	{
//		const auto pBuf = PSEND_DATA_INFO( InputBuffer );
//
//		if ( InputBufferLength >= sizeof( SEND_DATA_INFO ) )
//		{
//			utils::XorBuffer( PUCHAR( pBuf ), sizeof( SEND_DATA_INFO ) );
//			return comms::HandleRequest( pBuf );
//		}
//
//		DbgOut( "FastIoCtrl - invalid request given" );
//		return FALSE;
//	}
//	}
//
//	return oFastIoDispatcher( FileObject, Wait, InputBuffer, InputBufferLength, OutputBuffer, OutputBufferLenght, IoControlCode, IoStatus, DeviceObject );
//}
