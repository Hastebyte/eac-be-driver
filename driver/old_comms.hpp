#pragma once

#define IOCTL_ULTRADRV	0x200C1

enum class SendDataIds : unsigned char
{
	Status,
	HideWindow,
	Attach,
	Detach,
	FindModule,
	KeyState,
	Read,
	Write,
	ReadInjected,
	WriteReadOnly
};

typedef struct _SEND_DATA_INFO
{
	SendDataIds id;
	HANDLE sender_pid;
	unsigned char Buffer[ 4096 ];
} SEND_DATA_INFO, * PSEND_DATA_INFO;

struct CHideWindowRequest
{
	HANDLE pid;
	HWND hwnd;

	CHideWindowRequest()
	{
		this->pid = 0;
		this->hwnd = 0;
	}
};

struct CAttachProcessRequest
{
	uint32_t hash;

	CAttachProcessRequest( const uint32_t hash ) : CAttachProcessRequest()
	{
		this->hash = hash;
	}
	CAttachProcessRequest()
	{
		this->hash = 0;
	}
};

struct CDetachProcessRequest
{
	CDetachProcessRequest() = default;
};

struct CGetWindowThreadRequest
{
	uintptr_t window_handle;
	uintptr_t res;

	CGetWindowThreadRequest( const uintptr_t window_handle ) : CGetWindowThreadRequest()
	{
		this->window_handle = window_handle;
	}
	CGetWindowThreadRequest()
	{
		this->window_handle = 0;
		this->res = 0;
	}
};

struct CSetWindowThreadRequest
{
	uintptr_t target_window_handle;
	uintptr_t thread_pointer;

	CSetWindowThreadRequest( const uintptr_t window_handle, const uintptr_t thread_pointer ) : CSetWindowThreadRequest()
	{
		this->target_window_handle = window_handle;
		this->thread_pointer = thread_pointer;
	}
	CSetWindowThreadRequest()
	{
		this->target_window_handle = 0;
		this->thread_pointer = 0;
	}
};

struct CFindModuleRequest
{
	uint32_t hash;
	uintptr_t* res;

	CFindModuleRequest( const uint32_t hash ) : CFindModuleRequest()
	{
		this->hash = hash;
	}
	CFindModuleRequest()
	{
		this->hash = 0;
		this->res = 0;
	}
};

struct CGetKeyStateRequest
{
	int key;
	bool* res;

	CGetKeyStateRequest( const int key ) : CGetKeyStateRequest()
	{
		this->key = key;
	}

	CGetKeyStateRequest()
	{
		this->key = 0;
		this->res = nullptr;
	}
};

struct CReadWriteRequest
{
	void* address;
	void* buffer;
	size_t size;

	CReadWriteRequest(
		void* address,
		void* buffer,
		const size_t size ) : CReadWriteRequest()
	{
		this->address = address;
		this->buffer = buffer;
		this->size = size;
	}

	CReadWriteRequest()
	{
		this->address = 0;
		this->buffer = 0;
		this->size = 0;
	}
};

struct CChangeProtRequest
{
	uintptr_t address;

	CChangeProtRequest(
		uintptr_t address
	) : CChangeProtRequest()
	{
		this->address = address;
	}

	CChangeProtRequest()
	{
		this->address = 0;
	}
};

namespace comms
{
	extern BOOLEAN HandleRequest( const PSEND_DATA_INFO& pBuf );
}