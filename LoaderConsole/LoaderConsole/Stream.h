#pragma once
#include <cstdint>
#include <cstddef>

namespace Streaming
{
	enum class StreamResult : int
	{
		Success = 0,
		WsaInitFailed,
		SocketCreateFailed,
		InvalidAddress,
		ConnectionFailed,
		SizeReceiveFailed,
		SizeZero,
		SizeTooLarge,
		AllocationFailed,
		DataReceiveFailed,
		DataIncomplete,
		DecryptionFailed
	};

	constexpr size_t MAX_DLL_SIZE = 50 * 1024 * 1024;
	constexpr size_t RECV_CHUNK_SIZE = 65536;

	extern uint8_t* binary_mem;
	extern size_t   binary_size;

	StreamResult __fastcall stream_dll(const char* server_ip, uint16_t port);
	const char* result_to_string(StreamResult result);
	void cleanup();
}
