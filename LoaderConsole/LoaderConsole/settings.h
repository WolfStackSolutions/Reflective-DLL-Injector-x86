#pragma once
#include <string>
#include <cstdint>

namespace Settings
{
	static const std::string server_ip = "1.1.1.1";
	static const uint16_t server_port = 1222;
	static const std::wstring target_process = L"processnamex86";
	static const uint8_t XOR_KEY[] = { 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0 };
	static const size_t XOR_KEY_SIZE = sizeof(XOR_KEY);
}
