#include "blabla/include.h"
#include "driver/driver.h"
#include "auth/auth.hpp"
#include "blabla/skStr.h"
#include "blabla/download.h"
#include <locale>
#include <iostream>
#include <windows.h>
#include <string>
#include <sstream>
#include <winerror.h>
#include <ntstatus.h>
#include <bcrypt.h>
#include <wininet.h>
#include <xstring>
#include <vector>
#include <fstream>
#include <chrono>
#include <codecvt>
#include <curl/curl.h>
#include <nlohmann/json.hpp>
#include "blabla/protect.h"
#include "sakso.h"
#include "sakso2.h"
#include "discord.hpp"

Discord* g_Discord;
#pragma comment(lib, "discord-rpc.lib")

#pragma comment(lib, "mysqlcppconn.lib")
#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "libcurl.lib")

#pragma optimize("", off)

using namespace KeyAuth;
std::string name = "vac"; // application name. right above the blurred text aka the secret on the licenses tab among other tabs
std::string ownerid = "d"; // ownerid, found in account settings. click your profile picture on top right of dashboard and then account settings.
std::string secret = "d"; // app secret, the blurred text on licenses tab and other tabs
std::string version = "2.0"; // leave alone unless you've changed version on website
std::string url = skCrypt("https://keyauth.win/api/1.2/").decrypt(); // change if you're self-hosting
std::string name2 = "exela"; // application name. right above the blurred text aka the secret on the licenses tab among other tabs
std::string ownerid2 = "d"; // ownerid, found in account settings. click your profile picture on top right of dashboard and then account settings.
std::string secret2 = "d"; // app secret, the blurred text on licenses tab and other tabs
std::string version2 = "2.0"; // leave alone unless you've changed version on website
std::string url2 = skCrypt("https://keyauth.win/api/1.2/").decrypt(); // change if you're self-hosting

api KeyAuthApp(name, ownerid, secret, version, url);
std::string host1 = "192.42.631.net.org";
std::string user1 = "exelaaa";
std::string password1 = "exelalolss";
std::string database1 = "exelalollaq";


using namespace std;
namespace fs = std::filesystem;

std::string tm_to_readable_time(tm ctx) {
    char buffer[80];

    strftime(buffer, sizeof(buffer), " %d/%m/%y", &ctx);

    return std::string(buffer);
}

static std::time_t string_to_timet(std::string timestamp) {
    auto cv = strtol(timestamp.c_str(), NULL, 10);

    return (time_t)cv;
}

static std::tm timet_to_tm(time_t timestamp) {
    std::tm context;

    localtime_s(&context, &timestamp);

    return context;
}

DWORD GetProcessID(const std::wstring processName)
{
    PROCESSENTRY32 processInfo;
    processInfo.dwSize = sizeof(processInfo);

    HANDLE processesSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
    if (processesSnapshot == INVALID_HANDLE_VALUE)
    {
        return 0;
    }

    Process32First(processesSnapshot, &processInfo);
    if (!processName.compare(processInfo.szExeFile))
    {
        CloseHandle(processesSnapshot);
        return processInfo.th32ProcessID;
    }

    while (Process32Next(processesSnapshot, &processInfo))
    {
        if (!processName.compare(processInfo.szExeFile))
        {
            CloseHandle(processesSnapshot);
            return processInfo.th32ProcessID;
        }
    }

    CloseHandle(processesSnapshot);
    return 0;
}


auto get_process_wnd(uint32_t pid) -> HWND
{
    std::pair<HWND, uint32_t> params = { 0, pid };
    BOOL bResult = EnumWindows([](HWND hwnd, LPARAM lParam) -> BOOL {
        auto pParams = (std::pair<HWND, uint32_t>*)(lParam);
        uint32_t processId = 0;

        if (GetWindowThreadProcessId(hwnd, reinterpret_cast<LPDWORD>(&processId)) && processId == pParams->second) {
            SetLastError((uint32_t)-1);
            pParams->first = hwnd;
            return FALSE;
        }

        return TRUE;

        }, (LPARAM)&params);

    if (!bResult && GetLastError() == -1 && params.first)
        return params.first;

    return NULL;
}

string hwidcheck = DownloadString(XorStr("https://raw.githubusercontent.com/amliva/valo-auth/main/keys.txt"));
string hwidcheck2 = DownloadString(XorStr("https://raw.githubusercontent.com/ahaaha/valo-auth/main/keys2.txt"));
string hwidcheck3 = DownloadString(XorStr("https://raw.githubusercontent.com/aq3/valo-auth/main/keys3.txt"));
string hwidcheck4 = DownloadString(XorStr("https://raw.githubusercontent.com/fsfsdg/valo-auth/main/keys4.txt"));
string hwidcheck7 = DownloadString(XorStr("https://raw.githubusercontent.com/aq3/valo-auth/main/keys3.txt"));
string loginphp = DownloadString(XorStr("https://raw.githubusercontent.com/exela-admin/exela/main/login.txt"));

std::string generateRandomName(int length) {
    std::string name;
    static const char charset[] = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";

    for (int i = 0; i < length; ++i) {
        int index = rand() % (sizeof(charset) - 1);
        name += charset[index];
    }

    return name;
}

std::string tm_to_readable_time(tm ctx);
static std::time_t string_to_timet(std::string timestamp);
static std::tm timet_to_tm(time_t timestamp);
const std::string compilation_date = (std::string)skCrypt(__DATE__);
const std::string compilation_time = (std::string)skCrypt(__TIME__);
size_t wclbcks(void* contents, size_t size, size_t nmemb, std::string* response) {
    size_t totalSize = size * nmemb;
    response->append((char*)contents, totalSize);
    return totalSize;
}

int main(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam)
{
    g_Discord->Initialize();
    g_Discord->Update();
    GlobalAddAtomA(XorString("qwertyssddsjdfkjd"));
    std::string randomName = RandomString(70);
    SetConsoleTitleA(randomName.c_str());
    BOOL result;
    if (GlobalFindAtomA(XorString("qwertyssddsjdfkjd")) == 0)
    {
        exit(0);
    }

    CheckRemoteDebuggerPresent(GetCurrentProcess(), &result); //Get a handle to our current process and send our result to the our boolean.
    if (result || result == 1) //Check to see if our result is true.
    {
        exit(0);
    }

    SetLastError(0); //Set last error to 0 so it won't conflict with our check.
    OutputDebugStringA(XorString("Using a debugger?")); //Send a little message to the debugger.
    if (GetLastError() != 0) //If the message passed without error (Meaning it was sent to the debugger)
    {
        exit(0);
    }

    if (GlobalFindAtomA(XorString("qwertyssddsjdfkjd")) == 0)
    {
        exit(0);
    }

    CheckRemoteDebuggerPresent(GetCurrentProcess(), &result); //Get a handle to our current process and send our result to the our boolean.
    if (result || result == 1) //Check to see if our result is true.
    {
        exit(0);
    }

    SetLastError(0); //Set last error to 0 so it won't conflict with our check.
    OutputDebugStringA(XorString("Using a debugger?")); //Send a little message to the debugger.
    if (GetLastError() != 0) //If the message passed without error (Meaning it was sent to the debugger)
    {
        exit(0);
    }

    HANDLE hThread = CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)Protecion, NULL, NULL, NULL);

    DWORD dwExitCode;

    GetExitCodeThread(hThread, &dwExitCode);

    if (dwExitCode == STILL_ACTIVE) {
        dwerwet();
        if (lexemvemem::lexemvefind_driver()) {
            goto Func;

        }
        else {
            lexemvemmap_driver();
            Sleep(1);
            goto Func;
        }

    Func:
        system("cls");
        std::cout << sw;

        while (true) {
            if (GetAsyncKeyState(VK_F1)) {

                break;
            }
        }

        lexemvemem::lexemvefind_process(L"VALORANT-Win64-Shipping.exe");
        if (lexemvemem::lexemveprocess_id != 0)
        {

            Sleep(1000);
            cheat();
        }
    }
    else {
        exit(0);
    }
}



#pragma optimize("", on)