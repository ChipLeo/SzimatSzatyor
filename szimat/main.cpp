/*
* This file is part of SzimatSzatyor.
*
* SzimatSzatyor is free software: you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation, either version 3 of the License, or
* (at your option) any later version.

* SzimatSzatyor is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details.

* You should have received a copy of the GNU General Public License
* along with SzimatSzatyor.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "OpcodeMgr.h"
#include "Sniffer.h"
#include "CliRunnable.h"
#include <thread>
#include <Windows.h>
#include <Shlwapi.h>
#include <cstdio>
#include <ctime>
#include "ConsoleManager.h"
#include "HookManager.h"
#include <mutex>
#include "Sniffer.h"

// static member initilization
volatile bool* ConsoleManager::_sniffingLoopCondition = NULL;

// needed to correctly shutdown the sniffer
HINSTANCE instanceDLL = NULL;
// true when a SIGINT occured
volatile bool isSigIntOccured = false;

// global access to the build number
WORD buildNumber = 0;
HookEntry hookEntry;

// this function will be called when send called in the client
// client has thiscall calling convention
// that means: this pointer is passed via the ECX register
// fastcall convention means that the first 2 parameters is passed
// via ECX and EDX registers so the first param will be the this pointer and
// the second one is just a dummy (not used)
DWORD __fastcall SendHook(void* thisPTR, void*, CDataStore*, void*);

typedef DWORD(__thiscall *SendProto)(void*, void*, void*);

// address of WoW's send function
DWORD sendAddress = 0;
// global storage for the "the hooking" machine code which 
// hooks client's send function
BYTE machineCodeHookSend[JMP_INSTRUCTION_SIZE] = { 0 };
// global storage which stores the
// untouched first 5 bytes machine code from the client's send function
BYTE defaultMachineCodeSend[JMP_INSTRUCTION_SIZE] = { 0 };

// this function will be called when recv called in the client
DWORD __fastcall RecvHook3(void* thisPTR, void* dummy, void* param1, CDataStore* dataStore);
DWORD __fastcall RecvHook4(void* thisPTR, void* dummy, void* param1, CDataStore* dataStore, void* param3);
DWORD __fastcall RecvHook5(void* thisPTR, void* dummy, void* param1, void* param2, CDataStore* dataStore, void* param4);

typedef DWORD(__thiscall *RecvProto3)(void*, void*, void*);
typedef DWORD(__thiscall *RecvProto4)(void*, void*, void*, void*);
typedef DWORD(__thiscall *RecvProto5)(void*, void*, void*, void*, void*);

// address of WoW's recv function
DWORD recvAddress = 0;
// global storage for the "the hooking" machine code which
// hooks client's recv function
BYTE machineCodeHookRecv[JMP_INSTRUCTION_SIZE] = { 0 };
// global storage which stores the
// untouched first 5 bytes machine code from the client's recv function
BYTE defaultMachineCodeRecv[JMP_INSTRUCTION_SIZE] = { 0 };

// these are false if "hook functions" don't called yet
// and they are true if already called at least once
bool sendInitialized = false;
bool recvInitialized = false;

// basically this method controls what the sniffer should do
// pretty much like a "main method"
DWORD MainThreadControl(LPVOID /* param */);

// entry point of the DLL
BOOL APIENTRY DllMain(HINSTANCE instDLL, DWORD reason, LPVOID /* reserved */)
{
    // called when the DLL is being loaded into the
    // virtual address space of the current process (where to be injected)
    if (reason == DLL_PROCESS_ATTACH)
    {
        instanceDLL = instDLL;
        // disables thread notifications (DLL_THREAD_ATTACH, DLL_THREAD_DETACH)
        DisableThreadLibraryCalls(instDLL);

        // creates a thread to execute within the
        // virtual address space of the calling process (WoW)
        CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)&MainThreadControl, NULL, 0, NULL);
    }
    // the DLL is being unloaded
    else if (reason == DLL_PROCESS_DETACH)
    {
        // close the dump file
        sSniffer->CloseFileDump();

        // deallocates the console
        ConsoleManager::Destroy();
    }
    return TRUE;
}

DWORD MainThreadControl(LPVOID /* param */)
{
    // creates the console
    if (!ConsoleManager::Create(&isSigIntOccured))
        FreeLibraryAndExitThread((HMODULE)instanceDLL, 0);

    // some info
    printf("Welcome to SzimatSzatyor, a WoW injector sniffer.\n");
    printf("SzimatSzatyor is distributed under the GNU GPLv3 license.\n");
    printf("Source code is available at: ");
    printf("http://github.com/Anubisss/SzimatSzatyor\n\n");

    printf("Type quit to stop sniffing ");
    printf("Note: you can simply re-attach the sniffer without ");
    printf("restarting the WoW.\n\n");

    // gets the build number
    buildNumber = GetBuildNumberFromProcess();
    // error occured
    if (!buildNumber)
    {
        printf("Can't determine build number.\n\n");
        system("pause");
        FreeLibraryAndExitThread((HMODULE)instanceDLL, 0);
    }
    printf("Detected build number: %hu\n", buildNumber);

    // checks this build is supported or not
    if (!GetOffsets(instanceDLL, buildNumber, &hookEntry))
    {
        printf("ERROR: This build number is not supported.\n\n");
        system("pause");
        FreeLibraryAndExitThread((HMODULE)instanceDLL, 0);
    }

    // get the base address of the current process
    DWORD baseAddress = (DWORD)GetModuleHandle(NULL);

    DWORD localeAddress = hookEntry.locale;
    std::string locale;

    if (localeAddress)
    {
        for (int i = 3; i >= 0; --i)
            locale += *(char*)(baseAddress + (localeAddress + i));

        printf("Detected client locale: %s\n", locale.c_str());
    }
    else
    {
        printf("Locale NOT detected (incorrect locale offset?)\n");
        locale = "enUnk";
    }

    // gets where is the DLL which injected into the client
    char dllPath[MAX_PATH] = { 0 };
    DWORD dllPathSize = GetModuleFileName((HMODULE)instanceDLL, dllPath, MAX_PATH);
    if (!dllPathSize)
    {
        printf("\nERROR: Can't get the injected DLL's location, ");
        printf("ErrorCode: %u\n\n", GetLastError());
        system("pause");
        FreeLibraryAndExitThread((HMODULE)instanceDLL, 0);
    }
    printf("\nDLL path: %s\n", dllPath);

    sSniffer->SetSnifferInfo(std::string(dllPath), locale, buildNumber);
    sOpcodeMgr->Initialize();
    sOpcodeMgr->LoadOpcodeFile(instanceDLL); // must be called after Initialize()

    // gets address of NetClient::Send2
    sendAddress = baseAddress + hookEntry.send_2;
    // hooks client's send function
    HookManager::Hook(sendAddress, (DWORD)SendHook, machineCodeHookSend, defaultMachineCodeSend);
    printf("Send is hooked.\n");

    // gets address of NetClient::ProcessMessage
    recvAddress = baseAddress + hookEntry.receive;
    // hooks client's recv function

    if (buildNumber < 8606)
        HookManager::Hook(recvAddress, (DWORD)RecvHook3, machineCodeHookRecv, defaultMachineCodeRecv);
    else if (buildNumber < 19000)
        HookManager::Hook(recvAddress, (DWORD)RecvHook4, machineCodeHookRecv, defaultMachineCodeRecv);
    else
        HookManager::Hook(recvAddress, (DWORD)RecvHook5, machineCodeHookRecv, defaultMachineCodeRecv);

    printf("Recv is hooked.\n");

    // Launch CliRunnable thread
    std::thread* cliThread = new std::thread(CliThread);
    sSniffer->SetCliThread(cliThread);

    // loops until SIGINT (CTRL-C) occurs
    while (!isSigIntOccured && !Sniffer::IsStopped())
    {
        sSniffer->ProcessCliCommands();
        Sleep(50); // sleeps 50 ms to be nice
    }

    sSniffer->ShutdownCLIThread();
    sOpcodeMgr->ShutDown();

    // unhooks functions
    HookManager::UnHook(sendAddress, defaultMachineCodeSend);
    HookManager::UnHook(recvAddress, defaultMachineCodeRecv);

    printf("Detached!\n");

    // shutdowns the sniffer
    // note: after that DLL's entry point will be called with
    // reason DLL_PROCESS_DETACH
    FreeLibraryAndExitThread((HMODULE)instanceDLL, 0);
    return 0;
}

void Sniffer::ShutdownCLIThread()
{
    if (m_cliThread != nullptr)
    {
        // First try to cancel any I/O in the CLI thread
        if (!CancelSynchronousIo(m_cliThread->native_handle()))
        {
            // if CancelSynchronousIo() fails, print the error and try with old way
            DWORD errorCode = GetLastError();
            LPSTR errorBuffer;

            DWORD formatReturnCode = FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_IGNORE_INSERTS,
                                                   nullptr, errorCode, 0, (LPTSTR)&errorBuffer, 0, nullptr);
            if (!formatReturnCode)
                errorBuffer = "Unknown error";

            LocalFree(errorBuffer);

            // send keyboard input to safely unblock the CLI thread
            INPUT_RECORD b[4];
            HANDLE hStdIn = GetStdHandle(STD_INPUT_HANDLE);
            b[0].EventType = KEY_EVENT;
            b[0].Event.KeyEvent.bKeyDown = TRUE;
            b[0].Event.KeyEvent.uChar.AsciiChar = 'X';
            b[0].Event.KeyEvent.wVirtualKeyCode = 'X';
            b[0].Event.KeyEvent.wRepeatCount = 1;

            b[1].EventType = KEY_EVENT;
            b[1].Event.KeyEvent.bKeyDown = FALSE;
            b[1].Event.KeyEvent.uChar.AsciiChar = 'X';
            b[1].Event.KeyEvent.wVirtualKeyCode = 'X';
            b[1].Event.KeyEvent.wRepeatCount = 1;

            b[2].EventType = KEY_EVENT;
            b[2].Event.KeyEvent.bKeyDown = TRUE;
            b[2].Event.KeyEvent.dwControlKeyState = 0;
            b[2].Event.KeyEvent.uChar.AsciiChar = '\r';
            b[2].Event.KeyEvent.wVirtualKeyCode = VK_RETURN;
            b[2].Event.KeyEvent.wRepeatCount = 1;
            b[2].Event.KeyEvent.wVirtualScanCode = 0x1c;

            b[3].EventType = KEY_EVENT;
            b[3].Event.KeyEvent.bKeyDown = FALSE;
            b[3].Event.KeyEvent.dwControlKeyState = 0;
            b[3].Event.KeyEvent.uChar.AsciiChar = '\r';
            b[3].Event.KeyEvent.wVirtualKeyCode = VK_RETURN;
            b[3].Event.KeyEvent.wVirtualScanCode = 0x1c;
            b[3].Event.KeyEvent.wRepeatCount = 1;
            DWORD numb;
            WriteConsoleInput(hStdIn, b, 4, &numb);
        }

        m_cliThread->join();
        delete m_cliThread;
    }
}

DWORD __fastcall SendHook(void* thisPTR, void* dummy , CDataStore* dataStore, void* param2)
{
    // dumps the packet
    sSniffer->DumpPacket(PacketInfo(CMSG, (DWORD)param2, 4, dataStore));

    // unhooks the send function
    HookManager::UnHook(sendAddress, defaultMachineCodeSend);

    // now let's call client's function
    // so it can send the packet to the server (connection, CDataStore*, 2)
    DWORD returnValue = SendProto(sendAddress)(thisPTR, dataStore, param2);

    // hooks again to catch the next outgoing packets also
    HookManager::ReHook(sendAddress, machineCodeHookSend);

    if (!sendInitialized)
    {
        printf("Send hook is working.\n");
        sendInitialized = true;
    }

    return 0;
}

#pragma region RecvHook

DWORD __fastcall RecvHook3(void* thisPTR, void* dummy, void* param1, CDataStore* dataStore)
{
    // packet dump
    sSniffer->DumpPacket(PacketInfo(SMSG, 0, 2, dataStore));

    // unhooks the recv function
    HookManager::UnHook(recvAddress, defaultMachineCodeRecv);

    // calls client's function so it can processes the packet
    DWORD returnValue = RecvProto3(recvAddress)(thisPTR, param1, dataStore);

    // hooks again to catch the next incoming packets also
    HookManager::ReHook(recvAddress, machineCodeHookRecv);

    if (!recvInitialized)
    {
        printf("Recv hook3 is working.\n");
        recvInitialized = true;
    }

    return returnValue;
}

DWORD __fastcall RecvHook4(void* thisPTR, void* dummy, void* param1, CDataStore* dataStore, void* param3)
{
    WORD opcodeSize = buildNumber <= WOW_MOP_16135 ? 2 : 4;
    // packet dump
    sSniffer->DumpPacket(PacketInfo(SMSG, (DWORD)param3, opcodeSize, dataStore));

    // unhooks the recv function
    HookManager::UnHook(recvAddress, defaultMachineCodeRecv);

    // calls client's function so it can processes the packet
    DWORD returnValue = RecvProto4(recvAddress)(thisPTR, param1, dataStore, param3);

    // hooks again to catch the next incoming packets also
    HookManager::ReHook(recvAddress, machineCodeHookRecv);

    if (!recvInitialized)
    {
        printf("Recv hook4 is working.\n");
        recvInitialized = true;
    }

    return returnValue;
}

DWORD __fastcall RecvHook5(void* thisPTR, void* dummy, void* param1, void* param2, CDataStore* dataStore, void* param4)
{
    // packet dump
    sSniffer->DumpPacket(PacketInfo(SMSG, (DWORD)param4, 4, dataStore));

    // unhooks the recv function
    HookManager::UnHook(recvAddress, defaultMachineCodeRecv);

    // calls client's function so it can processes the packet
    DWORD returnValue = RecvProto5(recvAddress)(thisPTR, param1, param2, dataStore, param4);

    // hooks again to catch the next incoming packets also
    HookManager::ReHook(recvAddress, machineCodeHookRecv);

    if (!recvInitialized)
    {
        printf("Recv hook5 is working.\n");
        recvInitialized = true;
    }

    return returnValue;
}

#pragma endregion
