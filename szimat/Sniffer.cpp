#include "Sniffer.h"
#include "OpcodeMgr.h"

std::atomic<bool> Sniffer::m_stopEvent(false);

void Sniffer::ProcessCliCommands()
{
    CliCommandHolder::Print* zprint = NULL;
    void* callbackArg = NULL;
    CliCommandHolder* command = NULL;
    while (cliCmdQueue.next(command))
    {
        zprint = command->m_print;
        callbackArg = command->m_callbackArg;

        if (!ParseCommand(command->m_command, command->m_numargs))
            printf("Invalid parameter(s)\n");

        if (command->m_commandFinished)
            command->m_commandFinished();
        delete command;
    }
}

bool Sniffer::ParseCommand(char* command[], int numargs)
{
    char* param = NULL;
    for (int i = 0; i < numargs; ++i)
    {
        if (strcmp(command[i], "quit") == 0)
        {
            Sniffer::Stop();
            printf("Detaching...\n");
            return true;
        }
        else if (strcmp(command[i], "block") == 0)
        {
            param = command[++i];
            if (!param)
                return false;

            int opcode = 0;

            opcode = GetOpcodeFromParam(param);
            if (!opcode)
                return false;

            param = command[++i];
            if (!param)
                return false;

            bool serverOpcode;
            if (strcmp(param, "true") == 0)
                serverOpcode = true;
            else if (strcmp(param, "false") == 0)
                serverOpcode = false;
            else
                return false;

            sOpcodeMgr->BlockOpcode(opcode, serverOpcode);

            printf("Opcode %s will no longer be shown\n", sOpcodeMgr->GetOpcodeNameForLogging(opcode, serverOpcode).c_str());
            return true;
        }
        else if (strcmp(command[i], "unblock") == 0)
        {
            param = command[++i];
            if (!param)
                return false;

            int opcode = 0;

            if (strcmp(param, "all") == 0)
            {
                param = command[++i];
                if (!param)
                {
                    sOpcodeMgr->UnBlockAll(0);
                    sOpcodeMgr->UnBlockAll(1);
                    return true;
                }

                bool serverOpcode;
                if (strcmp(param, "true") == 0)
                    serverOpcode = true;
                else if (strcmp(param, "false") == 0)
                    serverOpcode = false;
                else
                    return false;

                sOpcodeMgr->UnBlockAll(serverOpcode);
                return true;
            }

            opcode = GetOpcodeFromParam(param);
            if (!opcode)
                return false;

            param = command[++i];
            if (!param)
                return false;

            bool serverOpcode;
            if (strcmp(param, "true") == 0)
                serverOpcode = true;
            else if (strcmp(param, "false") == 0)
                serverOpcode = false;
            else
                return false;

            sOpcodeMgr->UnBlockOpcode(opcode, serverOpcode);

            printf("Opcode %s will now be shown\n", sOpcodeMgr->GetOpcodeNameForLogging(opcode, serverOpcode).c_str());
            return true;
        }
        else if (strcmp(command[i], "toggleknown") == 0)
        {
            sOpcodeMgr->ToggleKnownOpcodes();
            printf("Show known opcodes: %s\n", sOpcodeMgr->ShowKnownOpcodes() ? "ON": "OFF");
            return true;
        }
        else if (strcmp(command[i], "exclusive") == 0)
        {
            param = command[++i];
            if (!param)
                return false;

            bool add, clear = false;
            if (strcmp(param, "add") == 0)
                add = true;
            else if (strcmp(param, "del") == 0 || strcmp(param, "delete") == 0)
                add = false;
            else if (strcmp(param, "clear") == 0)
                clear = true;
            else
                return false;

            if (clear)
            {
                param = command[++i];
                if (!param)
                {
                    sOpcodeMgr->ClearExclusive(true);
                    sOpcodeMgr->ClearExclusive(false);
                    return true;
                }

                bool serverOpcode;
                if (strcmp(param, "true") == 0)
                    serverOpcode = true;
                else if (strcmp(param, "false") == 0)
                    serverOpcode = false;
                else
                    return false;

                sOpcodeMgr->ClearExclusive(serverOpcode);
                return true;
            }

            param = command[++i];
            unsigned int opcode;
            opcode = GetOpcodeFromParam(param);
            if (!opcode)
                return false;

            param = command[++i];
            if (!param)
                return false;

            bool serverOpcode;
            if (strcmp(param, "true") == 0)
                serverOpcode = true;
            else if (strcmp(param, "false") == 0)
                serverOpcode = false;
            else
                return false;

            printf("Opcode %s is %s exclusive\n", sOpcodeMgr->GetOpcodeNameForLogging(opcode, serverOpcode).c_str(), add ? "now" : "no longer");

            if (add)
                sOpcodeMgr->AddExclusiveOpcode(opcode, serverOpcode);
            else sOpcodeMgr->DelExclusiveOpcode(opcode, serverOpcode);

            return true;
        }
        else if (strcmp(command[i], "help") == 0)
        {
            printf("|-----------------------------------------------------------------------------------------------------|\n");
            printf("| COMMAND     | PARAMS                               | DESCRIPTION                                    |\n");
            printf("|-----------------------------------------------------------------------------------------------------|\n");
            printf("| quit        |                                      | Unhook the sniffer                             |\n");
            printf("| block       | #Opcode true/false                   | Block #opcode type (true=server, false=client) |\n");
            printf("| unblock     | #Opcode/all true/false               | Unblock #opcode (or all) of type ^             |\n");
            printf("| toggleknown |                                      | Toggle showing/sniffing known opcodes          |\n");
            printf("| exclusive   | Add/del/clear #opcode/all true/false | Add/remove/clear exclusive opcodes of type     |\n");
            printf("| help        |                                      | Show commands                                  |\n");
            printf("|-----------------------------------------------------------------------------------------------------|\n");
            return true;
        }
    }

    printf("Invalid command. Type 'help' for list of commands\n");
    return true;
}

unsigned int Sniffer::GetOpcodeFromParam(char* param)
{
    if (!param)
        return 0;

    long opcode;

    std::string param_str(param);
    if (param_str.find("0x") != std::string::npos)
         opcode = strtol(param, NULL, 0);
    else opcode = atol(param);

    // 0x1FC9 current highest opcode 6.1.0 19702
    if (opcode > 0x1FC9 || opcode < 0)
        return 0;

    return opcode;
}

void Sniffer::DumpPacket(PacketInfo const& info)
{
    DWORD packetOpcode = info.opcodeSize == 4
        ? *(DWORD*)info.dataStore->buffer
        : *(WORD*)info.dataStore->buffer;

    if (!sOpcodeMgr->IsExclusive(packetOpcode, info.packetType != CMSG))
        return;

    if (!sOpcodeMgr->ShowKnownOpcodes() && sOpcodeMgr->IsKnownOpcode(packetOpcode, info.packetType != CMSG))
        return;

    if (sOpcodeMgr->IsBlocked(packetOpcode, info.packetType != CMSG))
        return;

    dumpMutex.lock();
    // gets the time
    time_t rawTime;
    time(&rawTime);

    DWORD tickCount = GetTickCount();

    DWORD optionalHeaderLength = 0;

    if (!fileDump)
    {
        tm* date = localtime(&rawTime);
        // basic file name format:
        char fileName[MAX_PATH];
        // removes the DLL name from the path
        PathRemoveFileSpec(const_cast<char *>(dllPath.c_str()));
        // fills the basic file name format
        _snprintf(fileName, MAX_PATH,
            "wowsniff_%s_%u_%d-%02d-%02d_%02d-%02d-%02d.pkt",
            locale.c_str(), buildNumber,
            date->tm_year + 1900,
            date->tm_mon + 1,
            date->tm_mday,
            date->tm_hour,
            date->tm_min,
            date->tm_sec);

        // some info
        printf("Sniff dump: %s\n\n", fileName);

        char fullFileName[MAX_PATH];
        _snprintf(fullFileName, MAX_PATH, "%s\\%s", dllPath.c_str(), fileName);

        WORD pkt_version    = PKT_VERSION;
        BYTE sniffer_id     = SNIFFER_ID;
        BYTE sessionKey[40] = { 0 };

        fileDump = fopen(fullFileName, "wb");
        // PKT 3.1 header
        fwrite("PKT",                           3, 1, fileDump);  // magic
        fwrite((WORD*)&pkt_version,             2, 1, fileDump);  // major.minor version
        fwrite((BYTE*)&sniffer_id,              1, 1, fileDump);  // sniffer id
        fwrite((DWORD*)&buildNumber,            4, 1, fileDump);  // client build
        fwrite(locale.c_str(),                  4, 1, fileDump);  // client lang
        fwrite(sessionKey,                     40, 1, fileDump);  // session key
        fwrite((DWORD*)&rawTime,                4, 1, fileDump);  // started time
        fwrite((DWORD*)&tickCount,              4, 1, fileDump);  // started tick's
        fwrite((DWORD*)&optionalHeaderLength,   4, 1, fileDump);  // opional header length

        fflush(fileDump);
    }

    BYTE* packetData     = info.dataStore->buffer + info.opcodeSize;
    DWORD packetDataSize = info.dataStore->size   - info.opcodeSize;

    fwrite((DWORD*)&info.packetType,            4, 1, fileDump);  // direction of the packet
    fwrite((DWORD*)&info.connectionId,          4, 1, fileDump);  // connection id
    fwrite((DWORD*)&tickCount,                  4, 1, fileDump);  // timestamp of the packet
    fwrite((DWORD*)&optionalHeaderLength,       4, 1, fileDump);  // connection id
    fwrite((DWORD*)&info.dataStore->size,       4, 1, fileDump);  // size of the packet + opcode lenght
    fwrite((DWORD*)&packetOpcode,               4, 1, fileDump);  // opcode

    fwrite(packetData, packetDataSize,          1, fileDump);  // data

    printf("%s Size: %u\n", sOpcodeMgr->GetOpcodeNameForLogging(packetOpcode, info.packetType != CMSG).c_str(), packetDataSize);

    fflush(fileDump);

    dumpMutex.unlock();
}
