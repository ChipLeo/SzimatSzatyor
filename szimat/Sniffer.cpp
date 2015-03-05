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
            if (param == "")
                return false;

            int opcode = 0;

            opcode = GetOpcodeFromParam(param);
            if (!opcode)
                return false;

            param = command[++i];
            if (param == "")
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
            if (param == "")
                return false;

            int opcode = 0;

            if (strcmp(param, "all") == 0)
            {
                param = command[++i];
                if (param == "")
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
            if (param == "")
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
            if (param == "")
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
                if (param == "")
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
            if (param == "")
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
            printf("| quit        |                                      | unhook the Sniffer                            |\n");
            printf("| block       | #opcode true/false                   | block #opcode type (true=server, false=client) |\n");
            printf("| unblock     | #opcode/all true/false               | unblock #opcode (or all) of type ^             |\n");
            printf("| toggleknown |                                      | toggle showing/sniffing known opcodes          |\n");
            printf("| exclusive   | add/del/clear #opcode/all true/false | add/remove/clear exclusive opcodes of type     |\n");
            printf("| help        |                                      | show commands                                  |\n");
            printf("|-----------------------------------------------------------------------------------------------------|\n");
            return true;
        }
    }

    printf("Invalid Command use 'help' for list of commands\n");
    return true;
}

unsigned int Sniffer::GetOpcodeFromParam(char* param)
{
    if (param == "")
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