#include "Injector.h"
#include "OpcodeMgr.h"

std::atomic<bool> Injector::m_stopEvent(false);

void Injector::ProcessCliCommands()
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

bool Injector::ParseCommand(char* command[], int numargs)
{
    char* param = NULL;
    for (int i = 0; i < numargs; ++i)
    {
        if (strcmp(command[i], "quit") == 0)
        {
            Injector::Stop();
            printf("Detaching...\n");
            return true;
        }
        else if (strcmp(command[i], "block") == 0)
        {
            param = command[++i];
            if (param == "")
                return false;

            int opcode = 0;

            std::string param_str(param);
            if (param_str.find("0x") != std::string::npos)
                opcode = (int)strtol(param, NULL, 0);
            else opcode = atoi(param);

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

            sOpcodeMgr->BlockOpcode(opcode, serverOpcode ? 1 : 0);

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

                sOpcodeMgr->UnBlockAll(serverOpcode ? 1 : 0);
                return true;
            }

            std::string param_str(param);
            if (param_str.find("0x") != std::string::npos)
                opcode = (int)strtol(param, NULL, 0);
            else opcode = atoi(param);

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

            sOpcodeMgr->UnBlockOpcode(opcode, serverOpcode ? 1 : 0);

            printf("Opcode %s will now be shown\n", sOpcodeMgr->GetOpcodeNameForLogging(opcode, serverOpcode).c_str());
            return true;
        }
        else if (strcmp(command[i], "toggleknown") == 0)
        {
            sOpcodeMgr->ToggleKnownOpcodes();
            printf("Show known opcodes: %s\n", sOpcodeMgr->ShowKnownOpcodes() ? "ON": "OFF");
            return true;
        }
        else if (strcmp(command[i], "help") == 0)
        {
            printf("|---------------------------------------------------------------------------------------|\n");
            printf("| COMMAND     | PARAMS                 | DESCRIPTION                                    |\n");
            printf("|---------------------------------------------------------------------------------------|\n");
            printf("| quit        |                        | unhook the injector                            |\n");
            printf("| block       | #opcode true/false     | block #opcode type (true=server, false=client) |\n");
            printf("| unblock     | #opcode/all true/false | unblock #opcode (or all) of type ^             |\n");
            printf("| toggleknown |                        | toggle showing/sniffing known opcodes          |\n");
            printf("| help        |                        | show commands                                  |\n");
            printf("|---------------------------------------------------------------------------------------|\n");
            return true;
        }
    }

    printf("Invalid Command use 'help' for list of commands\n");
    return true;
}