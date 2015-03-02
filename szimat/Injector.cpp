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
        }
        else if (strcmp(command[i], "block") == 0)
        {
            param = command[++i];
            if (!param)
                return false;

            int opcode = 0;

            std::string param_str(param);
            if (param_str.find("0x") != std::string::npos)
                opcode = (int)strtol(param, NULL, 0);
            else opcode = atoi(param);

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

            printf("Opcode %s will no longer be shown\n", sOpcodeMgr->GetOpcodeNameForLogging(opcode, serverOpcode));
        }
        else if (strcmp(command[i], "unblock") == 0)
        {
            param = command[++i];
            if (!param)
                return false;

            int opcode = 0;

            std::string param_str(param);
            if (param_str.find("0x") != std::string::npos)
                opcode = (int)strtol(param, NULL, 0);
            else opcode = atoi(param);

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

            printf("Opcode %s will now be shown\n", sOpcodeMgr->GetOpcodeNameForLogging(opcode, serverOpcode));
        }
        else if (strcmp(command[i], "toggleknown") == 0)
        {
            sOpcodeMgr->ToggleKnownOpcodes();
            printf("Show known opcodes: %s\n", sOpcodeMgr->ShowKnownOpcodes() ? "ON": "OFF");
        }
    }

    return true;
}