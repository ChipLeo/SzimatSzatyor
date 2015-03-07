#include "CommandMgr.h"
#include "Sniffer.h"
#include "CommandHandler.h"
#include "OpcodeMgr.h"

Commands commandTable;

inline void AddCommand(const std::string& name, const char* help, pCommandHandler handler)
{
    commandTable[name] = new CommandHandler(name, help, handler);
}

void CommandMgr::InitCommands()
{
    AddCommand("quit", "Syntax: 'quit'\nUnhook the sniffer", &CommandMgr::HandleQuitCommand);
    AddCommand("block", "Syntax: 'block [#opcode] [true|false]' (true=server, false=client)\nBlock a specific opcode from being sniffed", &CommandMgr::HandleBlockCommand);
    AddCommand("unblock", "Syntax: 'unblock [#opcode|all] [true|false]' (true=server, false=client)\nUnblock a specific opcode (or all) from being sniffed", &CommandMgr::HandleBlockCommand);
    AddCommand("toggle", "Syntax: 'toggle [known|server|client]'\nToggle sniffing known, server, or client opcodes", &CommandMgr::HandleToggleCommand);
    AddCommand("exclusive", "Syntax: 'exclusive [add|del|clear] [#opcode|all] [true|false]'\nMake only a specific opcode(s) be sniffed", &CommandMgr::HandleExclusiveCommand);
    AddCommand("help", "Syntax: 'help', Display the list of commands", &CommandMgr::HandleHelpCommand);
}

void CommandMgr::ClearCommands()
{
    while (!commandTable.empty())
    {
        Commands::iterator itr = commandTable.begin();
        delete itr->second;
        commandTable.erase(itr);
    }
}

bool CommandMgr::HandleCommand(const std::string& command, char* args[])
{
    CommandHandler* const handler = GetCommandHandler(command);
    if (!handler)
        return false;

    if (!(this->*handler->Handler)(args))
    {
        printf("Invalid parameter(s)\n");
        printf("%s\n", handler->Help);
    }

    return true;
}

unsigned int CommandMgr::GetOpcodeFromParam(char* param)
{
    if (!param)
        return 0;

    long opcode;

    std::string param_str(param);
    if (param_str.find("0x") != std::string::npos)
         opcode = strtol(param, NULL, 0);
    else opcode = atol(param);

    if (opcode > 0xFFFF || opcode < 0)
        return 0;

    return opcode;
}

bool CommandMgr::HandleQuitCommand(char* args[])
{
    Sniffer::Stop();
    printf("Detaching...\n");
    return true;
}

bool CommandMgr::HandleBlockCommand(char* args[])
{
    int arg_n = 0;
    char* param = args[arg_n++];
    if (!param)
        return false;

    int opcode = 0;

    opcode = GetOpcodeFromParam(param);
    if (!opcode)
        return false;

    param = args[arg_n++];
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

bool CommandMgr::HandleUnblockCommand(char* args[])
{
    int arg_n = 0;
    char* param = args[arg_n++];
    if (!param)
        return false;

    int opcode = 0;

    if (strcmp(param, "all") == 0)
    {
        param = args[arg_n++];
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

    param = args[arg_n++];
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

bool CommandMgr::HandleToggleCommand(char* args[])
{
    int arg_n = 0;
    char* param = args[arg_n++];
    if (!param)
        return false;

    if (strcmp(param, "known") == 0)
    {
        sOpcodeMgr->ToggleKnownOpcodes();
        printf("Show known opcodes: %s\n", sOpcodeMgr->ShowKnownOpcodes() ? "ON" : "OFF");
        return true;
    }
    else if (strcmp(param, "client") == 0)
    {
        sOpcodeMgr->ToggleClientOpcodes();
        printf("Show client opcodes: %s\n", sOpcodeMgr->ShowOpcodeType(CMSG) ? "ON" : "OFF");
        return true;
    }
    else if (strcmp(param, "server") == 0)
    {
        sOpcodeMgr->ToggleServerOpcodes();
        printf("Show server opcodes: %s\n", sOpcodeMgr->ShowOpcodeType(SMSG) ? "ON" : "OFF");
        return true;
    }

    return false;
}

bool CommandMgr::HandleExclusiveCommand(char* args[])
{
    int arg_n = 0;
    char* param = args[arg_n++];
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
        param = args[arg_n++];
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

    param = args[arg_n++];
    unsigned int opcode;
    opcode = GetOpcodeFromParam(param);
    if (!opcode)
        return false;

    param = args[arg_n++];
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

bool CommandMgr::HandleHelpCommand(char* args[])
{
    printf("|-----------------------------------------------------------------------------------------------------|\n");
    printf("| COMMAND     | PARAMS                               | DESCRIPTION                                    |\n");
    printf("|-----------------------------------------------------------------------------------------------------|\n");
    printf("| quit        |                                      | Unhook the sniffer                             |\n");
    printf("| block       | #Opcode true/false                   | Block #opcode type (true=server, false=client) |\n");
    printf("| unblock     | #Opcode/all true/false               | Unblock #opcode (or all) of type ^             |\n");
    printf("| toggle      | known/server/client                  | Toggle showing/sniffing opcodes of type        |\n");
    printf("| exclusive   | Add/del/clear #opcode/all true/false | Add/remove/clear exclusive opcodes of type     |\n");
    printf("| help        |                                      | Show commands                                  |\n");
    printf("|-----------------------------------------------------------------------------------------------------|\n");
    return true;
}
