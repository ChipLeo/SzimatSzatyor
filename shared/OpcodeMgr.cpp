#include "OpcodeMgr.h"

void OpcodeMgr::Initialize()
{
    serverOpcodeTable = new OpcodeTable();
    serverOpcodeTable->InitializeServerTable();

    clientOpcodeTable = new OpcodeTable();
    clientOpcodeTable->InitializeClientTable();

    m_showKnownOpcodes = true;
}

void OpcodeMgr::ShutDown()
{
    delete serverOpcodeTable;
    delete clientOpcodeTable;
}

bool OpcodeMgr::IsKnownOpcode(unsigned int opcode, bool isServerOpcode)
{
    OpcodeTable* table = isServerOpcode ? serverOpcodeTable : clientOpcodeTable;

    if (table->GetOpcodeHandler(opcode))
        return true;

    return false;
}

/// Lookup opcode name for human understandable logging
std::string OpcodeMgr::GetOpcodeNameForLogging(unsigned int opcode, bool isServerOpcode)
{
    OpcodeTable* table = isServerOpcode ? serverOpcodeTable : clientOpcodeTable;

    std::ostringstream ss;
    ss << '[';

    if (OpcodeHandler const* handler = table->GetOpcodeHandler(opcode))
    {
        ss << handler->Name;
        opcode = handler->OpcodeNumber;
    }
    else ss << (isServerOpcode ? "SMSG" : "CMSG") << "_UNKNOWN_OPCODE";

    ss << " 0x" << std::hex << std::uppercase << opcode << std::nouppercase << " (" << std::dec << opcode << ")]";
    return ss.str();
}