#include "OpcodeMgr.h"
#include <wtypes.h>
#include <psapi.h>
#include <Shlwapi.h>
#include <cstdio>
#include <io.h>
#include <iostream>
#include <fstream>
#include <algorithm>
#include <regex>
#include <iomanip>

void OpcodeMgr::Initialize()
{
    serverOpcodeTable = new OpcodeTable();
    clientOpcodeTable = new OpcodeTable();

    m_showKnownOpcodes = true;
    m_showClientOpcodes = true;
    m_showServerOpcodes = true;
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

    ss << " 0x" << std::hex << std::uppercase << std::setfill('0') << std::setw(4) << opcode << std::nouppercase << " (" << std::dec << opcode << ")]";
    return ss.str();
}

void OpcodeMgr::ValidateAndSetOpcode(const std::string& name, unsigned int opcodeNumber)
{
    if (opcodeNumber == 0xBADD || opcodeNumber == 0x0000)
        return;

    OpcodeTable* opcodeTable;
    if (name.find("CMSG")  != std::string::npos)
        opcodeTable = clientOpcodeTable;
    else if (name.find("SMSG")  != std::string::npos)
        opcodeTable = serverOpcodeTable;
    else opcodeTable = clientOpcodeTable;

    if (OpcodeHandler* handler = opcodeTable->GetOpcodeHandler(opcodeNumber))
    {
        printf("Tried to override handler of %s with %s (opcode 0x%04x)\n", handler->Name.c_str(), name.c_str(), opcodeNumber);
        return;
    }

    opcodeTable->CreateOpcodeHandler(opcodeNumber, name);
}

void OpcodeMgr::LoadOpcodeFile(const HINSTANCE moduleHandle)
{
    char dllPath[MAX_PATH];
    char filePath[MAX_PATH];
    std::ifstream opcodeFile;

    GetModuleFileNameA((HMODULE)moduleHandle, dllPath, MAX_PATH);
    // removes the DLL name from the path
    PathRemoveFileSpecA(dllPath);

    _snprintf_s(filePath, MAX_PATH, "%s\\Opcodes.h", dllPath);
    opcodeFile.open(filePath);

    if (!opcodeFile)
    {
        opcodeFile.close();
        opcodeFile.clear();

        _snprintf_s(filePath, MAX_PATH, "%s\\Opcodes.cpp", dllPath);
        opcodeFile.open(filePath);
    }


    if (!opcodeFile)
    {
        printf("Loaded 0 opcodes, file doesn't exist!\n");
        return;
    }

    printf("Opcodes path: %s\n\n", filePath);

    std::string line;
    std::regex opcodereg("MSG_.*(=|,)0x");
    while(std::getline(opcodeFile, line))
    {
        line.erase(std::remove_if(line.begin(), line.end(), isspace), line.end());
        // make sure the line is an opcode
        if (!std::regex_search(line.c_str(), opcodereg))
            continue;

        std::string func = "";
        if (line.find("=0x") == std::string::npos)
        {
            func = "DEFINE_OPCODE_HANDLER(";

            if(line.find(func) == std::string::npos)
                continue;
        }

        std::string opcode = line.substr(func.length(), line.find("0x") - func.length() - 1);
        long opcodeNumber = strtol(line.substr(line.find("0x"), 6).c_str(), NULL, 0);

        if (opcodeNumber > 0xFFFF || opcodeNumber < 0)
            continue;

        ValidateAndSetOpcode(opcode, opcodeNumber);
    }

    printf("Loaded %u SMSG opcodes\n", GetNumServerOpcodes());
    printf("Loaded %u CMSG opcodes\n\n", GetNumCliOpcodes());
}

bool OpcodeMgr::IsBlocked(unsigned int opcode, bool serverOpcode)
{
    unsigned short type = serverOpcode ? 1 : 0;
    OpcodeSet::const_iterator itr = m_blockedOpcodes[type].find(opcode);
    if (itr != m_blockedOpcodes[type].end())
        return true;

    return false;
}

bool OpcodeMgr::ShouldShowOpcode(unsigned int opcode, unsigned int packetType)
{
    if (HasExclusive())
    {
        if (!IsExclusive(opcode, packetType != CMSG))
            return false;
    }
    else
    {
        if (!ShowOpcodeType(packetType))
            return false;

        if (!ShowKnownOpcodes() && IsKnownOpcode(opcode, packetType != CMSG))
            return false;

        if (IsBlocked(opcode, packetType != CMSG))
            return false;
    }

    return true;
}

bool OpcodeMgr::ShowOpcodeType(unsigned int type)
{
    switch (type)
    {
        case CMSG: return m_showClientOpcodes;
        case SMSG: return m_showServerOpcodes;
        default:   return true;
    }
}

void OpcodeMgr::UnBlockAll(unsigned int type)
{
    for (OpcodeSet::const_iterator itr = m_blockedOpcodes[type].begin(); itr != m_blockedOpcodes[type].end(); ++itr)
        printf("Opcode %s will now be shown\n", GetOpcodeNameForLogging(*itr, type ? true : false).c_str());

    m_blockedOpcodes[type].clear();
}

void OpcodeMgr::ClearExclusive(unsigned short type)
{
    for (OpcodeSet::const_iterator itr = m_exclusiveOpcodes[type].begin(); itr != m_exclusiveOpcodes[type].end(); ++itr)
        printf("Opcode %s is no longer exclusive\n", GetOpcodeNameForLogging(*itr, type ? true : false).c_str());

    m_exclusiveOpcodes[type].clear();
}

bool OpcodeMgr::IsExclusive(unsigned int opcode, unsigned short type)
{
    OpcodeSet::const_iterator itr = m_exclusiveOpcodes[type].find(opcode);
    if (itr != m_exclusiveOpcodes[type].end())
        return true;

    return false;
}