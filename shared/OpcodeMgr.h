#ifndef _OpcodeMgr_h__
#define _OpcodeMgr_h__

#include <xstring>
#include <ios>
#include <iosfwd>
#include <ostream>
#include <sstream>
#include <set>

#include "Opcodes.h"

class OpcodeMgr
{
    public:
        static OpcodeMgr* instance()
        {
            static OpcodeMgr instance;
            return &instance;
        }

        void Initialize();
        void ShutDown();

        bool IsKnownOpcode(unsigned int opcode, bool isServerOpcode);
        bool IsBlocked(unsigned int opcode, bool serverOpcode)
        {
            unsigned short type = serverOpcode ? 1 : 0;
            BlockedOpcodes::const_iterator itr = m_blockedOpcodes[type].find(opcode);
            if (itr != m_blockedOpcodes[type].end())
                return true;

            return false;
        }
        void BlockOpcode(unsigned int opcode, unsigned short type) { m_blockedOpcodes[type].insert(opcode); }
        void UnBlockOpcode(unsigned int opcode, unsigned short type) { m_blockedOpcodes[type].erase(opcode); }
        bool ShowKnownOpcodes() { return m_showKnownOpcodes; }
        void ToggleKnownOpcodes() { m_showKnownOpcodes = !m_showKnownOpcodes; }

        std::string GetOpcodeNameForLogging(unsigned int opcode, bool isServerOpcode);

    private:
        OpcodeMgr() { }
        ~OpcodeMgr() { }

        OpcodeTable* serverOpcodeTable;
        OpcodeTable* clientOpcodeTable;

        typedef std::set<unsigned int> BlockedOpcodes;
        BlockedOpcodes m_blockedOpcodes[2];

        bool m_showKnownOpcodes;

};

#define sOpcodeMgr OpcodeMgr::instance()

#endif // _OpcodeMgr_h__