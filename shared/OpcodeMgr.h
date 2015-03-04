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
            OpcodeSet::const_iterator itr = m_blockedOpcodes[type].find(opcode);
            if (itr != m_blockedOpcodes[type].end())
                return true;

            return false;
        }
        void BlockOpcode(unsigned int opcode, unsigned short type) { m_blockedOpcodes[type].insert(opcode); }
        void UnBlockOpcode(unsigned int opcode, unsigned short type) { m_blockedOpcodes[type].erase(opcode); }
        void UnBlockAll(unsigned short type)
        {
            for (OpcodeSet::const_iterator itr = m_blockedOpcodes[type].begin(); itr != m_blockedOpcodes[type].end(); ++itr)
                printf("Opcode %s will now be shown\n", GetOpcodeNameForLogging(*itr, type ? true : false).c_str());

            m_blockedOpcodes[type].clear();
        }
        bool ShowKnownOpcodes() { return m_showKnownOpcodes; }
        void ToggleKnownOpcodes() { m_showKnownOpcodes = !m_showKnownOpcodes; }

        void AddExclusiveOpcode(unsigned int opcode, unsigned short type) { m_exclusiveOpcodes[type].insert(opcode); }
        void DelExclusiveOpcode(unsigned int opcode, unsigned short type) { m_exclusiveOpcodes[type].erase(opcode); }
        void ClearExclusive(unsigned short type)
        {
            for (OpcodeSet::const_iterator itr = m_exclusiveOpcodes[type].begin(); itr != m_exclusiveOpcodes[type].end(); ++itr)
                printf("Opcode %s is no longer exclusive\n", GetOpcodeNameForLogging(*itr, type ? true : false).c_str());

            m_exclusiveOpcodes[type].clear();
        }
        bool IsExclusive(unsigned int opcode, unsigned short type)
        {
            if (m_exclusiveOpcodes[type].empty())
                return true;

            OpcodeSet::const_iterator itr = m_exclusiveOpcodes[type].find(opcode);
            if (itr != m_exclusiveOpcodes[type].end())
                return true;

            return false;
        }

        std::string GetOpcodeNameForLogging(unsigned int opcode, bool isServerOpcode);

    private:
        OpcodeMgr() { }
        ~OpcodeMgr() { }

        OpcodeTable* serverOpcodeTable;
        OpcodeTable* clientOpcodeTable;

        typedef std::set<unsigned int> OpcodeSet;
        OpcodeSet m_blockedOpcodes[2];
        OpcodeSet m_exclusiveOpcodes[2];

        bool m_showKnownOpcodes;

};

#define sOpcodeMgr OpcodeMgr::instance()

#endif // _OpcodeMgr_h__