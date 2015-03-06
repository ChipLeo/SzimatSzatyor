#ifndef _OpcodeMgr_h__
#define _OpcodeMgr_h__

#include <xstring>
#include <ios>
#include <iosfwd>
#include <ostream>
#include <sstream>
#include <set>
#include <Windows.h>
#include <unordered_map>

struct OpcodeHandler
{
    OpcodeHandler() {}

    OpcodeHandler(unsigned int opcodeNumber, const std::string& _name)
        : OpcodeNumber(opcodeNumber), Name(_name) {}

    std::string Name;
    unsigned int OpcodeNumber;
};

class OpcodeTable
{
public:
    OpcodeTable() { }

    ~OpcodeTable()
    {
        while (!_internalTable.empty())
        {
            Opcodes::iterator opcode = _internalTable.begin();
            delete opcode->second;
            _internalTable.erase(opcode);
        }
    }

    void CreateOpcodeHandler(unsigned int opcode, const std::string& name) { _internalTable[opcode] = new OpcodeHandler(opcode, name); }
    OpcodeHandler* const GetOpcodeHandler(unsigned int opcode) const
    {
        Opcodes::const_iterator itr = _internalTable.find(opcode);
        if (itr != _internalTable.end())
            return itr->second;

        return nullptr;
    }

    size_t size() { return _internalTable.size(); }

private:

    // Prevent copying this structure
    OpcodeTable(OpcodeTable const&);
    OpcodeTable& operator=(OpcodeTable const&);

    typedef std::unordered_map<unsigned int, OpcodeHandler*> Opcodes;
    Opcodes _internalTable;
};

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
        void ValidateAndSetOpcode(const std::string& name, unsigned int opcodeNumber);
        void LoadOpcodeFile(const HINSTANCE moduleHandle);

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
            if (m_exclusiveOpcodes[0].empty() && m_exclusiveOpcodes[1].empty())
                return true;

            OpcodeSet::const_iterator itr = m_exclusiveOpcodes[type].find(opcode);
            if (itr != m_exclusiveOpcodes[type].end())
                return true;

            return false;
        }

        std::string GetOpcodeNameForLogging(unsigned int opcode, bool isServerOpcode);

        unsigned int GetNumCliOpcodes() { return clientOpcodeTable->size(); }
        unsigned int GetNumServerOpcodes() { return serverOpcodeTable->size(); }
        unsigned int GetNumMiscOpcodes() { return miscOpcodeTable->size(); }

    private:
        OpcodeMgr() { }
        ~OpcodeMgr() { }

        OpcodeTable* serverOpcodeTable;
        OpcodeTable* clientOpcodeTable;
        OpcodeTable* miscOpcodeTable;

        typedef std::set<unsigned int> OpcodeSet;
        OpcodeSet m_blockedOpcodes[2];
        OpcodeSet m_exclusiveOpcodes[2];

        bool m_showKnownOpcodes;

};

#define sOpcodeMgr OpcodeMgr::instance()

#endif // _OpcodeMgr_h__