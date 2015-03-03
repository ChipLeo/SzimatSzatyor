
#ifndef _Injector_h__
#define _Injector_h__

#include <atomic>
#include <thread>

#include "Util.h"
#include "LockedQueue.h"

#define MAX_COMMAND_ARGS 255

struct CliCommandHolder
{
    typedef void Print(void*, const char*);
    typedef void CommandFinished();

    void* m_callbackArg;
    char* m_command[MAX_COMMAND_ARGS];
    Print* m_print;
    int m_numargs;

    CommandFinished* m_commandFinished;

    CliCommandHolder(void* callbackArg, char* command[], int numargs, Print* zprint, CommandFinished* commandFinished)
        : m_callbackArg(callbackArg), m_print(zprint), m_commandFinished(commandFinished), m_numargs(numargs)
    {
        for (int i = 0; i < MAX_COMMAND_ARGS; ++i)
            m_command[i] = command[i];
    }

    ~CliCommandHolder() { }

private:
    CliCommandHolder(CliCommandHolder const& right) = delete;
    CliCommandHolder& operator=(CliCommandHolder const& right) = delete;
};

class Injector
{
    public:
        static Injector* instance()
        {
            static Injector instance;
            return &instance;
        }

        static void Stop() { m_stopEvent = true; }
        static bool IsStopped() { return m_stopEvent; }

        void SetCliThread(std::thread* cliThread) { m_cliThread = cliThread; }
        void ProcessCliCommands();
        bool ParseCommand(char* command[], int numargs);
        void QueueCliCommand(CliCommandHolder* commandHolder) { cliCmdQueue.add(commandHolder); }
        void ShutdownCLIThread();

    private:
        Injector() { }
        ~Injector() { }

        LockedQueue<CliCommandHolder*> cliCmdQueue;

       static std::atomic<bool> m_stopEvent;
       std::thread* m_cliThread;
};

#define sInjector Injector::instance()

#endif