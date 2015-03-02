#include "CliRunnable.h"
#include "Util.h"
#include "Injector.h"

#include <stdio.h>
#include <string.h>
#include <wchar.h>

void utf8print(void* /*arg*/, const char* str)
{
    wchar_t wtemp_buf[6000];
    size_t wtemp_len = 6000-1;
    if (!Utf8toWStr(str, strlen(str), wtemp_buf, wtemp_len))
        return;

    char temp_buf[6000];
    CharToOemBuffW(&wtemp_buf[0], &temp_buf[0], wtemp_len+1);
    printf(temp_buf);
}

void commandFinished()
{
    printf("> ");
    fflush(stdout);
}


/// %Thread start
void CliThread()
{
    // print this here the first time
    // later it will be printed after command queue updates
    printf(">");

    ///- As long as the World is running (no World::m_stopEvent), get the command line and handle it
    while (!Injector::IsStopped())
    {
        fflush(stdout);

        char commandbuf[256];
        char *command_str = fgets(commandbuf, sizeof(commandbuf), stdin);

        if (command_str != NULL)
        {
            for (int x=0; command_str[x]; ++x)
                if (command_str[x] == '\r' || command_str[x] == '\n')
                {
                    command_str[x] = 0;
                    break;
                }

            if (!*command_str)
            {
                printf(">");
                continue;
            }

            char* command[255];
            char* arg = NULL;
            int numargs = 0;
            arg = strtok(command_str, " ");
            while (arg != NULL)
            {
              command[numargs] = arg;
              arg = strtok (NULL, " ,.-");
              ++numargs;
            }

            if (!numargs)
                command[0] = command_str;

            fflush(stdout);
            sInjector->QueueCliCommand(new CliCommandHolder(NULL, command, numargs, &utf8print, &commandFinished));
        }
        else if (feof(stdin))
        {
            Injector::Stop();
        }
    }
}
