#ifndef _Util_h__
#define _Util_h__

#include "uft8.h"

bool Utf8toWStr(char const* utf8str, size_t csize, wchar_t* wstr, size_t& wsize);
inline bool Utf8toWStr(const std::string& utf8str, wchar_t* wstr, size_t& wsize)
{
    return Utf8toWStr(utf8str.c_str(), utf8str.size(), wstr, wsize);
}

bool WStrToUtf8(std::wstring const& wstr, std::string& utf8str);
bool consoleToUtf8(const std::string& conStr, std::string& utf8str);

#endif


