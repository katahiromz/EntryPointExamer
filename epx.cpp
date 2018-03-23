// epx --- EntryPointExamer
// This program statically analyzes the entry points of an EXE/DLL file.
// Copyright (C) 2018 Katayama Hirofumi MZ.
// This file is public domain software (PDS).

#define _CRT_SECURE_NO_WARNINGS

#if defined(WONVER) && WONVER == 0
    #include "wondef.h"
    #include "wonnt.h"
#else
    #include <windows.h>
#endif

#include <string>
#include <set>
#include <vector>
#include <cstdlib>
#include <cstdio>
#include <sys/types.h>
#include <sys/stat.h>

#include "ExeImage.hpp"
using namespace codereverse;

void show_help(void)
{
    printf("EPX --- EntryPointExamer\n");
    printf("EPX statically analyzes the entry points of Windows EXE/DLL files.\n");
    printf("Usage: epx.exe [OPTIONS] [exe-file.exe]\n");
    printf("\n");
#if defined(_WIN32) && !defined(WONVER)
    printf("If no EXE file specified, then OS info file will be dumped.\n");
    printf("\n");
#endif
    printf("Options:\n");
    printf("--os-info \"os.info\"  Set the OS info file for analysis or dumping.\n");
    printf("--version              Show version info.\n");
    printf("--help                 Show this message.\n");
}

void show_version(void)
{
    printf("EPX 0.2 by katahiromz (%s %s)\n", __DATE__, __TIME__);
    printf("This software is public domain software (PDS).\n");
}

struct EPX_IMPORT
{
    std::string dll_file;
    std::string symbol_name;
    WORD symbol_ordinal;
};

struct EPX_EXPORT
{
    std::string symbol_name;
    WORD symbol_ordinal;
};

#define NOT_FOUND       "NOT FOUND"
#define UNKNOWN_FORMAT  "UNKNOWN FORMAT"

const char *g_progname = "epx";
char g_dll_check_list_file[MAX_PATH] = "DllCheckList.txt";
typedef std::set<std::string> dll_check_list_t;
dll_check_list_t g_dll_check_list;
std::vector<std::pair<std::string, std::string> > g_dll_and_exports;
std::vector<std::string> g_additional_dll_targets;

enum RET
{
    RET_SUCCESS = 0,
    RET_INVALID_ARGUMENT,
    RET_CANNOT_READ,
    RET_CANNOT_WRITE,
    RET_LIST_IS_EMPTY,
    RET_UNKNOWN_FORMAT,
    RET_DLL_NOT_FOUND,
    RET_SYMBOL_NOT_FOUND,
    RET_NOT_CHECK_TARGET,
    RET_CHECK_LIST_FILE_NOT_FOUND
};

template <typename T_CHAR>
inline void mstr_trim(std::basic_string<T_CHAR>& str, const T_CHAR *spaces)
{
    typedef std::basic_string<T_CHAR> string_type;
    size_t i = str.find_first_not_of(spaces);
    size_t j = str.find_last_not_of(spaces);
    if ((i == string_type::npos) || (j == string_type::npos))
    {
        str.clear();
    }
    else
    {
        str = str.substr(i, j - i + 1);
    }
}

char *my_strlwr(char *str)
{
    for (char *ptr = str; *ptr; ++ptr)
    {
        *ptr = tolower(*ptr);
    }
    return str;
}

inline bool file_exists(const char *pathname)
{
#if defined(_WIN32) && !defined(WONVER)
    return GetFileAttributesA(pathname) == 0xFFFFFFFF;
#else
    struct stat st;
    return (stat(pathname, &st) == 0);
#endif
}

RET get_imports(const char *exe_file, std::vector<EPX_IMPORT>& imports)
{
    imports.clear();

    ExeImage exe(exe_file);
    if (exe.is_loaded())
    {
        std::vector<const char *> dlls;
        if (exe.get_import_dll_names(dlls))
        {
            for (size_t i = 0; i < dlls.size(); ++i)
            {
                std::vector<ImportSymbol> symbols;
                if (exe.get_import_symbols(DWORD(i), symbols))
                {
                    for (size_t k = 0; k < symbols.size(); ++k)
                    {
                        ImportSymbol& symbol = symbols[k];
                        EPX_IMPORT imp;
                        imp.dll_file = dlls[i];
                        if (symbol.Name.wImportByName)
                        {
                            imp.symbol_name = symbol.pszName;
                        }
                        else
                        {
                            imp.symbol_ordinal = symbol.Name.wOrdinal;
                        }
                        imports.push_back(imp);
                    }
                }
            }
            return RET_SUCCESS;
        }
    }

    fprintf(stderr, "ERROR: Unknown format: '%s'\n", exe_file);
    return RET_UNKNOWN_FORMAT;
}

RET get_exports(const char *dll_file, std::vector<EPX_EXPORT>& exports)
{
    exports.clear();

    ExeImage dll(dll_file);
    if (dll.is_loaded())
    {
        std::vector<ExportSymbol> symbols;
        if (dll.get_export_symbols(symbols))
        {
            for (size_t i = 0; i < symbols.size(); ++i)
            {
                ExportSymbol& symbol = symbols[i];
                EPX_EXPORT exp;
                if (symbol.pszName)
                {
                    exp.symbol_name = symbol.pszName;
                }
                else
                {
                    exp.symbol_ordinal = WORD(symbol.dwOrdinal);
                }
                exports.push_back(exp);
            }
            return RET_SUCCESS;
        }
    }

    fprintf(stderr, "WARNING: Unknown format: '%s'\n", dll_file);
    return RET_UNKNOWN_FORMAT;
}

RET get_dll_check_list(const char *check_list_file)
{
    g_dll_check_list.clear();

    if (FILE *fp = fopen(check_list_file, "r"))
    {
        char buf[MAX_PATH];
        while (fgets(buf, MAX_PATH, fp))
        {
            if (buf[0] == ';')
                continue;

            std::string str = buf;
            mstr_trim(str, " \t\n\r\f\v");
            if (str.empty())
                continue;

            g_dll_check_list.insert(str);
        }

        fclose(fp);

        if (g_dll_check_list.empty())
        {
            fprintf(stderr, "ERROR: '%s' is empty.\n", check_list_file);
            return RET_LIST_IS_EMPTY;
        }

        return RET_SUCCESS;
    }

    fprintf(stderr, "ERROR: Unable to read file '%s'.\n", check_list_file);
    return RET_CANNOT_READ;
}

#if defined(_WIN32) && !defined(WONVER)
    RET dump_dll_info(FILE *fp, const char *dll)
    {
        char path[MAX_PATH], *pch;
        if (!SearchPathA(NULL, dll, ".dll", MAX_PATH, path, &pch))
        {
            if (!SearchPathA(NULL, dll, NULL, MAX_PATH, path, &pch))
            {
                return RET_DLL_NOT_FOUND;
            }
        }

        std::vector<EPX_EXPORT> exports;
        if (RET ret = get_exports(path, exports))
            return ret;

        for (size_t k = 0; k < exports.size(); ++k)
        {
            EPX_EXPORT& exp = exports[k];
            if (exp.symbol_name.size())
            {
                fprintf(fp, "%s\t%s\n", dll, exp.symbol_name.c_str());
            }
            else
            {
                fprintf(fp, "%s\t%d\n", dll, exp.symbol_ordinal);
            }
        }

        return RET_SUCCESS;
    }

    RET dump_os_info(const char *os_info_file)
    {
        if (g_dll_check_list.empty())
        {
            if (RET ret = get_dll_check_list(g_dll_check_list_file))
                return ret;
        }

        if (FILE *fp = fopen(os_info_file, "w"))
        {
            OSVERSIONINFOA osver;
            memset(&osver, 0, sizeof(osver));
            osver.dwOSVersionInfoSize = sizeof(osver);
            GetVersionExA(&osver);

            fprintf(fp, "; Filename: %s\n", os_info_file);
            SYSTEMTIME st;
            GetLocalTime(&st);
            fprintf(fp, "; Timestamp: %04u.%02u.%02u %02u:%02u:%02u\n",
                st.wYear, st.wMonth, st.wDay,
                st.wHour, st.wMinute, st.wSecond);
    #ifdef _WIN64
            fprintf(fp, "; _WIN64\n");
    #else
            fprintf(fp, "; _WIN32\n");
    #endif
            fprintf(fp, "; GetVersion: 0x%08lX\n", GetVersion());
            fprintf(fp, "; osver.dwMajorVersion: 0x%08lX\n", osver.dwMajorVersion);
            fprintf(fp, "; osver.dwMinorVersion: 0x%08lX\n", osver.dwMinorVersion);
            fprintf(fp, "; osver.dwBuildNumber: 0x%08lX\n", osver.dwBuildNumber);
            fprintf(fp, "; osver.dwPlatformId: 0x%08lX\n", osver.dwPlatformId);
            fprintf(fp, "; osver.szCSDVersion: %s\n", osver.szCSDVersion);

            dll_check_list_t::iterator it, end = g_dll_check_list.end();
            for (it = g_dll_check_list.begin(); it != end; ++it)
            {
                const std::string& dll = *it;
                if (RET ret = dump_dll_info(fp, dll.c_str()))
                {
                    if (ret == RET_DLL_NOT_FOUND)
                    {
                        fprintf(fp, "%s\t%s\n", dll.c_str(), NOT_FOUND);
                    }
                    if (ret == RET_UNKNOWN_FORMAT)
                    {
                        fprintf(fp, "%s\t%s\n", dll.c_str(), UNKNOWN_FORMAT);
                    }
                }
            }

            if (ferror(fp))
            {
                fprintf(stderr, "ERROR: Unable to write file '%s'.\n", os_info_file);
                fclose(fp);
                _unlink(os_info_file);
                return RET_CANNOT_WRITE;
            }

            fclose(fp);
            return RET_SUCCESS;
        }

        fprintf(stderr, "ERROR: Unable to write file '%s'.\n", os_info_file);
        return RET_CANNOT_WRITE;
    }
#endif  // defined(_WIN32) && !defined(WONVER)

RET load_os_info(const char *os_info_file)
{
    g_dll_and_exports.clear();

    if (FILE *fp = fopen(os_info_file, "r"))
    {
        char buf[MAX_PATH];
        while (fgets(buf, MAX_PATH, fp))
        {
            if (buf[0] == ';')
                continue;

            std::string str = buf;
            mstr_trim(str, " \t\n\r\f\v");
            if (str.empty())
                continue;

            size_t k = str.find('\t');
            if (k == std::string::npos)
                continue;

            std::string dll = str.substr(0, k), exports = str.substr(k + 1);
            g_dll_and_exports.push_back(std::make_pair(dll, exports));
        }

        fclose(fp);
        return RET_SUCCESS;
    }

    fprintf(stderr, "ERROR: Unable to read file '%s'.\n", os_info_file);
    return RET_CANNOT_READ;
}

RET check_import_by_os_info(EPX_IMPORT& imp)
{
    if (g_dll_check_list.find(imp.dll_file) == g_dll_check_list.end())
        return RET_NOT_CHECK_TARGET;

    my_strlwr(&imp.dll_file[0]);
    if (imp.symbol_name.empty())
    {
        char buf[32];
        sprintf(buf, "%d", imp.symbol_ordinal);
        imp.symbol_name = buf;
    }

    for (size_t i = 0; i < g_dll_and_exports.size(); ++i)
    {
        std::string& dll = g_dll_and_exports[i].first;
        my_strlwr(&dll[0]);
        if (dll == imp.dll_file)
        {
            std::string& symbol_name = g_dll_and_exports[i].second;

            if (symbol_name == NOT_FOUND)
                return RET_DLL_NOT_FOUND;

            if (symbol_name == UNKNOWN_FORMAT)
            {
                fprintf(stderr, "WARNING: Unknown format of target dll file.\n");
                return RET_SUCCESS;
            }

            if (symbol_name == imp.symbol_name)
                return RET_SUCCESS;
        }
    }

    return RET_SYMBOL_NOT_FOUND;
}

RET check_dll_for_import(const char *dll_file, EPX_IMPORT& imp)
{
    std::vector<EPX_EXPORT> exports;
    if (RET ret = get_exports(dll_file, exports))
        return ret;

    for (size_t k = 0; k < exports.size(); ++k)
    {
        EPX_EXPORT& exp = exports[k];
        if (exp.symbol_name.size())
        {
            if (imp.symbol_name.size() && imp.symbol_name == exp.symbol_name)
                return RET_SUCCESS;
        }
        else
        {
            if (imp.symbol_name.empty() && imp.symbol_ordinal == exp.symbol_ordinal)
                return RET_SUCCESS;
        }
    }

    return RET_SYMBOL_NOT_FOUND;
}

RET analyze_exe(const char *exe, const char *os_info_file)
{
    if (g_dll_check_list.empty())
    {
        if (RET ret = get_dll_check_list(g_dll_check_list_file))
            return ret;
    }

    if (RET ret = load_os_info(os_info_file))
        return ret;

    std::vector<EPX_IMPORT> imports;
    if (RET ret = get_imports(exe, imports))
        return ret;

    RET ret = RET_SUCCESS;
    for (size_t i = 0; i < imports.size(); ++i)
    {
        EPX_IMPORT& imp = imports[i];

        if (RET ret2 = check_import_by_os_info(imp))
        {
            if (ret2 == RET_DLL_NOT_FOUND || ret2 == RET_NOT_CHECK_TARGET)
            {
                char path[MAX_PATH], *pch;
                strcpy(path, exe);
                pch = strrchr(path, '\\');
                if (pch)
                {
                    ++pch;
                    strcpy(pch, imp.dll_file.c_str());
                    g_additional_dll_targets.push_back(path);
                    ret2 = check_dll_for_import(path, imp);
                }
            }
            if (ret2 == RET_SYMBOL_NOT_FOUND)
            {
                fprintf(stderr, "ERROR: '%s' - Symbol '%s' not found.\n",
                        imp.dll_file.c_str(), imp.symbol_name.c_str());
                ret = ret2;
            }
        }
    }

    for (size_t i = 0; i < g_additional_dll_targets.size(); ++i)
    {
        if (RET ret2 = analyze_exe(g_additional_dll_targets[i].c_str(), os_info_file))
        {
            ret = ret2;
        }
    }

    if (ret == RET_SUCCESS)
    {
        printf("Success.\n");
    }

    return ret;
}

int main(int argc, char **argv)
{
    const char *os_info = "os.info";
    char *exe_file = NULL;

    g_progname = argv[0];

    {
        char path[MAX_PATH], *pch;
#if defined(_WIN32) && !defined(WONVER)
        GetModuleFileNameA(NULL, path, MAX_PATH);
#else
        strcpy(path, g_progname);
#endif
        pch = strrchr(path, '\\');
        if (pch)
        {
            strcpy(pch, "\\DllCheckList.txt");
            if (!file_exists(path))
            {
                strcpy(pch, "\\..\\DllCheckList.txt");
                if (!file_exists(path))
                {
                    strcpy(pch, "\\..\\..\\DllCheckList.txt");
                    if (!file_exists(path))
                    {
                        fprintf(stderr, "ERROR: Not found: DllCheckList.txt\n");
                        return RET_CHECK_LIST_FILE_NOT_FOUND;
                    }
                }
            }
            strcpy(g_dll_check_list_file, path);
        }
    }

    if (argc <= 1)
    {
#if defined(_WIN32) && !defined(WONVER)
        return dump_os_info(os_info);
#else
        show_help();
        return 0;
#endif
    }

    for (int i = 1; i < argc; ++i)
    {
        if (strcmp(argv[i], "--help") == 0)
        {
            show_help();
            return RET_SUCCESS;
        }
        if (strcmp(argv[i], "--version") == 0)
        {
            show_version();
            return RET_SUCCESS;
        }
        if (strcmp(argv[i], "--os-info") == 0)
        {
            if (i + 1 < argc)
            {
                os_info = argv[i + 1];
                ++i;
            }
            else
            {
                fprintf(stderr, "ERROR: Option '--os-info' needs an operand.\n");
                return RET_INVALID_ARGUMENT;
            }
            continue;
        }
        if (argv[i][0] == '-')
        {
            fprintf(stderr, "ERROR: Invalid option '%s'.\n", argv[i]);
            return RET_INVALID_ARGUMENT;
        }
        if (exe_file == NULL)
        {
            exe_file = argv[i];
        }
        else
        {
            fprintf(stderr, "ERROR: Multiple exe file specified.\n");
            return RET_INVALID_ARGUMENT;
        }
    }

    if (exe_file)
    {
        return analyze_exe(exe_file, os_info);
    }

#if defined(_WIN32) && !defined(WONVER)
    return dump_os_info(os_info);
#else
    show_help();
    return RET_INVALID_ARGUMENT;
#endif
}
