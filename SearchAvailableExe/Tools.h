#include <windows.h>
#include <wincrypt.h>
#include <stdio.h>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <unordered_map>
#include <iostream>
#include <algorithm>
#include <filesystem>
#include <mutex>
#include <random>
#include <map>
#include <psapi.h>
#include <TlHelp32.h>

using namespace std;

typedef struct {
    bool isWrite;
    string filePath;
    string fileDir;
    int bit;
    bool isCreateWindow;
    vector<char*> preLoadDlls;
    vector<char*> postLoadDlls;
    string exploitDllPath;
    int   loadType;
    bool  isSystemDll;
    size_t fileHash;
    bool  isGUIWindow;
} ResultInfo, * PResultInfo;

#define STRING_MAX 256
typedef struct {
    char  input[STRING_MAX];
    char  output[STRING_MAX];
    bool  isWrite;
    int   dllCount;
    int   bit;
    bool  isSaveFile;
    int   loadType;
    bool  isPassSystemDll;
    int   isAllSectionSearch;
    bool  isGUIWindow;
} ARG_CONFIG, * PARG_CONFIG;

BOOL VerifyFileSignature(LPCWSTR filePath);
std::wstring ConvertToWideString(const char* input);
string wstring2string(wstring wstr);
void RunPE(PResultInfo result);
