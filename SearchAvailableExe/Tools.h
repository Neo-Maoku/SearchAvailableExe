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

using namespace std;

typedef struct {
    bool isWrite;
    string filePath;
    int bit;
    vector<char*> preLoadDlls;
    vector<char*> postLoadDlls;
} ResultInfo, * PResultInfo;

#define STRING_MAX 256
typedef struct {
    char  input[STRING_MAX];
    char  output[STRING_MAX];
    bool  isWrite;
    int   dllCount;
    int   bit;
} ARG_CONFIG, * PARG_CONFIG;

BOOL VerifyFileSignature(LPCWSTR filePath);
std::wstring ConvertToWideString(const char* input);