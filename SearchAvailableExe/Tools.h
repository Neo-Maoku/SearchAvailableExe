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

BOOL VerifyFileSignature(LPCWSTR filePath);
