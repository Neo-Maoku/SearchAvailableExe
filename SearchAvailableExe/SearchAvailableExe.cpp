#include <thread>
#include "Tools.h"
#include "CmdlineParser.hpp"

using namespace std;

vector<PResultInfo> results;
ARG_CONFIG c;

void ThreadFunction(const std::wstring& filePath) {
    VerifyFileSignature(filePath.c_str());
}

void ListExecutableFiles(const wstring& directory) {
    WIN32_FIND_DATA findFileData;
    HANDLE hFind = FindFirstFile((directory + L"\\*").c_str(), &findFileData);
    std::vector<std::thread> threads;

    if (hFind != INVALID_HANDLE_VALUE) {
        do {
            wstring filename = findFileData.cFileName;
            if (filename != L"." && filename != L"..") {
                if (findFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                    // 如果是目录，则递归遍历
                    ListExecutableFiles(directory + L"\\" + filename);
                }
                else {
                    // 如果是文件，则检查是否是可执行文件
                    if (filename.size() > 4 && filename.substr(filename.size() - 4) == L".exe") {
                        // 将可执行文件路径写入文件
                        wstring fileFullPath = directory + L"\\" + filename;
                        threads.push_back(std::thread(ThreadFunction, fileFullPath));
                    }
                }
            }
        } while (FindNextFile(hFind, &findFileData) != 0);
        FindClose(hFind);
    }

    for (auto& thread : threads) {
        thread.join();
    }
}

bool compare(PResultInfo a, PResultInfo b) {
    int aPreSize = a->preLoadDlls.size() == 0 ? 999 : a->preLoadDlls.size();
    int aPostSize = a->postLoadDlls.size() == 0 ? 999 : a->postLoadDlls.size();
    int bPreSize = b->preLoadDlls.size() == 0 ? 999 : b->preLoadDlls.size();
    int bPostSize = b->postLoadDlls.size() == 0 ? 999 : b->postLoadDlls.size();

    if ((aPreSize < bPreSize && aPreSize < bPostSize) || (aPostSize < bPreSize && aPostSize < bPostSize))
        return true;
    else if ((bPreSize < aPreSize && bPreSize < aPostSize) || (bPostSize < aPreSize && bPostSize < aPostSize))
        return false;
    else {
        return a->isWrite > b->isWrite;
    }
}

map<size_t, bool> fileHashMap;
bool isUnwanted(const PResultInfo result) {
    int preSize = result->preLoadDlls.size();
    int postSize = result->postLoadDlls.size();

    if (c.isWrite == 1 && result->isWrite == 0)
        return true;
    if ((c.bit == 32 && result->bit != 32) || (c.bit == 64 && result->bit != 64))
        return true;
    if (preSize > c.dllCount)
        return true;

    if (fileHashMap[result->fileHash])
        return true;
    fileHashMap[result->fileHash] = true;

    return false;
}

bool isAvailable(const PResultInfo result) {
    if (result->exploitDllPath == "")
        return true;

    if ((c.loadType == 1 && result->loadType != 1) || (c.loadType == 2 && result->loadType != 2))
        return true;

    int preSize = result->preLoadDlls.size();
    int postSize = result->postLoadDlls.size();

    //如果是动态加载，需要加上静态dll个数去判断
    if (result->loadType == 2 && (preSize + postSize > c.dllCount))
        return true;

    if (c.isPassSystemDll && result->isSystemDll)
        return true;

    return false;
}

static int validate_dllCount(opt_arg* arg, void* args) {
    char* str = (char*)args;

    arg->u32 = 0;
    if (str == NULL) return 0;

    arg->u32 = atoi(str);

    if (arg->u32 <= 0)
        return 0;
    else
        return 1;
}

static int validate_bit(opt_arg* arg, void* args) {
    char* str = (char*)args;

    arg->u32 = 0;
    if (str == NULL) return 0;

    arg->u32 = atoi(str);

    if (arg->u32 != 32 && arg->u32 != 64 && arg->u32 != 96)
        return 0;
    else
        return 1;
}

static void usage(void) {
    printf("usage: SearchAvailableExe [options]\n");
    printf("       -o,--output: <path>                     Output file to save dll info. Default is output command.\n");
    printf("       -i,--input: <path>                      Input search path. Default traverse all disks.\n");
    printf("       -w,--write: <bool>                      Whether to only output information about directories with write permissions, with the default value being 'no'.\n");
    printf("       -c,--count: <count>                     Controls the output of the number of DLLs loaded by white programs, only outputting if the count is less than or equal to a specified value. The default value is 1.\n");
    printf("       -b,--bit: <count>                       Select the output bitness, supporting 32, 64, and 96 bits. The default is 96 bits, while also outputting information for 32 and 64-bit white programs.\n");
    printf("       -s,--save: <bool>                       Whether to save available files, default is not to save.\n");
    printf("       -l,--load: <loadType>                   Dll loading method, 1 for static loading, 2 for dynamic loading, and 3 for both static and dynamic loading. Default value is 3.\n");
    printf("       -p,--pass: <bool>                       Filter system DLLs.\n");
    exit(0);
}

std::map<DWORD, bool> processIdMap;
BOOL CALLBACK lpEnumFunc(HWND hwnd, LPARAM lParam) {
    DWORD  processId;
    GetWindowThreadProcessId(hwnd, &processId);

    CHAR windowText[256];
    GetWindowTextA(hwnd, windowText, ARRAYSIZE(windowText));

    if (processIdMap[processId]) {
        PostMessage(hwnd, WM_CLOSE, 0, 0);
    }

    return TRUE;
}

DWORD WINAPI MonitorThread(LPVOID lpParam) {
    HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32 process = { sizeof(PROCESSENTRY32) };

    // 遍历进程
    while (Process32Next(hProcessSnap, &process)) {
        if (strstr(wstring2string(process.szExeFile).c_str(), "csrss.exe"))
            processIdMap[process.th32ProcessID] = true;
    }

    while (1)
        EnumWindows(lpEnumFunc, (LPARAM)&processIdMap);
    
    return 0;
}

int main(int argc, char* argv[]) {
    //处理传入的参数
    memset(&c, 0, sizeof(c));
    
    c.dllCount = 1;
    c.bit = 96;
    c.loadType = 3;

    get_opt(argc, argv, OPT_TYPE_NONE, NULL, "h;?", "help", usage);
    get_opt(argc, argv, OPT_TYPE_STRING, c.output, "o", "output", NULL);
    get_opt(argc, argv, OPT_TYPE_STRING, c.input, "i", "input", NULL);
    get_opt(argc, argv, OPT_TYPE_FLAG, &c.isWrite, "w", "write", NULL);
    get_opt(argc, argv, OPT_TYPE_DEC, &c.dllCount, "c", "count", validate_dllCount);
    get_opt(argc, argv, OPT_TYPE_DEC, &c.bit, "b", "bit", validate_bit);
    get_opt(argc, argv, OPT_TYPE_FLAG, &c.isSaveFile, "s", "save", NULL);
    get_opt(argc, argv, OPT_TYPE_DEC, &c.loadType, "l", "load", NULL);
    get_opt(argc, argv, OPT_TYPE_FLAG, &c.isPassSystemDll, "p", "pass", NULL);

    ostream* output = &cout;
    ofstream outputFile;
    if (c.output[0] != 0) {
        outputFile.open(c.output);

        if (!outputFile.is_open()) {
            cerr << "Failed to open output file." << endl;
            return 1;
        }
        output = &outputFile;
    }
    //第一步：多线程递归遍历指定目录，筛选出带有签名的可执行文件，并获取可能需要加载dll信息等
    if (c.input[0] == 0) {
        for (char drive = 'A'; drive <= 'Z'; ++drive) {
            wstring rootDirectory = wstring(1, drive) + L":";
            ListExecutableFiles(rootDirectory);
        }
    }
    else {
        ListExecutableFiles(ConvertToWideString(c.input));
    }
    //对遍历的结果排序
    sort(results.begin(), results.end(), compare);

    //根据指定条件对结果过滤
    results.erase(std::remove_if(results.begin(), results.end(), isUnwanted), results.end());

    //创建线程，监听第二步运行时的报错弹窗，及时关闭
    HANDLE hThread = CreateThread(NULL, 0, MonitorThread, NULL, 0, NULL);

    //第二步：多线程运行找到的白程序，判断是否会加载被hook的dll，并进行上线测试
    std::vector<std::thread> threads;
    for (const auto& result : results) {
        threads.push_back(std::thread(RunPE, result));
    }
    for (auto& thread : threads)
        thread.join();

    TerminateThread(hThread,  0);

    //对结果进行过滤，去除不满足条件的白程序
    results.erase(std::remove_if(results.begin(), results.end(), isAvailable), results.end());
    
    *output << "找到可利用白文件：" << results.size() << "个" << endl;

    for (const auto& result : results) {
        *output << result->filePath << endl;
        *output << "程序位数: " << result->bit << " 目录是否可写: " << (result->isWrite==1 ? "是" : "否") << " Dll加载方式: " << (result->loadType == 1 ? "静态加载" : "动态加载") << endl;
        *output << "可利用DLL: " << result->exploitDllPath << endl;

        if ((result->loadType == 1 && result->preLoadDlls.size() > 1) || (result->loadType == 2 && result->preLoadDlls.size() + result->postLoadDlls.size() > 1)) {
            *output << "需要复制以下DLL: " << endl;
            if (result->preLoadDlls.size() > 0) {
                for (const auto& dll : result->preLoadDlls) {
                    if (result->exploitDllPath != dll)
                        *output << dll << endl;
                    delete[] dll;
                }
            }

            if (result->loadType == 2 && result->postLoadDlls.size() > 0) {
                for (const auto& dll : result->postLoadDlls) {
                    if (result->exploitDllPath != dll)
                        *output << dll << endl;
                    delete[] dll;
                }
            }
        }

        *output << "--------------------------------------------------" << endl;

        delete result;
    }

    if (c.output[0] != 0) {
        outputFile.close();
        cout << "Search finish. Output saved to " << c.output << endl;
    }
    else
        cout << "Search finish!" << endl;

    return 0;
}