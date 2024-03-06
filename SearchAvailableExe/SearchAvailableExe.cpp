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

bool isUnwanted(const PResultInfo result) {
    if (c.isWrite == 1 && result->isWrite == 0)
        return true;
    if ((c.bit == 32 && result->bit != 32) || (c.bit == 64 && result->bit != 64))
        return true;
    if (c.dllCount < result->postLoadDlls.size() && c.dllCount < result->preLoadDlls.size())
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
    printf("       -c,--count: <count>                     Controls the output of the number of DLLs loaded by white programs, only outputting if the count is less than or equal to a specified value. The default value is 5.\n");
    printf("       -b,--bit: <count>                       Select the output bitness, supporting 32, 64, and 96 bits. The default is 96 bits, while also outputting information for 32 and 64-bit white programs.\n");
    exit(0);
}

int main(int argc, char* argv[]) {
    
    memset(&c, 0, sizeof(c));
    
    c.dllCount = 5;
    c.bit = 96;

    get_opt(argc, argv, OPT_TYPE_NONE, NULL, "h;?", "help", usage);
    get_opt(argc, argv, OPT_TYPE_STRING, c.output, "o", "output", NULL);
    get_opt(argc, argv, OPT_TYPE_STRING, c.input, "i", "input", NULL);
    get_opt(argc, argv, OPT_TYPE_FLAG, &c.isWrite, "w", "write", NULL);
    get_opt(argc, argv, OPT_TYPE_DEC, &c.dllCount, "c", "count", validate_dllCount);
    get_opt(argc, argv, OPT_TYPE_DEC, &c.bit, "b", "bit", validate_bit);

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

    if (c.input[0] == 0) {
        for (char drive = 'A'; drive <= 'Z'; ++drive) {
            wstring rootDirectory = wstring(1, drive) + L":";
            ListExecutableFiles(rootDirectory);
        }
    }
    else {
        ListExecutableFiles(ConvertToWideString(c.input));
    }

    sort(results.begin(), results.end(), compare);

    results.erase(std::remove_if(results.begin(), results.end(), isUnwanted), results.end());

    for (const auto& result : results) {
        *output << result->filePath << endl;
        *output << "程序位数: " << result->bit << " 目录是否可写: " << result->isWrite << endl;

        if (result->preLoadDlls.size() > 0) {
            *output << "预加载DLL个数: " << result->preLoadDlls.size() << endl;
            for (const auto& dll : result->preLoadDlls) {
                *output << dll << endl;
                delete[] dll;
            }
        }

        if (result->postLoadDlls.size() > 0) {
            *output << "动态加载DLL个数: " << result->postLoadDlls.size() << endl;
            for (const auto& dll : result->postLoadDlls) {
                *output << dll << endl;
                delete[] dll;
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