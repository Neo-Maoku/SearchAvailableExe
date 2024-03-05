#include <iostream>
#include <windows.h>
#include <fstream>
#include <thread>
#include "Tools.h"

using namespace std;

vector<PResultInfo> results;

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

int main() {
    string outputFilename = "output.txt";
    ofstream outputFile(outputFilename);

    if (!outputFile.is_open()) {
        cerr << "Failed to open output file." << endl;
        return 1;
    }

    // 遍历系统的所有盘符
    for (char drive = 'A'; drive <= 'Z'; ++drive) {
        wstring rootDirectory = wstring(1, drive) + L":";
        ListExecutableFiles(rootDirectory);
    }

    //wstring rootDirectory = L"D:\\Code\\TeamWorkspace\\beacon\\白+黑 嵌入生成";
    //wstring rootDirectory = L"C:\\Program Files\\Microsoft Visual Studio\\2022\\Professional\\VC\\Tools\\Llvm\\x64\\bin";
    /*wstring rootDirectory = L"D:\\Users\\MaoKu\\AppData\\Local\\Programs\\Microsoft VS Code\\bin";
    ListExecutableFiles(rootDirectory);*/

    for (const auto& result : results) {
        outputFile << result->filePath << endl;
        outputFile << "程序位数: " << result->bit << " 目录是否可写: " << result->isWrite << endl;

        if (result->preLoadDlls.size() > 0) {
            outputFile << "预加载DLL个数: " << result->preLoadDlls.size() << endl;
            for (const auto& dll : result->preLoadDlls) {
                outputFile << dll << endl;
                delete[] dll;
            }
        }

        if (result->postLoadDlls.size() > 0) {
            outputFile << "动态加载DLL个数: " << result->postLoadDlls.size() << endl;
            for (const auto& dll : result->postLoadDlls) {
                outputFile << dll << endl;
                delete[] dll;
            }
        }

        outputFile << "-------------------------" << endl;

        delete result;
    }

    outputFile.close();
    cout << "Output saved to " << outputFilename << endl;

    return 0;
}