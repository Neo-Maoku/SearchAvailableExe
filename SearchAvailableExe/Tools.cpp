#include "Tools.h"

extern vector<PResultInfo> results;
extern ARG_CONFIG c;
std::mutex mtx;

string wstring2string(wstring wstr)
{
    string result;
    //获取缓冲区大小，并申请空间，缓冲区大小事按字节计算的  
    int len = WideCharToMultiByte(CP_ACP, 0, wstr.c_str(), wstr.size(), NULL, 0, NULL, NULL);
    char* buffer = new char[len + 1];
    //宽字节编码转换成多字节编码  
    WideCharToMultiByte(CP_ACP, 0, wstr.c_str(), wstr.size(), buffer, len, NULL, NULL);
    buffer[len] = '\0';
    //删除缓冲区并返回值  
    result.append(buffer);
    delete[] buffer;
    return result;
}

DWORD rvaToFOA(LPVOID buf, int rva)
{
    PIMAGE_DOS_HEADER  pDH = (PIMAGE_DOS_HEADER)buf;
    IMAGE_SECTION_HEADER* sectionHeader;

    if (*(PWORD)((size_t)pDH + pDH->e_lfanew + 0x18) == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
    {
        PIMAGE_NT_HEADERS32  pNtH32 = PIMAGE_NT_HEADERS32((size_t)pDH + pDH->e_lfanew);

        sectionHeader = IMAGE_FIRST_SECTION(pNtH32);
    }
    else {
        PIMAGE_NT_HEADERS64 pNtH64 = PIMAGE_NT_HEADERS64((size_t)pDH + pDH->e_lfanew);

        sectionHeader = IMAGE_FIRST_SECTION(pNtH64);
    }

    while (sectionHeader->VirtualAddress != 0)
    {
        if (rva >= sectionHeader->VirtualAddress && rva < sectionHeader->VirtualAddress + sectionHeader->Misc.VirtualSize) {
            return rva - sectionHeader->VirtualAddress + sectionHeader->PointerToRawData;
        }

        sectionHeader++;
    }

    return 0;
}

bool containsIgnoreCase(const std::string& str1, const std::string& str2) {
    std::string str1Lower = str1;
    std::string str2Lower = str2;

    // 将两个字符串转换为小写
    std::transform(str1Lower.begin(), str1Lower.end(), str1Lower.begin(), ::tolower);
    std::transform(str2Lower.begin(), str2Lower.end(), str2Lower.begin(), ::tolower);

    // 在转换后的字符串中查找
    return str1Lower.find(str2Lower) != std::string::npos;
}

BYTE* readRDataSection(BYTE* buffer, PDWORD rdataLength) {
    PIMAGE_DOS_HEADER dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(buffer);
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        std::cerr << "Invalid DOS header." << std::endl;
        return 0;
    }

    PIMAGE_NT_HEADERS ntHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<BYTE*>(buffer) + dosHeader->e_lfanew);
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
        std::cerr << "Invalid NT headers." << std::endl;
        return 0;
    }

    PIMAGE_SECTION_HEADER sectionHeader = IMAGE_FIRST_SECTION(ntHeaders);
    for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; ++i) {
        if (strcmp(".rdata", (char*)sectionHeader[i].Name) == 0) {
            *rdataLength = sectionHeader[i].SizeOfRawData;
            return reinterpret_cast<BYTE*>(buffer) + sectionHeader[i].PointerToRawData;
        }
    }

    return 0;
}

LPSTR ConvertWideToMultiByte(LPCWSTR wideString) {
    int wideLength = wcslen(wideString);

    int bufferSize = WideCharToMultiByte(CP_ACP, 0, wideString, wideLength, NULL, 0, NULL, NULL);

    LPSTR multiByteString = new char[bufferSize + 1];
    memset(multiByteString, 0, bufferSize + 1);

    WideCharToMultiByte(CP_ACP, 0, wideString, wideLength, multiByteString, bufferSize, NULL, NULL);

    return multiByteString;
}

std::string GetDirectoryFromPath(const std::string& filePath) {
    // 将文件路径转换为路径对象
    std::filesystem::path pathObj(filePath);

    // 返回文件所在目录的字符串表示
    return pathObj.parent_path().string();
}

void searchDll(BYTE* buffer, PResultInfo result, LPCWSTR filePath, char* dllsName, string fileDir) {
    DWORD rdataLength;
    BYTE* rdata = readRDataSection(buffer, &rdataLength);
    if (rdata != 0) {
        char fileFullPath[0x255] = { 0 };
        strcat(fileFullPath, fileDir.c_str());
        int fileDirLength = fileDir.length();
        DWORD vaule, vaule1;
        char* str;
        int strLength;
        char ch;
        int index = 0;

        for (int i = rdataLength - 8; i > 0; --i, index = 0) {
            vaule = *(PDWORD)((PBYTE)rdata + i);
            vaule1 = *(PDWORD)((PBYTE)rdata + i + 4);
            
            if (vaule == 0x6c6c642e)
                index = 1;
            else if (vaule1 == 0x6c && vaule == 0x6c0064)
                index = 2;

            if (index > 0) {
                i -= index;
                ch = rdata[i];
                while (((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') || ch == '_' || ch == '.' || ch == '-')) {
                    i -= index;
                    ch = rdata[i];
                }

                if (ch != 0)
                    continue;

                if (index == 1)
                    str = (char*)(rdata + i + 1);
                else
                    str = ConvertWideToMultiByte((wchar_t*)(rdata + i + 2));

                strLength = strlen(str);
                if (str[strLength-1] != 'l')
                    continue;

                memcpy(fileFullPath + fileDirLength, str, strLength + 1);

                if (filesystem::exists(filesystem::path(fileFullPath)) && containsIgnoreCase(dllsName, str) == NULL)
                    result->postLoadDlls.push_back(_strdup(str));
            }
        }
    }
}

bool hasWritePermission(const std::string& directoryPath) {
    std::string tempFilePath = directoryPath + "\\tmp";
    {
        std::lock_guard<std::mutex> lock(mtx);
        std::ofstream tempFile(tempFilePath);

        if (!tempFile.is_open()) {
            return false;  // 创建文件失败，目录没有写权限
        }
        tempFile.close();
        std::filesystem::remove(tempFilePath);  // 创建文件后立即删除
    }
    return true;  // 创建文件成功，目录有写权限
}

void printImportTableInfo(BYTE* buffer, PResultInfo result, LPCWSTR filePath)
{
    const char* known_dlls[] = {"kernel32", "wow64cpu", "wowarmhw", "xtajit", "advapi32", "clbcatq", "combase", "COMDLG32", "coml2", "difxapi", "gdi32", "gdiplus", "IMAGEHLP", "IMM32", "MSCTF", "MSVCRT", "NORMALIZ", "NSI", "ole32", "OLEAUT32", "PSAPI", "rpcrt4", "sechost", "Setupapi", "SHCORE", "SHELL32", "SHLWAPI", "user32", "WLDAP32", "wow64cpu", "wow64", "wow64base", "wow64con", "wow64win", "WS2_32", "xtajit64"};
    string fileDir = GetDirectoryFromPath(ConvertWideToMultiByte(filePath)) + "\\";
    result->fileDir = fileDir;

    if (hasWritePermission(fileDir))
        result->isWrite = true;
    else
        result->isWrite = false;

    PIMAGE_DOS_HEADER  pDH = (PIMAGE_DOS_HEADER)buffer;
    IMAGE_DATA_DIRECTORY directory;
    DWORD THUNK_DATA_SIZE;

    if (*(PWORD)((size_t)pDH + pDH->e_lfanew + 0x18) == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
    {
        PIMAGE_NT_HEADERS32  pNtH32 = PIMAGE_NT_HEADERS32((size_t)pDH + pDH->e_lfanew);
        PIMAGE_OPTIONAL_HEADER32 pOH32 = &pNtH32->OptionalHeader;

        directory = pOH32->DataDirectory[1];
        THUNK_DATA_SIZE = 4;
        result->bit = 32;
    }
    else {
        PIMAGE_NT_HEADERS64 pNtH64 = PIMAGE_NT_HEADERS64((size_t)pDH + pDH->e_lfanew);
        PIMAGE_OPTIONAL_HEADER64 pOH64 = &pNtH64->OptionalHeader;

        directory = pOH64->DataDirectory[1];
        THUNK_DATA_SIZE = 8;
        result->bit = 64;
    }

    PIMAGE_IMPORT_DESCRIPTOR ImportTable = PIMAGE_IMPORT_DESCRIPTOR(rvaToFOA(buffer, directory.VirtualAddress) + buffer);
    //获取导入dll名称
    char* dllsName = (char*)malloc(0x2000);
    memset(dllsName, 0, 0x2000);
    while (ImportTable->Name)
    {
        char* pName = (char*)(rvaToFOA(buffer, ImportTable->Name) + buffer);
        strcat(dllsName, pName);
        ImportTable++;
    }

    ImportTable = PIMAGE_IMPORT_DESCRIPTOR(rvaToFOA(buffer, directory.VirtualAddress) + buffer);
    while (ImportTable->Name)
    {
        char* pName = (char*)(rvaToFOA(buffer, ImportTable->Name) + buffer);

        PIMAGE_THUNK_DATA INT = PIMAGE_THUNK_DATA(rvaToFOA(buffer, ImportTable->OriginalFirstThunk) + buffer);
        PIMAGE_IMPORT_BY_NAME temp = { 0 };
        int count = 0;
        while (INT->u1.AddressOfData)//当遍历到的是最后一个是时候是会为0，所以随便遍历一个就好
        {
            if (!(INT->u1.Ordinal & 0x80000000))
            {
                temp = (PIMAGE_IMPORT_BY_NAME)(rvaToFOA(buffer, INT->u1.AddressOfData) + buffer);
                if (containsIgnoreCase(temp->Name, "loadlibrary") != NULL)
                {
                    searchDll(buffer, result, filePath, dllsName, fileDir);
                    break;
                }
            }
            INT = PIMAGE_THUNK_DATA((PBYTE)INT + THUNK_DATA_SIZE);//INT在INT数组中下移
            count++;
        }

        char fileFullPath[255] = { 0 };
        strcat(fileFullPath, fileDir.c_str());
        strcat(fileFullPath, pName);

        if (filesystem::exists(filesystem::path(fileFullPath)))
            result->preLoadDlls.push_back(_strdup(pName));

        ImportTable++;
    }

    free(dllsName);
}

BOOL VerifyFileSignature(LPCWSTR filePath) {
    DWORD dwEncoding, dwContentType, dwFormatType;
    HCERTSTORE hStore = NULL;
    HCRYPTMSG hMsg = NULL;
    BOOL bResult = FALSE;

    // Open the file and get the file handle
    HANDLE hFile = CreateFile(filePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        return FALSE;
    }

    // Get the size of the file
    DWORD dwFileSize = GetFileSize(hFile, NULL);

    // Read the file into a buffer
    BYTE* pbFile = (BYTE*)malloc(dwFileSize);
    DWORD dwBytesRead;
    if (!ReadFile(hFile, pbFile, dwFileSize, &dwBytesRead, NULL)) {
        CloseHandle(hFile);
        free(pbFile);
        return FALSE;
    }

    // Verify the signature
    bResult = CryptQueryObject(CERT_QUERY_OBJECT_FILE, filePath, CERT_QUERY_CONTENT_FLAG_ALL,
        CERT_QUERY_FORMAT_FLAG_ALL, 0, &dwEncoding, &dwContentType,
        &dwFormatType, &hStore, &hMsg, NULL);
    if (!bResult) {
        CloseHandle(hFile);
        free(pbFile);
        return FALSE;
    }

    PIMAGE_DOS_HEADER  pDH = (PIMAGE_DOS_HEADER)pbFile;
    IMAGE_DATA_DIRECTORY directory;

    if (*(PWORD)((size_t)pDH + pDH->e_lfanew + 0x18) == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
    {
        PIMAGE_NT_HEADERS32  pNtH32 = PIMAGE_NT_HEADERS32((size_t)pDH + pDH->e_lfanew);
        PIMAGE_OPTIONAL_HEADER32 pOH32 = &pNtH32->OptionalHeader;

        directory = pOH32->DataDirectory[1];
    }
    else {
        PIMAGE_NT_HEADERS64 pNtH64 = PIMAGE_NT_HEADERS64((size_t)pDH + pDH->e_lfanew);
        PIMAGE_OPTIONAL_HEADER64 pOH64 = &pNtH64->OptionalHeader;

        directory = pOH64->DataDirectory[1];
    }
    //没有导入表的程序
    if (directory.VirtualAddress == 0) {
        CloseHandle(hFile);
        free(pbFile);
        return FALSE;
    }
    
    ResultInfo* result = new ResultInfo;
    result->filePath = wstring2string(filePath);
    
    printImportTableInfo(pbFile, result, filePath);

    if (result->preLoadDlls.size() > 0 || result->postLoadDlls.size() > 0) {
        {
            std::lock_guard<std::mutex> lock(mtx);
            results.push_back(result);
        }
    }

    // Clean up resources
    if (hMsg != NULL)
        CryptMsgClose(hMsg);
    if (hStore != NULL)
        CertCloseStore(hStore, CERT_CLOSE_STORE_FORCE_FLAG);
    CloseHandle(hFile);
    free(pbFile);

    return TRUE;
}

int readFileContext(string path, char** contexts)
{
    ifstream inFile(path, std::ios::binary);
    if (!inFile) {
        printf("%s open fail\n", path.c_str());
        return -1;
    }

    inFile.seekg(0, std::ios::end);
    std::streamsize payloadFileSize = inFile.tellg();
    inFile.seekg(0, std::ios::beg);

    *contexts = new char[payloadFileSize];

    if (!inFile.read(*contexts, payloadFileSize)) {
        printf("%s payloadBuffer read fail\n", path.c_str());
        delete[] contexts;
        return -1;
    }

    inFile.close();

    return payloadFileSize;
}

void saveFile(string filePath, char* buffer, DWORD fileSize)
{
    std::ofstream outFile;
    outFile.open(filePath, std::ios::binary | std::ios::trunc);
    outFile.write(buffer, fileSize);
    outFile.close();
}

int fixExportTable(string targetFilePath, string sourceFilePath)
{
    char* targetBuffer;
    DWORD fileSize = readFileContext(targetFilePath, &targetBuffer);

    PIMAGE_DOS_HEADER pDH = (PIMAGE_DOS_HEADER)targetBuffer;
    PIMAGE_NT_HEADERS pNtH = (PIMAGE_NT_HEADERS)((DWORD)pDH + pDH->e_lfanew);
    PIMAGE_OPTIONAL_HEADER pOH = &pNtH->OptionalHeader;
    IMAGE_DATA_DIRECTORY exportDirectory;

    if (*(PWORD)((size_t)pDH + pDH->e_lfanew + 0x18) == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
    {
        PIMAGE_NT_HEADERS32  pNtH32 = PIMAGE_NT_HEADERS32((size_t)pDH + pDH->e_lfanew);
        PIMAGE_OPTIONAL_HEADER32 pOH32 = &pNtH32->OptionalHeader;

        exportDirectory = pOH32->DataDirectory[0];
    }
    else {
        PIMAGE_NT_HEADERS64 pNtH64 = PIMAGE_NT_HEADERS64((size_t)pDH + pDH->e_lfanew);
        PIMAGE_OPTIONAL_HEADER64 pOH64 = &pNtH64->OptionalHeader;

        exportDirectory = pOH64->DataDirectory[0];
    }

    IMAGE_EXPORT_DIRECTORY* exportDir = (IMAGE_EXPORT_DIRECTORY*)(targetBuffer + rvaToFOA(targetBuffer, exportDirectory.VirtualAddress));

    DWORD* nameRVAs = (DWORD*)(targetBuffer + rvaToFOA(targetBuffer, exportDir->AddressOfNames));

    char* sourceBuffer;
    readFileContext(sourceFilePath, &sourceBuffer);

    pDH = (PIMAGE_DOS_HEADER)sourceBuffer;
    pNtH = (PIMAGE_NT_HEADERS)((DWORD)pDH + pDH->e_lfanew);
    pOH = &pNtH->OptionalHeader;

    if (*(PWORD)((size_t)pDH + pDH->e_lfanew + 0x18) == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
    {
        PIMAGE_NT_HEADERS32  pNtH32 = PIMAGE_NT_HEADERS32((size_t)pDH + pDH->e_lfanew);
        PIMAGE_OPTIONAL_HEADER32 pOH32 = &pNtH32->OptionalHeader;

        exportDirectory = pOH32->DataDirectory[0];
    }
    else {
        PIMAGE_NT_HEADERS64 pNtH64 = PIMAGE_NT_HEADERS64((size_t)pDH + pDH->e_lfanew);
        PIMAGE_OPTIONAL_HEADER64 pOH64 = &pNtH64->OptionalHeader;

        exportDirectory = pOH64->DataDirectory[0];
    }

    IMAGE_EXPORT_DIRECTORY* exportDir_source = (IMAGE_EXPORT_DIRECTORY*)(sourceBuffer + rvaToFOA(sourceBuffer, exportDirectory.VirtualAddress));

    DWORD* nameRVAs_source = (DWORD*)(sourceBuffer + rvaToFOA(sourceBuffer, exportDir_source->AddressOfNames));

    for (int i = 0; i < exportDir_source->NumberOfNames; i++)
    {
        DWORD nameRVA_source = nameRVAs_source[i];
        char* exportFunctionName_source = sourceBuffer + rvaToFOA(sourceBuffer, nameRVA_source);

        DWORD nameRVA = nameRVAs[i];
        char* exportFunctionName = targetBuffer + rvaToFOA(targetBuffer, nameRVA);

        memcpy(exportFunctionName, exportFunctionName_source, strlen(exportFunctionName_source)+1);
    }

    saveFile(targetFilePath, targetBuffer, fileSize);

    delete[] targetBuffer;
    delete[] sourceBuffer;

    return 0;
}

std::string GetCurrentPath() {
    char buffer[MAX_PATH];
    GetModuleFileNameA(NULL, buffer, MAX_PATH);
    std::string::size_type pos = std::string(buffer).find_last_of("\\/");
    return std::string(buffer).substr(0, pos);
}

std::string GenerateRandomFolderName() {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<int> dist(1, 1000000);

    // 生成随机字符串作为文件夹名
    const char charset[] = "ghijklmnopq_rstuvwxyz0123456789abcdef";
    const size_t charsetSize = sizeof(charset) - 1;
    const size_t folderNameLength = 10; // 文件夹名长度
    std::string folderName;
    for (size_t i = 0; i < folderNameLength; ++i) {
        folderName += charset[dist(gen) % charsetSize];
    }
    return folderName;
}

string CreateRandomFolder(const std::string& basePath) {
    std::string randomFolderName = GenerateRandomFolderName();
    std::string folderPath = basePath + "\\" + randomFolderName;

    if (CreateDirectoryA(folderPath.c_str(), NULL) || GetLastError() == ERROR_ALREADY_EXISTS) {
        return folderPath;
    }

    return 0;
}

std::wstring ConvertToWideString(const char* input) {
    int length = strlen(input) + 1;
    int requiredLength = MultiByteToWideChar(CP_ACP, 0, input, length, NULL, 0);
    wchar_t* buffer = new wchar_t[requiredLength];
    MultiByteToWideChar(CP_ACP, 0, input, length, buffer, requiredLength);
    std::wstring result(buffer);
    delete[] buffer;
    return result;
}

string CopyFileToFolder(const std::string& sourceFilePath, const std::string& targetFolderPath, bool isNeedHook, bool isPreDll, int bit) {
    std::string targetFilePath = targetFolderPath + "\\" + sourceFilePath.substr(sourceFilePath.find_last_of("\\/") + 1);

    if (isNeedHook) {
        std::string hookFilePath = GetCurrentPath() + "\\TestLoad_x86.dll";
        if (bit == 64)
            hookFilePath = GetCurrentPath() + "\\TestLoad_x64.dll";

        if (isPreDll) {
            CopyFileA(hookFilePath.c_str(), targetFilePath.c_str(), FALSE);
            fixExportTable(targetFilePath, sourceFilePath);
        }
        else {
            CopyFileA(hookFilePath.c_str(), targetFilePath.c_str(), FALSE);
        }
    }
    else {
        CopyFileA(sourceFilePath.c_str(), targetFilePath.c_str(), FALSE);
    }

    return targetFilePath;
}

bool DeleteDirectory(const string& path) {
    WIN32_FIND_DATAA findData;
    HANDLE hFind = FindFirstFileA((path + "\\*").c_str(), &findData);

    if (hFind == INVALID_HANDLE_VALUE) {
        return false;
    }

    do {
        if (strcmp(findData.cFileName, ".") != 0 && strcmp(findData.cFileName, "..") != 0) {
            string filePath = path + "\\" + findData.cFileName;
            if (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                // 递归删除子目录
                if (!DeleteDirectory(filePath)) {
                    FindClose(hFind);
                    return false;
                }
            }
            else {
                // 删除文件
                DWORD fileAttributes = GetFileAttributesA(filePath.c_str());
                !SetFileAttributesA(filePath.c_str(), fileAttributes & ~FILE_ATTRIBUTE_READONLY);

                if (!DeleteFileA(filePath.c_str())) {
                    FindClose(hFind);
                    return false;
                }
            }
        }
    } while (FindNextFileA(hFind, &findData) != 0);

    FindClose(hFind);

    // 删除空目录
    if (!RemoveDirectoryA(path.c_str())) {
        return false;
    }

    return true;
}

int TestCreateProcess(string runFilePath) {
    // 定义进程信息结构体
    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi;

    // 创建进程
    if (!CreateProcessA(
        nullptr,                        // 指向可执行文件名的指针（在这里，nullptr表示使用当前可执行文件）
        (char*)runFilePath.c_str(),     // 可执行文件的路径
        nullptr,                        // 安全属性
        nullptr,                        // 安全属性
        FALSE,                          // 指定是否继承句柄
        CREATE_NO_WINDOW,               // 指定窗口显示方式（这里指定为无窗口）
        nullptr,                        // 指定新进程的环境块
        nullptr,                        // 指定新进程的当前目录
        &si,                            // STARTUPINFO 结构体
        &pi)) {                         // 接收新进程信息的 PROCESS_INFORMATION 结构体
        std::cerr << "Failed to create process. Error code: " << GetLastError() << std::endl;
        return 1;
    }

    // 等待进程结束
    WaitForSingleObject(pi.hProcess, 2 * 1000);

    TerminateProcess(pi.hProcess, 0);

    // 获取进程的退出码
    DWORD exitCode;
    GetExitCodeProcess(pi.hProcess, &exitCode);

    // 输出退出码
    std::cout << runFilePath << " Process exited with code: " << exitCode << std::endl;

    // 关闭进程和线程句柄
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    return 0;
}

void RunPE() {
    std::string currentPath = GetCurrentPath();

    for (const auto& result : results) {
        string folderPath = CreateRandomFolder(currentPath);

        string runFilePath = CopyFileToFolder(result->filePath, folderPath, false, false, result->bit);

        bool flag;
        if (result->preLoadDlls.size() > 0) {
            flag = result->preLoadDlls.size() <= c.dllCount ? true : false;

            for (const auto& dll : result->preLoadDlls) {
                CopyFileToFolder(result->fileDir + dll, folderPath, flag, true, result->bit);
            }
        }

        if (result->postLoadDlls.size() > 0) {
            flag = result->postLoadDlls.size() <= c.dllCount ? true : false;

            for (const auto& dll : result->postLoadDlls) {
                CopyFileToFolder(result->fileDir + dll, folderPath, flag, false, result->bit);
            }
        }

        TestCreateProcess(runFilePath);

        DeleteDirectory(folderPath.c_str());
    }
}