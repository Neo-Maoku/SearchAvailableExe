#include "Tools.h"

extern vector<PResultInfo> results;
std::unordered_map<std::string, std::wstring> md5Map;
std::mutex mtx;

std::string calculateMD5(BYTE* buffer, DWORD bytesRead) {
    std::string md5;

    // 初始化加密API
    HCRYPTPROV hProv = 0;
    if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
        std::cerr << "CryptAcquireContext failed\n";
        return md5;
    }

    HCRYPTHASH hHash = 0;
    if (!CryptCreateHash(hProv, CALG_MD5, 0, 0, &hHash)) {
        std::cerr << "CryptCreateHash failed\n";
        CryptReleaseContext(hProv, 0);
        return md5;
    }

    // 读取文件并更新哈希值
    if (!CryptHashData(hHash, buffer, bytesRead, 0)) {
        std::cerr << "CryptHashData failed\n";
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return md5;
    }

    // 获取哈希值
    DWORD hashSize = 16; // MD5 哈希值大小为 16 字节
    BYTE hashBuffer[16];
    if (CryptGetHashParam(hHash, HP_HASHVAL, hashBuffer, &hashSize, 0)) {
        std::stringstream ss;
        ss << std::hex << std::setfill('0');
        for (int i = 0; i < hashSize; ++i) {
            ss << std::setw(2) << static_cast<unsigned int>(hashBuffer[i]);
        }
        md5 = ss.str();
    }
    else {
        std::cerr << "CryptGetHashParam failed\n";
    }

    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);

    return md5;
}

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

bool endsWithDLL(const std::string& str) {
    int strLength = str.length();
    for (size_t i = 0; i < strLength; i += 2) {
        char ch = str[i];
        if (!((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') || ch == '_' || ch == '.' || ch == '-'))
            return false;
    }

    return str.size() > 4 && str.compare(str.size() - 4, 4, ".dll") == 0;
}

bool endsWithDLL(const std::wstring& str) {
    int strLength = str.length();
    for (size_t i = 0; i < strLength; i += 2) {
        wchar_t ch = str[i];
        if (!((ch >= L'a' && ch <= L'z') || (ch >= L'A' && ch <= L'Z') || (ch >= L'0' && ch <= L'9') || ch == L'_' || ch == L'.' || ch == L'-'))
            return false;
    }

    return str.size() > 4 && str.compare(str.size() - 4, 4, L".dll") == 0;
}

void searchDll(BYTE* buffer, PResultInfo result, LPCWSTR filePath, char* dllsName, string fileDir) {
    DWORD rdataLength;
    BYTE* rdata = readRDataSection(buffer, &rdataLength);
    if (rdata != 0) {
        LPVOID str = (LPVOID)malloc(255);
        DWORD begin = 0;
        int fileDirLength = fileDir.length();

        for (size_t i = 0; i < rdataLength; ++i) {
            char ch = rdata[i];
            if (ch == '\0') {
                if (i - begin > 10 && i - begin < 30) {
                    memcpy(str, rdata + begin, i + 1 - begin);
                    if (endsWithDLL((char*)str)) {
                        char fileFullPath[255] = { 0 };
                        strcat(fileFullPath, fileDir.c_str());
                        strcat(fileFullPath, (char*)str);

                        if (filesystem::exists(filesystem::path(fileFullPath)) && containsIgnoreCase(dllsName, (char*)str) == NULL)
                            result->postLoadDlls.push_back(_strdup((char*)str));
                    }
                }
                begin = i + 1;
            }
        }

        begin = 0;
        for (size_t i = 0; i < rdataLength; i += 2) {
            wchar_t ch = rdata[i];

            if (ch == L'\0') {
                if (i - begin > 10 && i - begin < 60) {
                    memcpy(str, rdata + begin, i + 2 - begin);
                    if (endsWithDLL((wchar_t*)str)) {
                        char fileFullPath[255] = { 0 };
                        strcat(fileFullPath, fileDir.c_str());
                        strcat(fileFullPath, ConvertWideToMultiByte((wchar_t*)str));

                        if (filesystem::exists(filesystem::path(fileFullPath)) && containsIgnoreCase(dllsName, ConvertWideToMultiByte((wchar_t*)str)) == NULL)
                            result->postLoadDlls.push_back(_strdup((char*)(wstring2string((wchar_t*)str).c_str())));
                    }
                }
                begin = i + 2;
            }
        }
        free(str);
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
        DWORD nameSize = sizeof(known_dlls) / 4;
        bool flag = true;
        
        for (int i = 0; i < nameSize; i++)
        {
            if (containsIgnoreCase(pName, known_dlls[i]) != NULL)
            {
                flag = false;
                break;
            }
        }

        PIMAGE_THUNK_DATA INT = PIMAGE_THUNK_DATA(rvaToFOA(buffer, ImportTable->OriginalFirstThunk) + buffer);
        PIMAGE_THUNK_DATA IAT = PIMAGE_THUNK_DATA(rvaToFOA(buffer, ImportTable->FirstThunk) + buffer);
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
            flag = true;
        
        if (flag)
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

    /*string md5 = calculateMD5(pbFile, dwFileSize);
    {
        std::lock_guard<std::mutex> lock(mtx);
        if (md5Map.find(md5) != md5Map.end())
            return FALSE;

        md5Map[md5] = filePath;
    }*/
    
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