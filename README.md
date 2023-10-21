# Dynamic-PE
POC for making a C++ windows executable that can load and execute functions dynamically at runtime

Provided is a demo dll (Dll5), the sender (Network Sender), a Linux version of the sender (LinuxServer.cpp), and the Loader (Network Loader 3)

Not going to put a technical explanation here because the comments in the code do it pretty well
DO NOTE WINAPI DLLS DO NOT WORK WITH THIS AND THAT WILL NOT BE FIXED (I might do it eventually but that code will be kept private)
To use custom dlls note the __stdcall calling convention must be used with all functions being implimented because the POC parses arguments in the stdcall calling convintion, like winapi functionality, other calling convintions will not be added in a public release

To use simply set the file_path varuable in the sender to the path of the dll you want to load and run the sender and loader (to use on different machines the ips have to be changed because they are hardcoded to localhost port 4444)

Huge credit to https://github.com/adamhlt/Manual-DLL-Loader as the code for managing address relocations and imported libraies was heavily based off the code for his Dll loader
