#pragma once

//Defines functions to export
//ALL FUNCTIONS MUST USE __stdcall CALLING CONVENTION
#define TEST_API __declspec(dllexport)
extern "C" TEST_API void __stdcall test_print(const char* str);
extern "C" TEST_API int __stdcall add(int a, int b);
extern "C" TEST_API void __stdcall hello();
extern "C" TEST_API void __stdcall shell(const char* ip, short port);