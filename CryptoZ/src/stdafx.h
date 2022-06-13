#pragma once

#define WIN32_LEAN_AND_MEAN
#define _CRT_SECURE_NO_WARNINGS

#include <Windows.h>
#include <iostream>
#include <vector>
#include <iterator>
#include <algorithm>
#include <string>
#include <sstream>
#include <memory>
#include <cmath>
#include <stdexcept>
#include <type_traits>

#include <bcrypt.h>
#pragma comment(lib, "Bcrypt.lib")

#include <wincrypt.h>
#pragma comment(lib, "crypt32.lib")

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status)	((NTSTATUS)(Status) >= 0)
#endif

#define xmalloc(x) HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (x))
#define xfree(x) HeapFree(GetProcessHeap(), 0, (x))