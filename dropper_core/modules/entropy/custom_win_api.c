/*
	file that contians the CRT functions replacement, in addition to the string hashing functions
*/
#include "entropy.h"


float _fltused = 0;


UINT32 HashStringJenkinsOneAtATime32BitA(_In_ PCHAR String)
{
	SIZE_T Index = 0;
	UINT32 Hash = 0;
	SIZE_T Length = lstrlenA(String);

	while (Index != Length)
	{
		Hash += String[Index++];
		Hash += Hash << INITIAL_SEED;
		Hash ^= Hash >> 6;
	}

	Hash += Hash << 3;
	Hash ^= Hash >> 11;
	Hash += Hash << 15;

	return Hash;
}


UINT32 HashStringJenkinsOneAtATime32BitW(_In_ PWCHAR String)
{
	SIZE_T Index = 0;
	UINT32 Hash = 0;
	SIZE_T Length = lstrlenW(String);

	while (Index != Length)
	{
		Hash += String[Index++];
		Hash += Hash << INITIAL_SEED;
		Hash ^= Hash >> 6;
	}

	Hash += Hash << 3;
	Hash ^= Hash >> 11;
	Hash += Hash << 15;

	return Hash;
}


CHAR _toUpper(CHAR C)
{
	if (C >= 'a' && C <= 'z')
		return C - 'a' + 'A';

	return C;
}

extern void* __cdecl memset(void*, int, size_t);
#pragma intrinsic(memset)
#pragma function(memset)

void* __cdecl memset(void* Destination, int Value, size_t Size) {
	unsigned char* p = (unsigned char*)Destination;
	while (Size > 0) {
		*p = (unsigned char)Value;
		p++;
		Size--;
	}
	return Destination;
}


#define RAND_MAX 32767

unsigned int bit_recycler = 0;
unsigned int rand_seed = 0;

int _rand()
{
    unsigned int oldbits = bit_recycler >> 23;
    bit_recycler = (bit_recycler << 7) + (rand_seed >> 23);
    rand_seed = (rand_seed * 83 + 13) ^ (rand_seed >> 17) ^ (oldbits);
    return rand_seed % RAND_MAX;
}

void _srand(unsigned int seed)
{
    rand_seed = seed;
    bit_recycler = 0;
}

VOID _RtlInitUnicodeString(OUT PUNICODE_STRING UsStruct, IN OPTIONAL PCWSTR Buffer) {

	if ((UsStruct->Buffer = (PWSTR)Buffer)) {

		unsigned int Length = wcslen(Buffer) * sizeof(WCHAR);
		if (Length > 0xfffc)
			Length = 0xfffc;

		UsStruct->Length = Length;
		UsStruct->MaximumLength = UsStruct->Length + sizeof(WCHAR);
	}

	else UsStruct->Length = UsStruct->MaximumLength = 0;
}

PVOID _memcpy(PVOID Destination, CONST PVOID Source, SIZE_T Length)
{
	PBYTE D = (PBYTE)Destination;
	PBYTE S = (PBYTE)Source;

	while (Length--)
		*D++ = *S++;

	return Destination;
}

wchar_t* _strcpy(wchar_t* dest, const wchar_t* src)
{
    wchar_t* p;

    if ((dest == NULL) || (src == NULL))
        return dest;

    if (dest == src)
        return dest;

    p = dest;
    while (*src != 0) {
        *p = *src;
        p++;
        src++;
    }

    *p = 0;
    return dest;
}

wchar_t* _strcat(wchar_t* dest, const wchar_t* src)
{
    if ((dest == NULL) || (src == NULL))
        return dest;

    while (*dest != 0)
        dest++;

    while (*src != 0) {
        *dest = *src;
        dest++;
        src++;
    }

    *dest = 0;
    return dest;
}