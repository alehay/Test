#include <windows.h>
#include <stdio.h>
#include <wincrypt.h>
#include <iostream>
#include <fstream>
#include <string>
#include <sysinfoapi.h>
#include <stdio.h>
#include <stdlib.h>
#include <chrono>
#include <vector>
#include <thread>

#define DEBUG
//#define TREAD_ON

#ifdef DEBUG

#define _CRTDBG_MAP_ALLOC
#include <stdlib.h>
#include <crtdbg.h>

#endif // DEBUG

const int MD5_SIZE = 32; 

void my_itoa (int num, BYTE*  stringNum ,  int size , int  radix =10) {
	char tmp[16];
	char* tp = tmp;
	int i;
	unsigned v;
	v = (unsigned)num;
	while (v || tp == tmp) {
		i = v % radix;
		v /= radix; 
		if (i < 10)
		* tp++ = i + '0';
		else
			*tp++ = i + 'a' - 10;
	}
	int len = tp - tmp;
	int index{ 0 };
	while (size) {
		if (len)  {
			stringNum[size - 1] = tmp[index];
		}
		else {
			stringNum[size - 1] = '0';
		}
		--len;
		--size;
		++index; 
	}	
}

void HashMD5(const BYTE * const data,BYTE * strHash, DWORD* result, int size) {
	DWORD dwStatus = 0;
	DWORD cbHash = 16;
	int i = 0;
	HCRYPTPROV cryptProv;
	HCRYPTHASH cryptHash;
	BYTE hash[16];
	const char* hex = "0123456789abcdef";
	if (!CryptAcquireContext(&cryptProv, NULL, MS_ENH_RSA_AES_PROV, PROV_RSA_AES, CRYPT_VERIFYCONTEXT))  {
	//if (!CryptAcquireContext(&cryptProv, NULL, MS_DEF_PROV, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
		dwStatus = GetLastError();
		printf("CryptAcquireContext failed: %d\n", dwStatus);
		*result = dwStatus;
	}  // +57kb - течет память. я не понимаю почему. 
	if (!CryptCreateHash(cryptProv, CALG_MD5, 0, 0, &cryptHash)) {
		dwStatus = GetLastError();
		printf("CryptCreateHash failed: %d\n", dwStatus);
		CryptReleaseContext(cryptProv, 0);
		*result = dwStatus;
	}
	if (!CryptHashData(cryptHash, (BYTE*)data, size, 0)) {
		dwStatus = GetLastError();
		printf("CryptHashData failed: %d\n", dwStatus);
		CryptReleaseContext(cryptProv, 0);
		CryptDestroyHash(cryptHash);
		*result = dwStatus;
	}
	if (!CryptGetHashParam(cryptHash, HP_HASHVAL, hash, &cbHash, 0)) {
		dwStatus = GetLastError();
		printf("CryptGetHashParam failed: %d\n", dwStatus);
		CryptReleaseContext(cryptProv, 0);
		CryptDestroyHash(cryptHash);
		*result = dwStatus;
	}
	for (i = 0; i < cbHash; i++) {
		strHash[i * 2] = hex[hash[i] >> 4];
		strHash[(i * 2) + 1] = hex[hash[i] & 0xF];
	}
	CryptReleaseContext(cryptProv, 0);
	CryptDestroyHash(cryptHash);
	// не обождает память! течет очень страшно. 
}

BYTE* bruteForce(BYTE* const ref,
				int  size,
				int start,
				int stop,
				int step) {

	DWORD* status = 0;
	char temp[MD5_SIZE];
	BYTE hash[MD5_SIZE];
	BYTE * buffer = new BYTE[size];
	for (unsigned int i = start; i <= stop; i += step) {
		
		//_itoa_s не работает как надо ....
		my_itoa(i, buffer, size , 10);
		
		HashMD5(buffer, hash, status , size);
		for (int j = 0; j < MD5_SIZE; j++) {
			if (ref[j] != hash[j]) {
				break;
			} 
			if (j == MD5_SIZE - 1) {
				return buffer;
			}
		}
	}
	delete buffer;
	//return NULL; 
}


int main() {
	SYSTEM_INFO sysinfo;
	GetSystemInfo(&sysinfo);
	
	setlocale(LC_ALL, "Russian");
	char * myHashTemp;

	DWORD result = 0;
	BYTE hash_test[MD5_SIZE] ;
	std::string path = "hash.txt" ;	
	std::ifstream fileIn;
	fileIn.open(path);
	BYTE * password = nullptr ;
	BYTE * password1; 

	if (!fileIn.is_open()) {
		std::cout << "hash.txt не найден" << std::endl; 
	}
	std::string temp; 
	std::getline(fileIn, temp);
	fileIn.close();
	if (temp.size() != MD5_SIZE) {
		std::cout << "не соотвествие длинны ! " << std::endl;
	}

	for (int i = 0; i < MD5_SIZE; ++i) {
		BYTE ch;
		ch = std::tolower(temp.at(i));
		if (! isxdigit(ch)) {
			std::cout << "неверный символ ! : " << i + 1 << std::endl;
			break; 
		}
		hash_test[i] = ch; 
	}

#ifdef TREAD_ON
	std::vector <std::thread > treadRun;
	int core = sysinfo.dwNumberOfProcessors;
	for (int tr_id = 1; tr_id <= core; ++tr_id) {
		std::thread th([&password, &hash_test, &core , &tr_id]() {
			password = bruteForce(hash_test, 8, 800000 + tr_id , 99999999, core);
			});
		th.detach();
		treadRun.push_back (move(th));
	}
#endif // TREAD_ON

#ifndef TREAD_ON
	password =  bruteForce(hash_test, 8, 1234567 - 100 , 12345678, 1);
#endif // !TREAD_ON

#ifdef TREAD_ON
	while ( !password ) {
		std::this_thread::sleep_for(std::chrono::microseconds(1000));
	}
#endif // TREAD_ON

	for (int i = 0; i < 8; i++) {
		std::cout << password[i];
	}
#ifdef DEBUG
	_CrtDumpMemoryLeaks();
#endif // DEBUG


}