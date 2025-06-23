#include <openssl/aes.h>

// Déchiffrement AES segmenté (32 octets)
void DecryptAESChunk(PVOID dest, PVOID src, PVOID key) {
    AES_KEY aesKey;
    AES_set_decrypt_key(key, 128, &aesKey);
    AES_decrypt(src, dest, &aesKey);
}

// Wiping des clés AES après usage
void WipeAESKey(PVOID key, SIZE_T keySize) {
    SecureZeroMemory(key, keySize);
    HeapFree(GetProcessHeap(), 0, key);
}