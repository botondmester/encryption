#include <iostream>
#include <array>
#include <vector>
#include <random>
#include <cstring>
#include "base64.h"

std::array<unsigned char, 256> subst = {
     57, 79, 85,216, 51, 98,219, 76,243, 42, 13,182,148, 10, 65,152,
    118,165,101, 62,155, 80,170, 70,255,106,142,228, 92,193,115, 96,
    119,249,211,104, 97, 66,150,133,217,108,  9,234,254,117,134,121,
     94,212,223,  4,196,202,176,251,126,  0,206,168, 67, 84, 19,164,
    105, 14, 37, 60,185,153, 23,110,204,218,239,120,  7,187,160,  1,
     21,146,226,203, 61,  2,109,161,180,245,199,192, 28,103, 48,132,
     31, 36,  5,137,198, 18,250, 93, 35, 64, 25,125, 41, 86, 71,173,
    116,130,171, 30,112, 45, 16, 32, 75, 47,232,162,248,107, 56,224,
    158,237,113,139, 95, 39, 46,197,236, 99,227,131,252,210, 26,175,
    238,220, 81,209, 12,178, 38,208, 15, 69,200, 20,244,159,128,157,
     78, 87,123,231, 63, 17,169,172, 59,166, 22,114,167,111,215,143,
     54,201,149,214, 88,184, 11,246,181, 68,191, 77,247,242,240,186,
     91, 29,225,253, 52,135,100, 90,154,177, 53, 83, 72,229, 58,235,
    151,147,141, 34, 49,221,179,174,  3, 40, 73,  6,145,213,241, 50,
    127,194, 82,138, 27,205,233,163,122,230, 43,207,136,129,144, 74,
    190,222,189,  8,156, 89,183,188,124, 33,102, 55,140,195, 44, 24
};

void xorBlock(std::array<unsigned char, 64> &a, std::array<unsigned char, 64> &b) {
    for (size_t i = 0; i < 64; i++) {
        a[i] ^= b[i];
    }
}

void barrelShiftLeftBlock(std::array<unsigned char, 64> &block) {
    for (size_t i = 0; i < 63; i++) {
        std::swap(block[i], block[i + 1]);
    }
}

void barrelShiftRightBlock(std::array<unsigned char, 64> &block) {
    for (size_t i = 63; i > 0; i--) {
        std::swap(block[i], block[i - 1]);
    }
}

std::array<unsigned char, 64> encryptBlock(std::array<unsigned char, 64> input, std::array<unsigned char, 64> key) {
    for (size_t n = 0; n < 64; n++) {
        xorBlock(input, key);

        for (size_t i = 0; i < 64; i++) {
            input[i] = subst[input[i]];
        }

        xorBlock(input, key);

        barrelShiftLeftBlock(input);
    }

    return input;
}

std::array<unsigned char, 64> decryptBlock(std::array<unsigned char, 64> input, std::array<unsigned char, 64> key) {
    for (size_t n = 0; n < 64; n++) {
        barrelShiftRightBlock(input);

        xorBlock(input, key);

        for (size_t i = 0; i < 64; i++) {
            input[i] = subst[input[i]];
        }

        xorBlock(input, key);
    }

    return input;
}

std::vector<unsigned char> encrypt(std::vector<unsigned char> &input, std::array<unsigned char, 64> key) {
    std::vector<unsigned char> data, out;
    data.push_back(input.size() & 0xff); // store data length (32 bit)
    data.push_back((input.size() & 0xff00) >> 8);
    data.push_back((input.size() & 0xff0000) >> 16);
    data.push_back((input.size() & 0xff000000) >> 24);
    for (size_t i = 0; i < input.size(); i++) {
        data.push_back(input[i]);
    }
    while (data.size() % 64 != 0) {
        data.push_back(rand()); // pad it out with junk data *trolling intensifies*
    }

    for (size_t i = 0; i < data.size(); i += 64) {
        std::array<unsigned char, 64> block{};
        for (size_t j = 0; j < 64; j++) {
            block[j] = data[i + j];
        }
        block = encryptBlock(block, key);
        for (size_t j = 0; j < 64; j++) {
            out.push_back(block[j]);
        }
    }

    return out;
}

std::vector<unsigned char> decrypt(std::vector<unsigned char>& input, std::array<unsigned char, 64> key) {
    std::vector<unsigned char> data, out;

    for (size_t i = 0; i < input.size(); i += 64) {
        std::array<unsigned char, 64> block;
        for (size_t j = 0; j < 64; j++) {
            block[j] = input[i + j];
        }
        block = decryptBlock(block, key);
        for (size_t j = 0; j < 64; j++) {
            data.push_back(block[j]);
        }
    }

    size_t len = 0;
    len |= (size_t)data[0]; // get actual data length
    len |= (size_t)data[1] << 8;
    len |= (size_t)data[2] << 16;
    len |= (size_t)data[3] << 24;

    for (size_t i = 0; i < len; i++) {
        out.push_back(data[i+4]);
    }

    return out;
}

std::string vectorToString(std::vector<unsigned char> &inp) {
    return std::string(inp.begin(), inp.end());
}

void printUsage(std::string name) {
    std::cout << "Usage: " << name << " <decrypt|encrypt> [key] message\n\t key: optinal in case of encryption but required for decryption (generates one randomly if it's missing)\n";
}

int main(int argc, char** argv)
{
    if (argc < 3 || argc > 4) {
        printUsage(argv[0]);
        exit(EXIT_FAILURE);
    }


    if (strncmp("encrypt", argv[1], 7) == 0) {
        if (argc == 3) {
            std::string inp = argv[2];
            std::vector<unsigned char> a(inp.begin(), inp.end());

            std::array<unsigned char, 64> key{};
            // generate random key
            std::random_device device;
            std::default_random_engine rng(device());
            std::uniform_int_distribution<int> dist(0, 255);
            for (size_t i = 0; i < 64; i++) {
                key[i] = (unsigned char)dist(rng);
            }

            std::cout << "Key: " << base64_encode(std::string(key.begin(), key.end())) << std::endl;

            std::vector<unsigned char> b = encrypt(a, key);

            std::cout << "Encrypted message: " << base64_encode(std::string(b.begin(), b.end())) << std::endl;

            exit(EXIT_SUCCESS);
        }

        if (argc == 4) {
            std::string base64Key = argv[2];
            std::string inpKey = base64_decode(base64Key);
            if (inpKey.length() < 64) {
                std::cout << "Key too short." << std::endl;
                printUsage(argv[0]);
                exit(EXIT_FAILURE);
            }
            std::array<unsigned char, 64> key{};
            for (size_t i = 0; i < 64; i++) {
                key[i] = inpKey[i];
            }
            std::string inp = argv[3];
            std::vector<unsigned char> a(inp.begin(), inp.end());

            std::vector<unsigned char> b = encrypt(a, key);

            std::cout << "Encrypted message: " << base64_encode(std::string(b.begin(), b.end())) << std::endl;

            exit(EXIT_SUCCESS);
        }
    }

    if (strncmp("decrypt", argv[1], 7) == 0) {
        if (argc != 4) {
            printUsage(argv[0]);
            exit(EXIT_FAILURE);
        }

        std::string base64Key = argv[2];
        std::string inpKey = base64_decode(base64Key);
        if (inpKey.length() < 64) {
            std::cout << "Key too short." << std::endl;
            printUsage(argv[0]);
            exit(EXIT_FAILURE);
        }
        std::array<unsigned char, 64> key{};
        for (size_t i = 0; i < 64; i++) {
            key[i] = inpKey[i];
        }
        std::string base64Inp = argv[3];
        std::string inp = base64_decode(base64Inp);
        std::vector<unsigned char> a(inp.begin(), inp.end());

        std::vector<unsigned char> b = decrypt(a, key);

        std::cout << "Decrypted message: " << std::string(b.begin(), b.end()) << std::endl;
        exit(EXIT_SUCCESS);
    }

    printUsage(argv[0]);
    exit(EXIT_FAILURE);
}
