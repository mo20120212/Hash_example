﻿#include <iostream>
#include <string>
#include <vector>
#include <Windows.h>
#include <fstream>
#include <memory>
#include <stdexcept>
#include <openssl/sha.h>
#include <unordered_map>
#include <iomanip>
#include <random>
#include <sstream>
#include <openssl/evp.h>

using namespace std;

class FileManager {
public:
    // 读取文件内容
    static vector<string> readConfig(const string& filename) {
        if (!fileExists(filename)) {
            createEmptyFile(filename);
            return {};
        }

        ifstream file(filename);
        if (!file.is_open()) {
            throw runtime_error("Failed to open file: " + filename);
        }

        vector<string> lines;
        string line;
        while (getline(file, line)) {
            if (!line.empty()) {
                lines.push_back(line);
            }
        }
        return lines;
    }

    // 写入文件内容
    static void writeConfig(const string& filename, const vector<string>& contents, bool append = false) {
        ios_base::openmode mode = ios::out;
        if (append) {
            mode |= ios::app;
        }

        ofstream file(filename, mode);
        if (!file.is_open()) {
            throw runtime_error("Failed to write to file: " + filename);
        }

        for (const auto& line : contents) {
            file << line << '\n';
        }
    }

    // 生成随机盐值（增强安全性）
    static string generateSalt() {
        constexpr int SALT_LENGTH = 32;
        static const char alphanum[] =
            "0123456789"
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
            "abcdefghijklmnopqrstuvwxyz";

        random_device rd;
        mt19937 gen(rd());
        uniform_int_distribution<> dist(0, sizeof(alphanum) - 2);

        string salt;
        salt.reserve(SALT_LENGTH);
        for (int i = 0; i < SALT_LENGTH; ++i) {
            salt += alphanum[dist(gen)];
        }
        return salt;
    }

    // 使用正确的SHA256函数
    static string hashPassword(const string& password, const string& salt) {
        string saltedPassword = password + salt;
        unsigned char hash[SHA256_DIGEST_LENGTH];

        // 使用EVP接口替代已弃用的函数
        EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
        if (mdctx == nullptr) {
            throw runtime_error("Failed to create EVP context");
        }

        if (1 != EVP_DigestInit_ex(mdctx, EVP_sha256(), nullptr)) {
            EVP_MD_CTX_free(mdctx);
            throw runtime_error("Digest init failed");
        }

        if (1 != EVP_DigestUpdate(mdctx, saltedPassword.c_str(), saltedPassword.size())) {
            EVP_MD_CTX_free(mdctx);
            throw runtime_error("Digest update failed");
        }

        unsigned int len = 0;
        if (1 != EVP_DigestFinal_ex(mdctx, hash, &len)) {
            EVP_MD_CTX_free(mdctx);
            throw runtime_error("Digest final failed");
        }

        EVP_MD_CTX_free(mdctx);

        stringstream ss;
        for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
            ss << hex << setw(2) << setfill('0') << static_cast<int>(hash[i]);
        }
        return ss.str();
    }

private:
    // 改进文件存在检查
    static bool fileExists(const string& filename) {
        ifstream file(filename);
        return file.good() && file.is_open();
    }

    // 创建空文件（添加异常处理）
    static void createEmptyFile(const string& filename) {
        ofstream file(filename);
        if (!file) {
            throw runtime_error("Failed to create config file: " + filename);
        }
        file.close();  // 显式关闭文件
    }
};



class UserManager {
public:
    UserManager() : fileManager(make_unique<FileManager>()) {}

    // 创建用户（增加输入验证）
    void createUser() {
        system("cls");
        string username, password;

        cout << "Please enter user name (3-20 characters, a-z0-9_):\n->";
        while (true) {
            cin >> username;
            if (isValidUsername(username)) break;
            cout << "Invalid username format. Try again:\n->";
        }

        if (isUserExists(username)) {
            cout << "User name is already in use.\n";
            return;
        }

        cout << "Please enter user password (min 8 characters):\n->";
        while (true) {
            cin >> password;
            if (password.length() >= 8) break;
            cout << "Password too short. Minimum 8 characters:\n->";
        }

        string salt = FileManager::generateSalt();
        string hashedPassword = FileManager::hashPassword(password, salt);

        FileManager::writeConfig("USER.cfg", { username }, true);
        FileManager::writeConfig("SALT.cfg", { salt }, true);
        FileManager::writeConfig("PASSWORD.cfg", { hashedPassword }, true);

        cout << "User created successfully!\n";
        Sleep(2000);
    }

    // 用户名格式验证
    bool isValidUsername(const string& username) {
        constexpr size_t MIN_LENGTH = 3;
        constexpr size_t MAX_LENGTH = 20;
        if (username.length() < MIN_LENGTH || username.length() > MAX_LENGTH)
            return false;

        return username.find_first_not_of("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_") == string::npos;
    }

    // 用户存在检查（使用哈希表优化）
    bool isUserExists(const string& username) {
        static unordered_map<string, bool> userCache;
        static bool cacheLoaded = false;

        if (!cacheLoaded) {
            auto users = FileManager::readConfig("USER.cfg");
            for (const auto& user : users) {
                userCache[user] = true;
            }
            cacheLoaded = true;
        }

        return userCache.find(username) != userCache.end();
    }

    // 用户认证（增加尝试次数限制）
    bool authenticateUser(const string& username, const string& password, int maxAttempts = 3) {
        static unordered_map<string, int> attemptCount;

        if (attemptCount[username] >= maxAttempts) {
            cout << "Account locked due to too many failed attempts.\n";
            return false;
        }

        auto users = FileManager::readConfig("USER.cfg");
        auto salts = FileManager::readConfig("SALT.cfg");
        auto passwords = FileManager::readConfig("PASSWORD.cfg");

        for (size_t i = 0; i < users.size(); ++i) {
            if (users[i] == username) {
                string hashedPassword = FileManager::hashPassword(password, salts[i]);
                if (hashedPassword == passwords[i]) {
                    attemptCount[username] = 0;
                    return true;
                }
            }
        }

        attemptCount[username]++;
        return false;
    }

private:
    unique_ptr<FileManager> fileManager;
};


void exitProgram() {
    system("cls");
    cout << "\aThanks for using!";
    Sleep(2000);
    exit(0);
}

void adminMenu(UserManager& userManager) {
    while (true) {
        system("cls");
        cout << "Welcome Admin\nServices: 0 - Create an account, 1 - Manage an account, 2 - Exit the service\n->";
        string choice;
        cin >> choice;

        if (choice == "0") {
            userManager.createUser();
        } else if (choice == "1") {
            // Manage account logic
        } else if (choice == "2") {
            exitProgram();
        } else {
            cout << "Invalid choice. Please try again.\n";
            Sleep(1000);
        }
    }
}

int main() {
    try {
        UserManager userManager;
        string username, password;
        bool 超管;
        超管 = false;
        cout << "Welcome!\nPlease enter your username. Enter /exit to exit\n->";
        cin >> username;

        if (username == "/exit") {
            exitProgram();
        }

        cout << "Please enter your password\n->";
        cin >> password;
        if (password == "/exit") {
            exitProgram();
        }
        if (username == "Admin" && password=="Super_Admin1234" || 超管) {
            adminMenu(userManager);
        } else if (userManager.authenticateUser(username, password)) {
            cout << "Welcome, " << username << "!\n";
            // User menu logic
        } else {
            cout << "Invalid username or password.\n";
        }
    } catch (const exception& e) {
        cerr << "Error: " << e.what() << endl;
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
