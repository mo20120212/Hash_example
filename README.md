It's a example for hash , filesteam and so on.  
It's in building.  
TMD英文太难写了，一下是中文.|TMD English is hard to write.Following is Chinese.  If you not know or speak Chinese you can use translation.  
---
说明:
以下是代码中各函数的详细解析及其输入值、作用说明：

---

### **1. `FileManager` 类**
#### **1.1 `readConfig`**
- **功能**：读取配置文件内容。
- **输入**：
  - `filename`：字符串，表示要读取的文件名（如 `USER.cfg`）。
- **作用**：
  - 检查文件是否存在，不存在则创建空文件。
  - 逐行读取文件内容，过滤空行后返回字符串向量。
- **示例**：
  ```cpp
  auto users = FileManager::readConfig("USER.cfg"); // 读取所有用户名
  ```

#### **1.2 `writeConfig`**
- **功能**：向文件写入内容。
- **输入**：
  - `filename`：目标文件名。
  - `contents`：字符串向量，表示要写入的内容。
  - `append`：布尔值，默认为 `false`，表示是否追加写入。
- **作用**：
  - 以覆盖或追加模式打开文件，逐行写入内容。
- **示例**：
  ```cpp
  FileManager::writeConfig("USER.cfg", {"Alice", "Bob"}, true); // 追加两个用户名
  ```

#### **1.3 `generateSalt`**
- **功能**：生成随机盐值。
- **输入**：无。
- **作用**：
  - 使用随机数生成器生成包含字母和数字的 32 位随机字符串。
- **示例**：
  ```cpp
  string salt = FileManager::generateSalt(); // 生成类似 "aB3x9Z..." 的盐值
  ```

#### **1.4 `hashPassword`**
- **功能**：使用 SHA-256 哈希算法加密密码。
- **输入**：
  - `password`：明文密码字符串。
  - `salt`：盐值字符串。
- **作用**：
  - 将密码与盐值拼接后生成哈希值，返回 64 位的十六进制字符串。
- **示例**：
  ```cpp
  string hash = FileManager::hashPassword("123456", "salt"); // 返回哈希值如 "a1b2c3..."
  ```

#### **1.5 `fileExists`**
- **功能**：检查文件是否存在。
- **输入**：`filename` 文件名。
- **作用**：
  - 通过尝试打开文件判断其是否存在。

#### **1.6 `createEmptyFile`**
- **功能**：创建空文件。
- **输入**：`filename` 文件名。
- **作用**：
  - 若文件不存在，则创建空文件。

---

### **2. `UserManager` 类**
#### **2.1 `createUser`**
- **功能**：创建新用户。
- **输入**：通过控制台输入用户名和密码。
- **作用**：
  - 验证用户名格式（3-20 位字母、数字或下划线）。
  - 检查用户名是否已存在。
  - 生成盐值并哈希密码。
  - 将用户名、盐值和哈希密码分别写入 `USER.cfg`、`SALT.cfg`、`PASSWORD.cfg`。

#### **2.2 `isValidUsername`**
- **功能**：验证用户名合法性。
- **输入**：`username` 用户名。
- **作用**：
  - 检查长度（3-20 位）和字符范围（仅允许字母、数字、下划线）。

#### **2.3 `isUserExists`**
- **功能**：检查用户是否存在。
- **输入**：`username` 用户名。
- **作用**：
  - 使用哈希表缓存用户列表，快速判断用户名是否存在。

#### **2.4 `authenticateUser`**
- **功能**：用户认证。
- **输入**：
  - `username`：用户名。
  - `password`：密码。
  - `maxAttempts`：最大尝试次数（默认 3 次）。
- **作用**：
  - 验证用户名和密码是否匹配。
  - 记录失败尝试次数，超过限制则锁定账户。

---

### **3. 其他函数**
#### **3.1 `exitProgram`**
- **功能**：退出程序。
- **输入**：无。
- **作用**：
  - 清屏并显示退出消息，2 秒后关闭程序。

#### **3.2 `adminMenu`**
- **功能**：管理员菜单。
- **输入**：`UserManager` 实例的引用。
- **作用**：
  - 提供选项：创建账户、管理账户、退出。
  - 根据用户输入调用 `createUser` 或退出。

#### **3.3 `main`**
- **功能**：程序入口。
- **作用**：
  - 初始化 `UserManager`。
  - 用户输入用户名和密码，验证是否为管理员或普通用户。
  - 根据验证结果进入管理员菜单或用户界面。

---

### **关键输入值与作用**
| **函数/类**       | **输入值**              | **作用**                                |
|--------------------|-------------------------|----------------------------------------|
| `main`             | 用户名、密码            | 验证身份并进入对应菜单                  |
| `createUser`       | 用户名、密码            | 创建新用户并存储加密信息                |
| `authenticateUser` | 用户名、密码、尝试次数  | 验证用户合法性，防止暴力破解            |
| `hashPassword`     | 密码、盐值              | 生成安全密码哈希                        |

---

### **安全性说明**
1. **密码存储**：使用盐值 + SHA-256 哈希，避免明文存储密码。
2. **输入验证**：用户名格式限制和密码长度要求。
3. **防暴力破解**：限制登录尝试次数。
4. **文件操作**：异常处理确保文件读写安全。

---

### **潜在改进点**
1. **密码复杂度检查**：可添加对密码特殊字符的要求。
2. **加密算法升级**：使用更安全的算法（如 Argon2）。
3. **文件加密**：敏感文件（如 `PASSWORD.cfg`）可加密存储。
4. **日志记录**：记录用户操作和登录尝试。
-------------------------------------------------------------------------------------------------
1. 本代码无太多注释，请谅解，可以结合以上内容编写
2. "超管"(True，现在是False)可以跳过登陆，转到Admin界面
3. 默认密码Admin , Super_Admin1234
待更新的点：
1. Login out(退出登陆，not退出程序（我已将退出程序写好了）)
2. 用户界面(not adimn界面)
3. 账户管理（admin功能，有删除指定项目等功能）
------------------------------------------------------------------------------------------------------
期待你们的build和优化
可以把你们的成果放在issues或pull requst(但请标明修改点)
-----------------------------------------------------------------------------------------------
version:1.0.0
Change log:
1. pull code && Write README.md
2. Del user file(USER.cfg PASSWORD.cfg and SALT.cfg)
