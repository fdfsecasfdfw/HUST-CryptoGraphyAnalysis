# CryptographyAnalysis
破解如pdf所示分组密码的1-6轮。

# 环境依赖
- 编译器：支持 C++20 的编译器 (GCC 10+, Clang 10+, MSVC 19.28+)。
- CMake：版本 >= 3.20。

# 编译指南
Linux / macOS
```Bash
mkdir build
cd build
cmake -DCMAKE_BUILD_TYPE=Release ..
make -j$(nproc)
```

Windows (Visual Studio)
确保已安装 Visual Studio 构建工具或MinGW。
在项目根目录打开 PowerShell 或 CMD：
```PowerShell
mkdir build
cd build
cmake ..
cmake --build . --config Release
```

# 运行

```bash
./build/bin/app
```
可在main函数中修改轮数
```cpp
constexpr int rounds = ...
```