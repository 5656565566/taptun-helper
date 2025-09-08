[English](README_EN.md)

## 介绍
本项目提供了一些简单的接口，为虚拟网卡的配置，以及链路层数据读写提供帮助

项目使用 MIT 许可证进行开源，请注意相关条款

**主要特性**：
*   **易于使用**：提供清晰的接口，快速集成到 C/C++ 项目中。
*   **轻量级**：核心代码精简，依赖少，适合参考。
*   **跨平台**：支持 Linux（tun） 以及 Windows（tap-windows6） 。

## 开始使用

### 安装与编译
注意，仅支持编译当前平台，windows 推荐使用 mingw64 编译，跨平台使用 wsl

1.  **获取代码**：
    ```bash
    git clone https://github.com/5656565566/taptun-helper.git
    cd taptun-helper
    ```

2.  **编译动态库**：
    ```bash
    make all
    ```
    然后你可在 bin 目录找到 库 文件

3.  **编译测试**：
    ```bash
    make test
    ```
    然后你可在 bin 目录使用管理员权限进行测试


## 已集成组件

本项目中包含以下项目的部分文件，下面列出展示许可证和源仓库

| 组件介绍 | 源仓库 | 使用文件 | 许可证 |
|-|-|-|-|
tap-windows6 驱动头文件 | [OpenVPN/tap-windows6](https://github.com/OpenVPN/tap-windows6) | [tap-windows6.h](include/tap-windows6.h) | MIT |
