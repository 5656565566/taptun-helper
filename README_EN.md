[简体中文](README.md)

## Introduction
This project provides some simple interfaces to help with the configuration of virtual network cards and the reading and writing of link-layer data.

The project is open-sourced under the MIT license. Please pay attention to the relevant terms.

**Main Features**:
*   **Easy to use**: Provides a clear interface for quick integration into C/C++ projects.
*   **Lightweight**: The core code is streamlined with few dependencies, making it suitable as a reference.
*   **Cross-platform**: Supports Linux (tun) and Windows (tap-windows6).

## Getting Started

### Installation and Compilation
Note that only compiling for the current platform is supported. It is recommended to use mingw64 for compilation on Windows, and WSL for cross-platform purposes.

1.  **Get the code**:
    ```bash
    git clone https://github.com/5656565566/taptun-helper.git
    cd taptun-helper
    ```

2.  **Compile the dynamic library**:
    ```bash
    make all
    ```
    Then you can find the library file in the `bin` directory.

3.  **Compile the test**:
    ```bash
    make test
    ```
    Then you can run the test with administrator privileges in the `bin` directory.


## Integrated Components

This project includes some files from the following projects. The licenses and source repositories are listed below.

| Component Introduction | Source Repository | Used Files | License |
|-|-|-|-|
| tap-windows6 driver header file | [OpenVPN/tap-windows6](https://github.com/OpenVPN/tap-windows6) | [tap-windows6.h](include/tap-windows6.h) | MIT |