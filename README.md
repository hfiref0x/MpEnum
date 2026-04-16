# MpEnum
## Enumerate Windows Defender threat families and dump their names into consolidated table.

# System Requirements

* x86/x64 Windows 10/11;
* R/W access to the current directory to be able save results;
* Windows Defender Client.

# Usage
No specific usage required. Just run compiled executable (in command prompt for better experience).

# Dump
Example of dumped table for definitions version 1.449.126.0 located in ```data\1.449.126.0.zip```

# Note

MpEnum enumerates known-bad signature threats through MpClient, groups them by category and saves results into version-specific output directory named after AV signature version. This tool is now part of WDExtract, WDSigEx toolchain. WDSigEx uses generated file to map actual threat names.

# Build

MpEnum comes with full source code written in C. Please note that included MpClient.h is build on official available Microsoft documentation with fixes and updates that actually make it work. It maybe incomplete/inaccurate however and you should expect breakage with future definition/platform changes.

## Instructions

* Select Platform ToolSet first for project in solution you want to build (Project->Properties->General):
  * v143 for Visual Studio 2022;
  * v145 for Visual Studio 2026.
* Set Target Platform Version (Project->Properties->General):
  * Select appropriate Windows 10/11 SDK installed with Visual Studio.

# Related references and tools

* WDExtract, https://github.com/hfiref0x/WDExtract

# Authors

(c) 2018 - 2026 MpEnum Project
