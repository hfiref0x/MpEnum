
# MpEnum
## Enumerate Windows Defender threat families and dump their names according category.

# System Requirements

* x86/x64 Windows 8/8.1/10;
* R/W access to the current directory to be able save results;
* Windows Defender Client.

# Usage
No specific usage required. Just run compiled executable (in command prompt for better experience).

# Dump
Included dump of following versions: 
+ AV Signatures: 1.273.443.0 / 1.273.1601.0 / 1.281.53.0 / 1.293.2098.0
+ AS Signatures: 1.273.443.0 / 1.273.1601.0 / 1.281.53.0 / 1.293.2098.0
+ NIS Signatures: 1.273.443.0 / 1.273.1601.0 / 1.281.53.0 / 1.293.2098.0

# Note

Several categories are declared obsolete by MS and families moved to other categories (e.g Nuker category) or messed up with different categories for example TrojanDownloader:Win32/Delf, TrojanDownloader:Win32/Admedia and Trojan:Win32/NewCell in PUA category despite they have Trojan/TrojanDownloader family in their names.

# Build

MpEnum comes with full source code written in C. Please note that included MpClient.h is build on official available Microsoft documentation with fixes and updates that actually make it work. It maybe different from MS private version. In order to build from source you need Microsoft Visual Studio 2015 and later versions.

## Instructions

* Select Platform ToolSet first for project in solution you want to build (Project->Properties->General): 
  * v120 for Visual Studio 2013;
  * v140 for Visual Studio 2015; 
  * v141 for Visual Studio 2017.
* For v140 and above set Target Platform Version (Project->Properties->General):
  * If v140 then select 8.1 (Note that Windows 8.1 SDK must be installed);
  * If v141 then select 10.0.17134.0 (Note that Windows 10.0.17134 SDK must be installed).

# Authors

(c) 2018 - 2019 MpEnum Project
