# Open Source Ransomware Example for my online course
Custom Ransomware: Static Code Analysis
https://youtu.be/jzjFi7s2Idc

Custom Ransomware: Debugger Setup
https://youtu.be/o9_Du447Tjc

Custom Ransomware: Dynamic Analysis
https://youtu.be/ELkjmUokO5Y

# To compile <br>
Open powershell as Administrator and run the following commands to install the build tools <br>
winget install LLVM.LLVM <br>
winget install Microsoft.VisualStudio.2022.BuildTools <br>

**Then run the batch script in cmd.exe to compile: clang-compile-32.bat** <br>
clang-cl -m32 /TP /Od /MT /GS- /W0 ransomware_dll.c /c /Foransomware_dll.obj <br>
clang-cl -m32 ransomware_dll.obj advapi32.lib user32.lib shell32.lib shfolder.lib kernel32.lib bcrypt.lib wininet.lib shlwapi.lib iphlpapi.lib winhttp.lib /Feransomware_dll.dll /link /DLL /SUBSYSTEM:WINDOWS <br>


# Disclaimer: <br>

The content presented here is intended solely for cybersecurity education, defensive research, red‑team simulation, and historical case‑study analysis. Nothing in this material is designed, intended, or authorized to support illegal, destructive, or disruptive activity of any kind. All demonstrations, proof‑of‑concepts, or simulations must be executed only inside a fully controlled, isolated lab environment owned by the practitioner.

To the best of publicly available knowledge and my personal recollection, the United States government has never officially endorsed, authorized, or operationalized tactics such as hoax bomb threats, coercive misinformation operations, destructive wiper deployments, or similar destabilizing actions described in comparative case studies herein. Any reference to such tactics is made strictly for the purposes of threat intelligence analysis and does not imply U.S. participation or approval.

Several foreign state‑aligned threat actors, however, have been publicly attributed—by international security firms, CERT organizations, and government advisories—to major offensive cyber operations. Examples include:

Pakistan (ISI):
Well known for at least a decade of creating hoax bomb threats against their adversaries to cause confusion and cloak actual kinetic attacks.

North Korea (DPRK):
Implicated in financially and operationally disruptive attacks such as WannaCry (2017), which spread globally and caused extensive economic damage.

Iran:
Attributed to multiple destructive campaigns involving wipers and ICS‑targeting malware against regional adversaries, including incidents affecting Saudi Arabia’s industrial and energy sectors.

Russia (SVR / APT29):
Publicly linked to the SolarWinds supply‑chain compromise, among other sophisticated long‑term cyber‑espionage operations.

My earlier book, Ultimate Cyberwarfare for Evasive Cyber Tactics, drew heavily on case studies modeled after SVR‑style tradecraft, a fact I have repeatedly discussed in interviews and podcasts.
These analyses remain strictly observational and are intended to help defenders understand advanced adversary behavior.

All geopolitical references are derived from publicly available threat‑intelligence reporting and are used purely for educational and analytical purposes. They do not advocate replication of any offensive action and should be interpreted solely as context for understanding modern cybersecurity threats.
