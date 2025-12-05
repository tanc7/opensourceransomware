clang-cl /TP /Od /MT /GS- /W0 ransomware_dll.c /c /Foransomware_dll.obj
clang-cl ransomware_dll.obj advapi32.lib user32.lib shell32.lib shfolder.lib kernel32.lib bcrypt.lib wininet.lib shlwapi.lib iphlpapi.lib winhttp.lib /Feransomware_dll.dll /link /DLL /SUBSYSTEM:WINDOWS /FORCE
