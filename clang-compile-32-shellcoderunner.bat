clang-cl -m32 /TP shellcoderunner.c ^
  advapi32.lib user32.lib shell32.lib shfolder.lib kernel32.lib bcrypt.lib wininet.lib shlwapi.lib iphlpapi.lib winhttp.lib ^
  /Od /MT /GS- /W0 ^
  /Feransomwareshellcoderunner.exe ^
  /link /SUBSYSTEM:CONSOLE
