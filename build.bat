@echo off
msbuild -version || call "C:\Program Files\Microsoft Visual Studio\2022\Community\Common7\Tools\VsDevCmd.bat"
msbuild packetdelay.vcxproj ^
    /p:Configuration=Release ^
    /p:Platform=x64 ^
    /p:OutDir=.\out\
