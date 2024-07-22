@echo off

call "C:\Program Files\Microsoft Visual Studio\2022\Professional\VC\Auxiliary\Build\vcvars64.bat"

set PROJECT_DIR=C:\Users\PC\Desktop\PC\ValorantSource\ExelaExternalSource
set PROJECT_NAME=Exela

set BUILD_CMD=msbuild %PROJECT_DIR%\%PROJECT_NAME%.vcxproj /t:Build /p:Configuration=Release

echo "Derleme başlatılıyor..."
%BUILD_CMD%
echo "Derleme tamamlandı."

pause	