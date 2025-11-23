@echo off
REM Windows build script for device bot

echo Building device bot for Windows...

cd device

REM Build for Windows x64
echo Building for x86_64-pc-windows-msvc...
cargo build --release --target x86_64-pc-windows-msvc
if %ERRORLEVEL% EQU 0 (
    copy target\x86_64-pc-windows-msvc\release\device.exe ..\builds\device_x86_64-pc-windows-msvc.exe
    echo Successfully built for Windows x64
) else (
    echo Failed to build for Windows x64
)

REM Build for Windows x86
echo Building for i686-pc-windows-msvc...
cargo build --release --target i686-pc-windows-msvc
if %ERRORLEVEL% EQU 0 (
    copy target\i686-pc-windows-msvc\release\device.exe ..\builds\device_i686-pc-windows-msvc.exe
    echo Successfully built for Windows x86
) else (
    echo Failed to build for Windows x86
)

cd ..

echo.
echo Build complete! Binaries are in the builds directory.
dir builds
