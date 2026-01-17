# Level Infinite Launcher Wine Fix

Fixes a race condition in the Level Infinite launcher/installer preventing games from updating and installing under Wine.

## The Bug

VersionServiceProxy.dll writes to named pipes before calling ConnectNamedPipe, causing initialization data loss and stalling. This occurs under Wine but not native Windows.

## Build

Requirements: `i686-w64-mingw32-gcc`

```
make
```

## Usage

0. Launch installer/launcher to let it populate appdata directories

1. Set DLL override in winecfg: `*version=n,b`

2. Copy version.dll to the game's miniloader directory:
   - NIKKE: `%APPDATA%\Local\nikkeminiloader\`
   - Delta Force: `%APPDATA%\Local\DeltaForceMiniloader\`

3. Launch the installer/launcher
