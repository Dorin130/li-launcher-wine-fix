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

### Testing

Tested and working with wine-10.20 and ge-proton10-28.

### Example Setup

```bash
$ wine --version
wine-10.20

# Create a clean Wine prefix
$ export WINEPREFIX="/path/to/clean/prefix"

# Add *version to overrides
$ winecfg
wine: created the configuration directory '/path/to/clean/prefix'

# Install the only dependency required by the installer
$ winetricks -q mfc42
Executing cd /usr/bin
Executing load_mfc42 
Executing cabextract -q /home/user/.cache/winetricks/vcrun6/vcredist.exe -d /path/to/clean/prefix/dosdevices/c:/windows/syswow64 -F mfc42*.dll

# First attempt without the fix - installation will stall
$ wine ~/Downloads/nikkeminiloader_oG7STxbESBb.wg.intl.exe

# Copy the fixed DLL to the miniloader directory
$ cp ~/Downloads/version.dll /path/to/clean/prefix/drive_c/users/user/AppData/Local/nikkeminiloader

# Second attempt with the fix - installation completes successfully
$ wine ~/Downloads/nikkeminiloader_oG7STxbESBb.wg.intl.exe
```