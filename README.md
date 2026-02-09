This project is archived and no longer recommended.

Use **wine-miniloader** instead:
https://dawn.wine/NelloKudo/wine-miniloader

`wine-miniloader` is a patched Wine build that includes fixes for miniloader and additional launcher issues beyond what is provided here.

---

# Level Infinite Miniloader Wine Fix

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A proxy DLL that fixes a race condition in Level Infinite's `VersionServiceProxy.dll` (usually found in AppData miniloader directories and launcher directories) when running under Wine. The bug causes data to be written to named pipes before `ConnectNamedPipe()` is called, resulting in lost initialization data and a deadlock that prevents installations and updates from completing. This issue does not occur on native Windows.

## Supported Games

- **NIKKE: Goddess of Victory**
- **Delta Force**
- Other Level Infinite games using the miniloader system

## Building

### Requirements

- `i686-w64-mingw32-gcc`

### Build Instructions

```bash
make
```

## Installation

### Step 1: Prepare the Environment

Install the required `mfc42` dependency:

```bash
winetricks -q mfc42
# Or for Proton/Steam:
protontricks APPID -q mfc42
```

Launch the installer/launcher once to let it create the necessary AppData directories, then close it.

### Step 2: Configure Wine DLL Override

Set the DLL override in `winecfg`:

1. Run `winecfg`
2. Go to the **Libraries** tab
3. Add a new override for `version` (type the name and click "Add")
4. Set it to `native, builtin` (n,b)

### Step 3: Copy the DLL

Copy `version.dll` to the appropriate miniloader directory:

**NIKKE:**
```bash
cp version.dll "$WINEPREFIX/drive_c/users/$USER/AppData/Local/nikkeminiloader/"
```

**Delta Force:**
```bash
cp version.dll "$WINEPREFIX/drive_c/users/$USER/AppData/Local/DeltaForceMiniloader/"
```

**Launcher updates:**

For launcher updates, also copy to the launcher folder:
```bash
cp version.dll "$WINEPREFIX/drive_c/NIKKE/Launcher/"
```

### Step 4: Launch the Installer

Run the installer/launcher normally. Installation and updates should now complete successfully.

## Compatibility

**Tested and working with:**
- Wine 10.20
- GE-Proton 10-28

Expected to work with most modern Wine versions (8.0+).

## Example Setup

Complete walkthrough for setting up NIKKE on a clean Wine prefix:

```bash
$ wine --version
wine-10.20

# Create a clean Wine prefix
$ export WINEPREFIX="/path/to/clean/prefix"

# Configure Wine and add version override
$ winecfg

# Install required dependency
$ winetricks -q mfc42

# First attempt without the fix - this will stall at 0%
$ wine ~/Downloads/nikkeminiloader_oG7STxbESBb.wg.intl.exe

# Install the fix
$ cp version.dll "$WINEPREFIX/drive_c/users/$USER/AppData/Local/nikkeminiloader/"

# Second attempt with the fix - installation completes successfully
$ wine ~/Downloads/nikkeminiloader_oG7STxbESBb.wg.intl.exe
```
