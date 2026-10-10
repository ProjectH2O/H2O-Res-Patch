# H2Overdrive Resolution Patch

This is a standalone version of the resolution patch used in Project H2O.

It is recommended to use Project H2O to play the game. You do not need this resolution patcher if you are using Project H2O.

However, it is provided here for reference purposes, or in case you want to play patched H2Overdrive on the standard version of TeknoParrot.

## Usage

Download the latest zip from [Releases](../../releases/latest) and follow the instructions in `README.txt`.

## Script

Already have Python? Download `patch.py`, place it in your game directory, and run the script:

```
pip install pefile
python patch.py
```

## Building

Requires Python 3 on Windows:

```
pip install pyinstaller pefile
pyinstaller --onefile --name patch patch.py
```

The exe is written to `dist/patch.exe`.
