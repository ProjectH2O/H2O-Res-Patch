import os
import struct
import hashlib
import shutil
import sys

try:
    import pefile
except ImportError:
    print("Error: The 'pefile' library is required.")
    print("Please run: pip install pefile")
    sys.exit(1)

# --- CONFIGURATION ---

KNOWN_HASHES = {
    "00C4C81455FF8C44EE50352A04565CFAE125ACFF38911AF1FDADA4D3469257E3".casefold(): "H2Overdrive (2010 build)"
}

IMAGE_BASE = 0x400000  # 32-bit exe

# (instruction VA, immediate offset within instruction, dimension, expected instruction bytes)
#
# Backbuffer: D3DPRESENT_PARAMETERS built on the stack in FUN_004013e0 and copied
# by FUN_00405ec0 into the globals every other system reads (DAT_006accc4 for
# CreateDevice/CreateWindowExA, DAT_007456f4/f8 for viewport, 2D ortho, etc.).
BACKBUFFER_PATCHES = [
    (0x4014ab, 4, 'width',  b'\xC7\x44\x24\x10\x50\x05\x00\x00'),  # mov [esp+0x10], 0x550
    (0x4014b3, 4, 'height', b'\xC7\x44\x24\x14\x00\x03\x00\x00'),  # mov [esp+0x14], 0x300
]

# --- HUD FIX: split "screen size" into real vs. virtual ---
# The UI is a pixel-space system (2D ortho camera FUN_00415560, widget anchoring
# FUN_0049b360/FUN_0049b9e0, text, etc.) that reads the screen size from the
# globals DAT_007456f4/f8. We pin those globals to the original 1360x768 so the
# UI keeps its layout and the 2D camera stretches it over the full backbuffer.
# The few render-sizing readers are redirected to DAT_006accc4/c8, the copy of
# D3DPRESENT_PARAMETERS that keeps the real resolution.
VIRTUAL_W, VIRTUAL_H = 0x550, 0x300

GLOBAL_W, GLOBAL_H = 0x7456f4, 0x7456f8   # virtual (UI) size
REAL_W,   REAL_H   = 0x6accc4, 0x6accc8   # D3DPRESENT_PARAMETERS.BackBufferWidth/Height

# (instruction VA, offset of the abs32 address within the instruction, original address)
# The exe has no relocations, so absolute addresses are fixed.
REAL_SIZE_REDIRECTS = [
    # FUN_00405a50 / FUN_00405d00: set render target + fullscreen post-process blit
    (0x405aae, 2, GLOBAL_W), (0x405ab4, 2, GLOBAL_W), (0x405ac4, 2, GLOBAL_H), (0x405ace, 2, GLOBAL_H),
    (0x405d59, 2, GLOBAL_W), (0x405d5f, 2, GLOBAL_W), (0x405d6f, 2, GLOBAL_H), (0x405d79, 2, GLOBAL_H),
    # NOT redirected: FUN_00408c40 / FUN_00408d80 view-size defaults. The engine
    # never calls SetViewport (D3D uses the full render target), so a view's
    # size only drives its projection -- ortho extents for 2D views are
    # size * 0.5 (FUN_00408f80). Leaving them virtual makes 2D views project
    # 1360x768 across the whole backbuffer, which is what scales the HUD.
    # FUN_0045e210: screen-sized CreateTexture (render targets)
    (0x45e291, 2, GLOBAL_W), (0x45e297, 2, GLOBAL_H),
    # FUN_0045e330: screen-sized CreateDepthStencilSurface
    (0x45e375, 2, GLOBAL_W), (0x45e37b, 2, GLOBAL_H),
]

# FUN_00405ec0 copies BackBufferWidth/Height into the globals. Replace with
# constant stores. The new code is 4 bytes longer than the original, so the
# width store goes to a 15-byte int3 padding cave after FUN_00401140's `ret 4`.
STORE_HOOK_VA = 0x405ef8
STORE_HOOK_ORIGINAL = bytes.fromhex(
    '8b 06'                 # mov eax, [esi]
    '8b 4e 04'              # mov ecx, [esi+4]
    '83 c4 0c'              # add esp, 0xc
    '83 7e 20 00'           # cmp dword [esi+0x20], 0
    'a3 f4 56 74 00'        # mov [0x7456f4], eax
    '89 0d f8 56 74 00'     # mov [0x7456f8], ecx
)                           # followed by `je 0x405f2f` at 0x405f0f (flags from the cmp)
STORE_CAVE_VA = 0x401151
STORE_CAVE_LEN = 15


def log(msg, status="INFO"):
    colors = {"INFO": "\033[94m", "SUCCESS": "\033[92m", "WARN": "\033[93m", "ERROR": "\033[91m"}
    reset = "\033[0m"
    print(f"[{colors.get(status, '')}{status}{reset}] {msg}")

def format_bytes(data):
    """Converts a bytearray/bytes object into a readable hex string (e.g., C7 44 24)."""
    return " ".join(f"{b:02X}" for b in data)

def calculate_sha256(filepath):
    sha256 = hashlib.sha256()
    with open(filepath, 'rb') as f:
        for block in iter(lambda: f.read(4096), b""):
            sha256.update(block)
    return sha256.hexdigest().lower()

def get_file_offset(pe, va):
    return pe.get_offset_from_rva(va - IMAGE_BASE)

def jmp_rel32(from_va, to_va):
    return b'\xE9' + struct.pack('<i', to_va - (from_va + 5))

def build_store_patch():
    """Returns (hook_bytes, cave_bytes) that pin the globals to VIRTUAL_W/H."""
    hook = (b'\x83\xC4\x0C'                                                     # add esp, 0xc
            + b'\xC7\x05' + struct.pack('<II', GLOBAL_H, VIRTUAL_H))            # mov [H], 768
    hook += jmp_rel32(STORE_HOOK_VA + len(hook), STORE_CAVE_VA)                 # jmp cave
    return_va = STORE_HOOK_VA + len(hook)
    hook += b'\x83\x7E\x20\x00'                                                 # cmp [esi+0x20], 0
    hook += b'\x90' * (len(STORE_HOOK_ORIGINAL) - len(hook))                    # pad to the je

    cave = b'\xC7\x05' + struct.pack('<II', GLOBAL_W, VIRTUAL_W)                # mov [W], 1360
    cave += jmp_rel32(STORE_CAVE_VA + len(cave), return_va)                     # jmp back to cmp
    assert len(hook) == len(STORE_HOOK_ORIGINAL) and len(cave) <= STORE_CAVE_LEN
    return hook, cave


def main():
    print("="*55)
    print(" H2Overdrive Resolution Patcher")
    print("="*55)
    exe_name = input("Enter the executable filename (e.g., sdaemon.exe): ").strip()
    if not os.path.exists(exe_name):
        log("File not found!", "ERROR")
        return

    current_hash = calculate_sha256(exe_name)
    if current_hash.casefold() in KNOWN_HASHES:
        log(f"Executable recognized: {KNOWN_HASHES[current_hash]}", "SUCCESS")
    else:
        log(f"SHA256 not in known list:\nCalculated: {current_hash}", "WARN")
        choice = input("This executable may be unsupported or modified. Continue anyway? (y/n): ")
        if choice.lower() != 'y':
            log("Aborting patch.", "INFO")
            return

    print("\nSelect Target Resolution:")
    print("1) 1920 x 1080 (1080p)")
    print("2) 2560 x 1440 (1440p)")
    print("3) 3840 x 2160 (4K)")
    print("4) Custom")

    choice = input("Choice: ").strip()
    if choice == '1':
        target_w, target_h = 1920, 1080
    elif choice == '2':
        target_w, target_h = 2560, 1440
    elif choice == '3':
        target_w, target_h = 3840, 2160
    elif choice == '4':
        target_w = int(input("Enter Width: "))
        target_h = int(input("Enter Height: "))
    else:
        log("Invalid choice.", "ERROR")
        return

    # ---------------------------------------------------------
    # PHASE 1: VALIDATION (DRY RUN)
    # ---------------------------------------------------------
    print("-" * 55)
    log("Evaluating patch viability...")

    try:
        pe = pefile.PE(exe_name)
        file_data = bytearray(open(exe_name, 'rb').read())
    except Exception as e:
        log(f"Failed to parse executable structure: {e}", "ERROR")
        return

    resolved = []
    for va, imm_off, dimension, original in BACKBUFFER_PATCHES:
        offset = get_file_offset(pe, va)
        if file_data[offset:offset+len(original)] != original:
            log(f"Original bytes mismatch at VA {hex(va)}.", "ERROR")
            log("Please patch your clean backup instead. This file might already be patched.", "ERROR")
            return
        resolved.append((offset + imm_off, dimension, va))

    redirects = []
    for va, addr_off, global_addr in REAL_SIZE_REDIRECTS:
        offset = get_file_offset(pe, va) + addr_off
        if file_data[offset:offset+4] != struct.pack('<I', global_addr):
            log(f"Screen-size reference mismatch at VA {hex(va)}.", "ERROR")
            return
        real_addr = REAL_W if global_addr == GLOBAL_W else REAL_H
        redirects.append((offset, va, real_addr))

    hook_offset = get_file_offset(pe, STORE_HOOK_VA)
    if file_data[hook_offset:hook_offset+len(STORE_HOOK_ORIGINAL)] != STORE_HOOK_ORIGINAL:
        log(f"Screen-size store original bytes mismatch at VA {hex(STORE_HOOK_VA)}.", "ERROR")
        return

    cave_offset = get_file_offset(pe, STORE_CAVE_VA)
    if any(b != 0xCC for b in file_data[cave_offset:cave_offset+STORE_CAVE_LEN]):
        log(f"Code cave at VA {hex(STORE_CAVE_VA)} is not empty padding!", "ERROR")
        return

    log("Validation successful. Executable is ready to patch.", "SUCCESS")
    print("-" * 55)

    # ---------------------------------------------------------
    # PHASE 2: EXECUTION
    # ---------------------------------------------------------
    backup_name = exe_name + ".bak"
    if not os.path.exists(backup_name):
        shutil.copy2(exe_name, backup_name)
        log(f"Created backup: {backup_name}", "SUCCESS")
    else:
        log(f"Backup already exists: {backup_name}", "INFO")

    for offset, dimension, va in resolved:
        val = target_w if dimension == 'width' else target_h
        val_bytes = struct.pack('<I', val)

        old_bytes = file_data[offset:offset+4]
        file_data[offset:offset+4] = val_bytes

        log(f"Patched {dimension} to {val} at VA {hex(va)}", "SUCCESS")
        print(f"    Old: {format_bytes(old_bytes)}  ->  New: {format_bytes(val_bytes)}\n")

    # 2. Render-sizing code reads the real backbuffer size
    for offset, va, real_addr in redirects:
        file_data[offset:offset+4] = struct.pack('<I', real_addr)
    log(f"Redirected {len(redirects)} render-target/viewport size reads to the real backbuffer size", "SUCCESS")
    print()

    # 3. Pin the UI screen-size globals to the original 1360x768
    hook_bytes, cave_bytes = build_store_patch()
    old_hook = file_data[hook_offset:hook_offset+len(hook_bytes)]
    file_data[hook_offset:hook_offset+len(hook_bytes)] = hook_bytes
    file_data[cave_offset:cave_offset+len(cave_bytes)] = cave_bytes
    log(f"Pinned UI screen size to {VIRTUAL_W}x{VIRTUAL_H} at VA {hex(STORE_HOOK_VA)}", "SUCCESS")
    print(f"    Old: {format_bytes(old_hook)}")
    print(f"    New: {format_bytes(hook_bytes)}")
    log(f"Injected code cave at VA {hex(STORE_CAVE_VA)}", "SUCCESS")
    print(f"    New: {format_bytes(cave_bytes)}\n")

    output_name = exe_name.replace(".exe", f"_{target_w}x{target_h}.exe")
    with open(output_name, 'wb') as f:
        f.write(file_data)

    print("-" * 55)
    log(f"Patch applied successfully! Saved as {output_name}", "SUCCESS")

if __name__ == "__main__":
    main()
    input("Press Enter to continue...")
