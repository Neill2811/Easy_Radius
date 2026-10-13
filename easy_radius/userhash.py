"""Password hashes for RADIUS users.

PAP uses a SHA-512 crypt hash (Crypt-Password, ``$6$``). MS-CHAP and
MS-CHAPv2, which MikroTik Winbox sends, use an NT hash (NT-Password):
MD4 of the password encoded as UTF-16LE. Neither hash can be turned back
into the password, and a crypt hash cannot be turned into an NT hash.
The plaintext password is not stored.
"""

from __future__ import annotations

import hashlib
import re
import secrets
import struct

_ALPHABET = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
_SALT_CHARS = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
_SHA512_CRYPT = re.compile(
    r"^\$6\$(?:rounds=[1-9][0-9]{3,8}\$)?"
    r"[./0-9A-Za-z]{1,16}\$[./0-9A-Za-z]{86}$"
)


def is_sha512_crypt(value: str) -> bool:
    return bool(_SHA512_CRYPT.fullmatch(value or ""))


def _b64_triplet(b2: int, b1: int, b0: int, count: int) -> str:
    value = (b2 << 16) | (b1 << 8) | b0
    chars = []
    for _ in range(count):
        chars.append(_ALPHABET[value & 0x3F])
        value >>= 6
    return "".join(chars)


def _encode_sha512(digest: bytes) -> str:
    h = digest
    return (
        _b64_triplet(h[0], h[21], h[42], 4)
        + _b64_triplet(h[22], h[43], h[1], 4)
        + _b64_triplet(h[44], h[2], h[23], 4)
        + _b64_triplet(h[3], h[24], h[45], 4)
        + _b64_triplet(h[25], h[46], h[4], 4)
        + _b64_triplet(h[47], h[5], h[26], 4)
        + _b64_triplet(h[6], h[27], h[48], 4)
        + _b64_triplet(h[28], h[49], h[7], 4)
        + _b64_triplet(h[50], h[8], h[29], 4)
        + _b64_triplet(h[9], h[30], h[51], 4)
        + _b64_triplet(h[31], h[52], h[10], 4)
        + _b64_triplet(h[53], h[11], h[32], 4)
        + _b64_triplet(h[12], h[33], h[54], 4)
        + _b64_triplet(h[34], h[55], h[13], 4)
        + _b64_triplet(h[56], h[14], h[35], 4)
        + _b64_triplet(h[15], h[36], h[57], 4)
        + _b64_triplet(h[37], h[58], h[16], 4)
        + _b64_triplet(h[59], h[17], h[38], 4)
        + _b64_triplet(h[18], h[39], h[60], 4)
        + _b64_triplet(h[40], h[61], h[19], 4)
        + _b64_triplet(h[62], h[20], h[41], 4)
        + _b64_triplet(0, 0, h[63], 2)
    )


def hash_user_password(password: str, salt: str | None = None, rounds: int = 5000) -> str:
    """Return a ``$6$`` SHA-512 crypt hash. Salt is random unless one is given."""
    if password == "":
        raise ValueError("Password is empty.")
    if salt is None:
        salt = "".join(secrets.choice(_SALT_CHARS) for _ in range(16))
    if not re.fullmatch(r"[./0-9A-Za-z]{1,16}", salt):
        raise ValueError("Salt must be 1-16 characters from the crypt alphabet.")
    if rounds < 1000 or rounds > 999_999_999:
        raise ValueError("Rounds must be between 1000 and 999999999.")
    password_b = password.encode("utf-8")
    salt_b = salt.encode("ascii")
    mixed = hashlib.sha512(password_b + salt_b + password_b).digest()
    digest = hashlib.sha512()
    digest.update(password_b)
    digest.update(salt_b)
    digest.update(mixed * (len(password_b) // 64))
    digest.update(mixed[: len(password_b) % 64])
    bit = len(password_b)
    while bit:
        if bit & 1:
            digest.update(mixed)
        else:
            digest.update(password_b)
        bit >>= 1
    first = digest.digest()

    temp = hashlib.sha512()
    for _ in range(len(password_b)):
        temp.update(password_b)
    temp_p = temp.digest()
    password_block = temp_p * (len(password_b) // 64) + temp_p[: len(password_b) % 64]

    temp = hashlib.sha512()
    for _ in range(16 + first[0]):
        temp.update(salt_b)
    temp_s = temp.digest()
    salt_block = temp_s * (len(salt_b) // 64) + temp_s[: len(salt_b) % 64]

    current = first
    for index in range(rounds):
        step = hashlib.sha512()
        step.update(password_block if index & 1 else current)
        if index % 3:
            step.update(salt_block)
        if index % 7:
            step.update(password_block)
        step.update(current if index & 1 else password_block)
        current = step.digest()

    encoded = _encode_sha512(current)
    if rounds == 5000:
        return f"$6${salt}${encoded}"
    return f"$6$rounds={rounds}${salt}${encoded}"


_NT_HASH = re.compile(r"^[0-9A-Fa-f]{32}$")


def md4(data: bytes) -> bytes:
    """MD4 digest. hashlib.md4 is unavailable on OpenSSL 3 / Python 3.12."""

    def leftrotate(value: int, bits: int) -> int:
        return ((value << bits) | (value >> (32 - bits))) & 0xFFFFFFFF

    def f(x: int, y: int, z: int) -> int:
        return (x & y) | (~x & z)

    def g(x: int, y: int, z: int) -> int:
        return (x & y) | (x & z) | (y & z)

    def h(x: int, y: int, z: int) -> int:
        return x ^ y ^ z

    message = bytearray(data)
    bit_length = (len(data) * 8) & 0xFFFFFFFFFFFFFFFF
    message.append(0x80)
    while (len(message) % 64) != 56:
        message.append(0)
    message += struct.pack("<Q", bit_length)

    a0 = 0x67452301
    b0 = 0xEFCDAB89
    c0 = 0x98BADCFE
    d0 = 0x10325476
    for offset in range(0, len(message), 64):
        words = list(struct.unpack("<16I", message[offset : offset + 64]))
        a, b, c, d = a0, b0, c0, d0

        def step(func, val_a, val_b, val_c, val_d, word, bits, constant):
            return leftrotate((val_a + func(val_b, val_c, val_d) + word + constant) & 0xFFFFFFFF, bits)

        for index, word in enumerate(words):
            shift = (3, 7, 11, 19)[index % 4]
            if index % 4 == 0:
                a = step(f, a, b, c, d, word, shift, 0)
            elif index % 4 == 1:
                d = step(f, d, a, b, c, word, shift, 0)
            elif index % 4 == 2:
                c = step(f, c, d, a, b, word, shift, 0)
            else:
                b = step(f, b, c, d, a, word, shift, 0)

        round2 = (0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15)
        for index, word_index in enumerate(round2):
            shift = (3, 5, 9, 13)[index % 4]
            word = (words[word_index] + 0x5A827999) & 0xFFFFFFFF
            if index % 4 == 0:
                a = step(g, a, b, c, d, word, shift, 0)
            elif index % 4 == 1:
                d = step(g, d, a, b, c, word, shift, 0)
            elif index % 4 == 2:
                c = step(g, c, d, a, b, word, shift, 0)
            else:
                b = step(g, b, c, d, a, word, shift, 0)

        round3 = (0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15)
        for index, word_index in enumerate(round3):
            shift = (3, 9, 11, 15)[index % 4]
            word = (words[word_index] + 0x6ED9EBA1) & 0xFFFFFFFF
            if index % 4 == 0:
                a = step(h, a, b, c, d, word, shift, 0)
            elif index % 4 == 1:
                d = step(h, d, a, b, c, word, shift, 0)
            elif index % 4 == 2:
                c = step(h, c, d, a, b, word, shift, 0)
            else:
                b = step(h, b, c, d, a, word, shift, 0)

        a0 = (a0 + a) & 0xFFFFFFFF
        b0 = (b0 + b) & 0xFFFFFFFF
        c0 = (c0 + c) & 0xFFFFFFFF
        d0 = (d0 + d) & 0xFFFFFFFF
    return struct.pack("<4I", a0, b0, c0, d0)


def nt_hash(password: str) -> str:
    """NT-Password: MD4 of the password as UTF-16LE, uppercase hex."""
    if password == "":
        raise ValueError("Password is empty.")
    return md4(password.encode("utf-16-le")).hex().upper()


def is_nt_hash(value: str) -> bool:
    return bool(_NT_HASH.fullmatch(value or ""))


def needs_mschap_password(user: dict) -> bool:
    """True when PAP can work but Winbox cannot, because there is no NT hash."""
    return is_sha512_crypt(str(user.get("password") or "")) and not is_nt_hash(str(user.get("nt_password") or ""))


def assign_user_password(user: dict, password: str) -> None:
    """Store the crypt hash and the NT hash. The plaintext is not kept."""
    user["password"] = hash_user_password(password)
    user["nt_password"] = nt_hash(password)


def migrate_users(users: list) -> bool:
    """Replace plaintext user passwords with both hashes, in place.

    A user who already has only a crypt hash is left alone. That hash cannot
    be converted into an NT hash.
    """
    changed = False
    for user in users:
        if not isinstance(user, dict):
            continue
        password = user.get("password")
        if not isinstance(password, str) or password == "" or is_sha512_crypt(password):
            continue
        assign_user_password(user, password)
        changed = True
    return changed
