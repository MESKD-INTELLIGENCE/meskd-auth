# Security

## Reporting

Email contact@meskd.com. Please do not open a public issue for security problems.

## What the vault protects against

Someone who copies your vault file, from a backup, a synced folder or a stolen disk, cannot read your accounts without your password. Argon2id with 64 MiB of memory makes guessing slow, but a short or reused password can still be guessed. Use a long one.

## What it does not protect against

- Malware running as your user while the vault is unlocked. It can read the app's memory, the clipboard and your keystrokes.
- A wrong system clock. Codes will not match.
- Plain text exports. They are readable by anyone who opens the file.

## File format

| Bytes | Content |
| --- | --- |
| 8 | `MSKDAUTH` |
| 1 | format version, currently 1 |
| 12 | Argon2id memory (KiB), passes, lanes, little endian u32 |
| 16 | salt |
| 24 | XChaCha20-Poly1305 nonce |
| rest | ciphertext and tag of the JSON vault |

All 61 header bytes are passed as associated data, so changing any of them makes decryption fail. Argon2id settings above 1 GiB, 16 passes or 8 lanes are rejected before any work is done.
