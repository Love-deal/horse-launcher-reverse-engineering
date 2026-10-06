# Horse Empire Launcher: Static Reverse Engineering of `setup 2.exe` and `cfg 2.hors`

**Date:** 2026-10-06  
**Tags:** `reverse-engineering` `windows` `nsis` `star-stable` `launcher` `aes-gcm` `ecdsa` `malware-analysis`

> This is a static reverse-engineering write-up of the two files I was given: `setup 2.exe` and `cfg 2.hors`. The executable was **not run** during this analysis. The goal was to determine what the installer contains, what the launcher is capable of doing, how the `.hors` profile is structured, and whether the files show obvious signs of commodity malware.
>
> This document records the evidence and the reasoning summary behind the conclusions. It does **not** reproduce private chain-of-thought or hidden scratch work.

## TL;DR

The installer is a **32-bit NSIS package** that contains a much larger **64-bit Horse Launcher executable** and two small NSIS helper DLLs. The extracted launcher is unsigned and has networking, registry, cryptography, update, and process-launching capabilities. It supports Star Stable client generations labeled **2014, 2016, 2018, and 2020**.

The companion `cfg 2.hors` file is not random garbage or a simple config file. It is a custom authenticated container:

- magic: `HORS`
- container version: `1`
- AES-256-GCM encrypted payload
- 16-byte GCM authentication tag
- 64-byte raw ECDSA-P256 signature

The config signature verifies successfully using a public key embedded in the launcher, and the payload decrypts successfully using the launcher's embedded AES key. The decrypted config identifies the profile as **Horse Empire**, points the launcher API at `78.17.213.164:443`, and lists four game servers at `162.35.243.182` on ports `20000`, `18000`, `16000`, and `13000`.

I did **not** find the usual static indicators of a commodity credential stealer, ransomware loader, or classic remote-process injector. In particular, there were no static imports for `WriteProcessMemory` or `CreateRemoteThread`, and I found no obvious `Run`/`RunOnce`, scheduled-task, or service persistence strings. That is not the same as proving the program is safe. The launcher downloads executable content, modifies game files, references `winmm.dll` and `patch.dll`, writes registry data, and launches processes. Those behaviors are enough to trigger antivirus heuristics and are also exactly the areas that would need dynamic analysis in a sandbox.

---

## Samples

| File | Size | SHA-256 | Notes |
|---|---:|---|---|
| `setup 2.exe` | 4,570,328 bytes | `33f12a3d861b8e6857e854c35ffb2e219dce95a6e5fc2230d260b58a74fdfbb9` | PE32 NSIS installer, GUI, `asInvoker`, unsigned |
| `cfg 2.hors` | 4,205,167 bytes | `3e9ea7959c73f059742c9bdb552d9310bc629e548f8ac4883db112b3832ce542` | Signed + encrypted HORS profile |
| Extracted `HorseLauncher.exe` | 9,389,056 bytes | `31fb42b07239018d0a1122c797c1b43b8d71b259dbf10e9263a2a7814e0cea16` | PE32+ x86-64 GUI, unsigned |

Two additional 32-bit PE DLLs were recovered from the NSIS data. They are small installer helper components rather than the main application payload:

| Component | Size | SHA-256 |
|---|---:|---|
| NSIS helper DLL #1 | 9,728 bytes | `715a9b58de0995d1a08384c522ad9af210e2791aaf8e87a6c07bfe72ebfd2cb5` |
| NSIS helper DLL #2 | 12,288 bytes | `996645d7f16a6294babb6da83478062aed7b72318d7a51b66e90ab5d3edc51a5` |

I am intentionally not redistributing the executable samples in this repository. The hashes are enough to identify the exact files that were analyzed.

---

## Why the Delivery Looks Suspicious

A Windows installer plus a second opaque binary file is a pattern worth treating cautiously. A normal desktop application often keeps its configuration in JSON, INI, XML, SQLite, or registry values. Here, the companion file is several megabytes, begins with a custom `HORS` header, and the rest has very high entropy.

That gives several reasonable starting hypotheses:

1. the `.hors` file could be compressed data;
2. it could be encrypted configuration;
3. it could be a packaged game archive;
4. it could contain executable payloads;
5. the launcher could be using the file as a signed profile that controls where it connects.

The static analysis supports hypothesis 5. The file is an authenticated encrypted profile containing connection details and artwork, not executable code.

**Evidence -> interpretation:** high entropy alone does not mean malware. Once the header, AES-GCM layout, valid ECDSA signature, and fully parsed plaintext are accounted for, the entropy has a straightforward cryptographic explanation.

---

## 1. Identifying the Installer

`setup 2.exe` is a 32-bit Windows PE executable built as an **NSIS / Nullsoft Scriptable Install System** installer. The installer manifest uses `asInvoker`, so this outer installer does not request administrator privileges by default.

The payload uses raw DEFLATE compression. Recovering the NSIS data produced:

- one large 64-bit `HorseLauncher.exe`;
- two small 32-bit helper DLLs used by the installer framework.

The installer strings indicate a normal per-user application install flow: it creates an uninstaller entry, handles shortcuts / Start Menu integration, and offers an **Open Horse Launcher** action when setup completes.

The uninstall registry location referenced by the installer is:

```text
Software\Microsoft\Windows\CurrentVersion\Uninstall\HorseLauncher
```

### What was *not* present in this installer build

The published analysis that inspired the structure of this write-up examined a different Horse Museum / Horse Empire launcher build. That earlier sample bundled `tor.exe` and a nested runtime installer. This uploaded build is materially different: in the recovered NSIS payload I found the launcher and two helper DLLs, but **no bundled `tor.exe` and no nested runtime installer**.

That difference matters because it means conclusions from the older sample should not be copied onto this one without verification.

---

## 2. The Extracted Launcher PE

The recovered launcher is:

```text
HorseLauncher.exe
PE32+ executable
x86-64
GUI subsystem
7 sections
9,389,056 bytes
SHA-256: 31fb42b07239018d0a1122c797c1b43b8d71b259dbf10e9263a2a7814e0cea16
```

It has no embedded Authenticode signature.

### Section layout

```text
.text     0x4d308c
.rdata    0x3ac4c0
.data     0x028400
.pdata    0x0329ac
.fptable  0x000100
.rsrc     0x010a80
.reloc    0x008bdc
```

The very large `.text` and `.rdata` sections are consistent with a statically heavy C/C++ program containing third-party libraries. Strings confirm that the executable includes a substantial portion of the **MEGA SDK**, including source-path remnants such as:

```text
C:\code\HorseLauncher\SSO2020\third_party\mega-sdk\...
```

and MEGA service strings such as:

```text
https://g.api.mega.co.nz/
https://mega.nz
```

The launcher also contains download-provider handling associated with **SwissTransfer**.

---

## 3. Imported Capabilities

Imports are useful for determining what a Windows program *can* do, but an import is not proof that every capability is used maliciously.

### Process / memory related

Observed:

```text
CreateProcessW
VirtualProtect
IsDebuggerPresent
```

Not observed as static imports:

```text
WriteProcessMemory
CreateRemoteThread
```

The absence of those two functions weakens the hypothesis that the launcher is a classic remote-process injector. It does not rule out all code patching techniques, because patching can happen inside the current process or inside a DLL loaded by the game.

### Registry

Observed:

```text
RegOpenKeyExW
RegSetValueExW
RegCreateKeyExW
```

The launcher has explicit profile storage strings under:

```text
Software\HorseLauncher\Profiles\
```

and references:

```text
active.hors
```

### Networking

The executable imports WinHTTP and Winsock APIs, including:

```text
WinHttpOpen
WinHttpConnect
WinHttpOpenRequest
WinHttpSendRequest
WinHttpReceiveResponse
WinHttpReadData
```

This matches the launcher API strings recovered later.

### Cryptography

The launcher imports a broad BCrypt surface:

```text
BCryptImportKeyPair
BCryptHash
BCryptVerifySignature
BCryptGenerateSymmetricKey
BCryptSetProperty
BCryptHashData
BCryptFinishHash
BCryptGenRandom
BCryptDecrypt
```

It also imports:

```text
CryptProtectData
CryptUnprotectData
```

The BCrypt functions line up directly with the `.hors` signature verification and AES-GCM decryption logic. `CryptProtectData` / `CryptUnprotectData` indicate use of Windows DPAPI somewhere in the launcher, most likely for local protected state or secrets, but the imports alone are not enough to say exactly which value is protected.

---

## 4. First-Pass Malware Checks

Because the delivery method and unsigned executable are suspicious, the first pass looked for common commodity-stealer and persistence indicators.

### Things I did not find in the static pass

- no obvious browser-profile targeting strings;
- no obvious cryptocurrency wallet targeting strings;
- no obvious `Run` or `RunOnce` persistence path;
- no obvious scheduled-task creation strings;
- no obvious service-install persistence strings;
- no static `WriteProcessMemory` import;
- no static `CreateRemoteThread` import.

This is meaningful, but it is **not a clean bill of health**. A program can resolve APIs dynamically, use different techniques, or download additional code after launch.

### Things that still deserve caution

The launcher can:

- download files;
- verify and install/update files;
- write to the registry;
- launch other processes;
- change memory protection with `VirtualProtect`;
- work with game-side files called `winmm.dll` and `patch.dll`;
- use rollback and staging directories;
- communicate with remote APIs.

Those are legitimate capabilities for a custom game launcher, but they also overlap with behaviors that antivirus engines score as suspicious.

---

## 5. Game Versions and Local File Handling

Strings in the launcher show support for four client generations:

```text
2014
2016
2018
2020
```

Game executable names include:

```text
PXStudioRuntimeMMO.exe
SSOClient.exe
```

The launcher uses several staging / transactional directory names:

```text
.downloads
.launcher-install
.installing
.rollback
```

This suggests an install/update sequence that downloads content separately, prepares a new version, and keeps rollback state rather than simply overwriting the live game directory in one step.

There are also strings for a custom package format called:

```text
HORSBOX1
```

and for integrity failures such as corrupted or incomplete downloaded files.

**Evidence -> interpretation:** these strings are consistent with a launcher that downloads versioned game packages, verifies them, stages installation, and can revert if something fails. They are not, on their own, evidence of malicious persistence.

---

## 6. `winmm.dll` and `patch.dll`

Two filenames are especially important:

```text
winmm.dll
patch.dll
```

They are explicitly referenced by the launcher during game-file handling.

`winmm.dll` is a Windows multimedia library name that is commonly used for **DLL proxying / DLL search-order loading** in game mods and private-server clients: placing a custom `winmm.dll` next to a game executable can cause the game to load the local copy before the system copy.

`patch.dll` strongly suggests a second component used to modify or adapt the game client.

For this specific uploaded launcher, the static pass establishes the filenames and the launcher's handling of them, but I did **not** recover enough evidence in this sample to claim the exact in-memory patch routine. That distinction is important: the related published sample had enough embedded DLL detail to prove the proxy/patch mechanism; this build should be described more conservatively unless those downloaded DLLs are captured and analyzed directly.

---

## 7. Launcher API Surface

The binary contains a complete set of launcher API paths:

| Endpoint | Likely purpose |
|---|---|
| `/api/launcher/login` | authenticate a launcher account |
| `/api/launcher/logout` | terminate a launcher session |
| `/api/launcher/session` | validate/restore a session |
| `/api/launcher/download` | request game/download metadata |
| `/api/launcher/integrity` | verify installed game state |
| `/api/launcher/launch-ticket` | request a game launch ticket |
| `/api/launcher/code-history` | retrieve redeemed-code history |
| `/api/launcher/invites` | retrieve invite information |
| `/api/launcher/change-password` | change account password |
| `/api/launcher/redeem` | redeem a code |

Other related paths found in the binary include:

```text
/api/web/download
/api/web/session
/api/web/logout
/api/download/
```

UI strings also expose features such as:

```text
Invites
Redeem
REDEEM A CODE
No codes redeemed yet.
YOUR INVITES
```

This looks like a full account/private-server launcher rather than a minimal patch executable.

---

## 8. Reconstructing the `.hors` Container

`cfg 2.hors` begins with the ASCII magic:

```text
HORS
```

The outer container layout is:

```text
Offset        Size       Meaning
-----------   --------   ----------------------------------------
0x00          4          ASCII magic "HORS"
0x04          4          container version, little-endian (1)
0x08          4          ciphertext length N
0x0C          12         AES-GCM nonce
0x18          N          AES-256-GCM ciphertext
0x18 + N      16         AES-GCM authentication tag
final bytes   64         raw ECDSA-P256 signature (r || s)
```

The overhead outside the ciphertext is therefore exactly **104 bytes**:

```text
24-byte header
+ 16-byte GCM tag
+ 64-byte ECDSA signature
= 104 bytes
```

That matches the file size relationship observed during analysis.

### Signature verification

The launcher hashes the entire container except the final 64-byte signature with SHA-256 and verifies the result using an embedded ECDSA P-256 public key.

Conceptually:

```text
digest = SHA256(file[0 : file_size - 64])
verify_ECDSA_P256(public_key, digest, signature_r_s)
```

The signature on the uploaded `cfg 2.hors` **verifies successfully**.

That means the file is internally consistent with the signing key expected by this launcher. It does not tell us who controls the private signing key or whether we should trust that operator.

### AES-GCM decryption

The ciphertext is decrypted with AES-256-GCM using a 32-byte key embedded in the launcher.

The authenticated associated data is the first 24 bytes of the `.hors` file:

```text
AAD = magic + version + ciphertext_length + nonce
```

The GCM authentication check succeeds and produces a plaintext payload of **4,205,063 bytes**.

I am deliberately omitting the embedded symmetric key from this public write-up. It is unnecessary for understanding the format and reduces the chance of turning an analysis note into a copy-paste tampering recipe.

---

## 9. Decrypted Profile Format

The decrypted payload starts with a second, inner format version:

```text
u32 format_version = 2
```

Strings are stored as a 16-bit little-endian length followed by UTF-8 bytes.

The structure reconstructed from the plaintext is approximately:

```text
u32    format_version
lp16   profile_slug
lp16   display_name
lp16   launcher_api_host
u16    launcher_api_port
lp16   launcher_api_prefix
lp16   artwork_credit
u8     game_count

repeat game_count times:
    u16   year_number
    lp16  year_string
    lp16  game_host
    u16   game_port

u8     image_count

repeat image_count times:
    u8    image_type
    u32   image_size
    bytes image_data
```

`lp16` means a `uint16` byte length followed by exactly that many bytes.

### Parsed values

```text
format version:       2
profile slug:         horse-empire-2016-test
display name:         Horse Empire
launcher API host:    78.17.213.164
launcher API port:    443
launcher API prefix:  /api/launcher/
artwork credit:       Thanks for the Discord art Bunni!
```

### Game entries

| Client | Host | Port |
|---|---|---:|
| 2020 | `162.35.243.182` | 20000 |
| 2018 | `162.35.243.182` | 18000 |
| 2016 | `162.35.243.182` | 16000 |
| 2014 | `162.35.243.182` | 13000 |

The inclusion of **2016** is one of the clearest differences between this profile and the older public sample.

---

## 10. Embedded Artwork

The decrypted profile contains four images and then ends exactly after the last image. There is no executable tail hidden after them.

| Type | Format | Size | Dimensions |
|---:|---|---:|---|
| 0 | JPEG | 242,967 bytes | 1159x688 |
| 1 | JPEG | 3,612,213 bytes | 4769x2548 |
| 2 | PNG | 55,003 bytes | 310x214 |
| 3 | PNG | 294,644 bytes | 1140x834 |

### Image 0

![Config artwork 0](assets/cfg_art_0.jpg)

### Image 1

![Config artwork 1](assets/cfg_art_1.jpg)

### Image 2

![Config artwork 2](assets/cfg_art_2.png)

### Image 3

![Config artwork 3](assets/cfg_art_3.png)

This is another useful check on the parser: all four extracted blobs have valid image signatures and dimensions, and the last blob ends at the exact end of the decrypted payload.

---

## 11. What the Config Tells Us About Networking

Unlike the Tor-based public sample, this config directly contains an IPv4 API endpoint:

```text
78.17.213.164:443
```

with the prefix:

```text
/api/launcher/
```

The game hosts are also plain IPv4 addresses:

```text
162.35.243.182:20000  # 2020
162.35.243.182:18000  # 2018
162.35.243.182:16000  # 2016
162.35.243.182:13000  # 2014
```

Because the launcher has explicit `login`, `session`, `integrity`, `download`, and `launch-ticket` routes, a likely high-level flow is:

```text
load + verify profile
        |
        v
connect to launcher API
        |
        +--> login / session
        |
        +--> request download metadata if needed
        |
        +--> verify local integrity
        |
        +--> request launch ticket
        |
        v
start selected game client
```

That sequence is a **behavioral reconstruction from static evidence**, not a packet capture. A dynamic run would be required to confirm the exact request bodies, response fields, TLS behavior, and whether the server address can be replaced after login.

---

## 12. Compared with the Published Horse Museum Sample

This analysis was formatted after the Patchi write-up:

`https://patchi.fyi/blog/horse-empire-star-stable-launcher`

The structure is useful, but the binaries are not the same.

| Detail | Published sample | Uploaded sample analyzed here |
|---|---|---|
| Installer size | ~18.1 MB | 4,570,328 bytes |
| Installer SHA-256 | `4e5129b0...` | `33f12a3d...` |
| Launcher size | ~1.9 MB | 9,389,056 bytes |
| Launcher SHA-256 | `93f83d0e...` | `31fb42b0...` |
| Bundled Tor | yes | not observed in extracted installer payload |
| Nested runtime installer | yes | not observed |
| Account/API host in profile | v3 `.onion` | direct IPv4 `78.17.213.164` |
| Game versions | 2014 / 2018 / 2020 | 2014 / 2016 / 2018 / 2020 |
| Game host in this profile | older profile had a different host | `162.35.243.182` |

The takeaway is that this project has changed significantly between builds. The name and broad architecture are related, but a malware verdict or safety claim should be made **per hash**, not per project name.

---

## 13. Indicators and Artifacts

### File hashes

```text
setup 2.exe
33f12a3d861b8e6857e854c35ffb2e219dce95a6e5fc2230d260b58a74fdfbb9

cfg 2.hors
3e9ea7959c73f059742c9bdb552d9310bc629e548f8ac4883db112b3832ce542

HorseLauncher.exe
31fb42b07239018d0a1122c797c1b43b8d71b259dbf10e9263a2a7814e0cea16
```

### Network indicators from the decrypted profile

```text
78.17.213.164:443
162.35.243.182:20000
162.35.243.182:18000
162.35.243.182:16000
162.35.243.182:13000
```

### Registry / profile paths

```text
Software\HorseLauncher\Profiles\
Software\Microsoft\Windows\CurrentVersion\Uninstall\HorseLauncher
active.hors
```

### Important filenames / directories

```text
PXStudioRuntimeMMO.exe
SSOClient.exe
winmm.dll
patch.dll
.downloads
.launcher-install
.installing
.rollback
```

### API paths

```text
/api/launcher/login
/api/launcher/logout
/api/launcher/session
/api/launcher/download
/api/launcher/integrity
/api/launcher/launch-ticket
/api/launcher/code-history
/api/launcher/invites
/api/launcher/change-password
/api/launcher/redeem
```

---

## 14. Reproducibility Notes

The core static checks can be reproduced with ordinary command-line tooling.

### Hashes and file identity

```bash
sha256sum "setup 2.exe" "cfg 2.hors"
file "setup 2.exe"
file HorseLauncher.exe
```

### PE sections and imports

```bash
objdump -h HorseLauncher.exe
objdump -p HorseLauncher.exe
```

### String triage

```bash
strings -a -n 5 HorseLauncher.exe > launcher-ascii.txt
strings -a -el -n 4 HorseLauncher.exe > launcher-utf16.txt

grep -Ei "api/launcher|winmm.dll|patch.dll|active.hors|rollback|integrity" launcher-ascii.txt launcher-utf16.txt
```

### HORS container parsing logic

A parser does not need to guess boundaries. They are explicit:

```python
magic = data[0:4]
version = u32le(data[4:8])
ct_len = u32le(data[8:12])
nonce = data[12:24]

ciphertext = data[24:24 + ct_len]
tag = data[24 + ct_len:24 + ct_len + 16]
signature = data[-64:]

signed_region = data[:-64]
aad = data[:24]
```

From there, the launcher behavior shows the required operations are:

1. SHA-256 the signed region;
2. verify the raw 64-byte ECDSA-P256 signature;
3. AES-256-GCM decrypt the ciphertext using the 12-byte nonce, 16-byte tag, and 24-byte AAD;
4. parse the plaintext as the length-prefixed profile structure described above.

The public `parsed_cfg.json` in this repository contains the decoded non-secret profile fields.

---

## 15. Assessment

### What I can say with relatively high confidence

- The outer file is an NSIS installer.
- Its main payload is an unsigned 64-bit Horse Launcher.
- The launcher is a networked private-game launcher with account, download, integrity, invite, redemption, and launch-ticket functionality.
- The `.hors` file is cryptographically structured rather than arbitrary obfuscation.
- The uploaded `.hors` signature is valid for the public key expected by the launcher.
- The encrypted profile decrypts and parses cleanly.
- The profile contains server settings and artwork, not hidden executable code.
- I did not find obvious static evidence of a commodity browser/Discord/crypto credential stealer.
- I did not find static imports for the classic `WriteProcessMemory` + `CreateRemoteThread` injection pair.

### What remains uncertain without dynamic analysis

- every network request the program actually makes at runtime;
- whether the API endpoint redirects or returns different server infrastructure after login;
- the exact contents of downloaded game packages for each year;
- the exact behavior of the `winmm.dll` and `patch.dll` files delivered for this build;
- whether any APIs are resolved dynamically rather than imported normally;
- whether the launcher performs behavior that only activates after authentication or a specific server response.

### Bottom line

The static evidence is more consistent with a **custom private-server game launcher with patching/update behavior** than with an obvious off-the-shelf credential stealer. That does not make it automatically trustworthy. It is unsigned, receives executable content from remote infrastructure, and participates in game modification. For a safety verdict, the correct next step is a controlled dynamic run with process, filesystem, registry, DNS/TLS, and network logging, followed by separate analysis of the downloaded `winmm.dll`, `patch.dll`, and game packages.

---

## Files in this Analysis Bundle

```text
README.md
SHA256SUMS.txt
parsed_cfg.json
assets/
  cfg_art_0.jpg
  cfg_art_1.jpg
  cfg_art_2.png
  cfg_art_3.png
```

The original executable samples are deliberately not included in the bundle.

---

## Reference

The presentation style and broad analysis order were inspired by:

- Patchi, **Horse Museum: Taking Apart a Private Star Stable Launcher Distributed over Tor** (2026-09-28): https://patchi.fyi/blog/horse-empire-star-stable-launcher

The wording, measurements, hashes, and conclusions in this file are specific to the uploaded samples analyzed on 2026-10-06.
