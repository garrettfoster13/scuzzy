# scuzzy

A minimal, dependency-free iSCSI client written in Python, focused on read-only
interaction with iSCSI targets that restrict access by initiator IQN.

It speaks enough of the iSCSI protocol (RFC 3720) to perform logins, discovery,
SCSI READ(10) operations, and basic NTFS parsing — entirely over a raw socket,
with no external libraries.

## Features

- **Zero dependencies** — pure Python 3 standard library (`socket`, `struct`,
  `hashlib`, `argparse`).
- **Read-only** — the only SCSI command issued is READ(10); nothing on the
  target is ever written.
- **Discovery without target knowledge** — the `oracle` command uses
  `SessionType=Discovery` logins (which require no TargetName) to enumerate
  which initiator IQNs are authorized and leak the target IQNs they can see.
- **NTFS awareness** — parses the GPT partition table, NTFS boot sector, and
  `$MFT` records to list directories and stream files off the volume.
- **Streamed downloads** — files are written chunk-by-chunk (16 KB READ bursts)
  with on-the-fly SHA256, so multi-GB images don't exhaust memory.

## Usage

Connection parameters are global arguments that precede the subcommand:

```
scuzzy.py --portal <host> [--port 3260] [--target <target IQN>] [--ini <initiator IQN>] <command> [options]
```

| Arg | Description |
|---|---|
| `--portal` | iSCSI portal host/IP (required) |
| `--port` | Portal TCP port (default `3260`) |
| `--target` | Target IQN (required by all commands except `oracle`) |
| `--ini` | Initiator IQN to claim (e.g. `iqn.1991-05.com.microsoft:node01`) |

### Commands

#### `probe` — discover targets

Performs a discovery login and issues `SendTargets=All` to see what the portal
returns for a given initiator IQN.

```
python3 scuzzy.py --portal 10.10.10.10 --ini iqn.1991-05.com.microsoft:node01 probe
```

#### `oracle` — brute-force initiator/target authorization

Tests a list of candidate source IQNs. Authorized initiators get a populated
SendTargets response (leaking the target IQN); unauthorized ones get an empty
response. No target IQN is needed up front.

```
python3 scuzzy.py --portal 10.10.10.10 oracle --ini-list iqn.1991-05.com.microsoft:node01 iqn.1991-05.com.microsoft:node02
python3 scuzzy.py --portal 10.10.10.10 oracle --ini-list @candidates.txt
```

`--ini-list` accepts space- or comma-separated IQNs, or `@file` with one IQN
per line (`#` comments allowed).

#### `login` — verify a normal-session login

```
python3 scuzzy.py --portal 10.10.10.10 --ini <iqn> --target <target-iqn> login
```

#### `ls` — list files on the target volume

Reads the GPT, NTFS boot sector, and `$MFT` to enumerate files.

```
python3 scuzzy.py --portal 10.10.10.10 --ini <iqn> --target <target-iqn> ls
python3 scuzzy.py --portal 10.10.10.10 --ini <iqn> --target <target-iqn> ls --path "Cluster"
python3 scuzzy.py ... ls --maxrec 8192
```

#### `download` — stream a file off the volume

Fetches a file by exact `$MFT` basename or by Windows-style path, computing
SHA256 as it goes.

```
python3 scuzzy.py ... download --name 0.hive
python3 scuzzy.py ... download --path "testvm/Virtual Hard Disks/testvm.vhdx" --out ./out.vhdx
```

## Notes & limitations

- Targets requiring CHAP or other auth are not supported (login will fail).
- Header/data digests are negotiated to `None`.
- File resolution depends on scanning `$MFT` records; if a file isn't found,
  try a larger `--maxrec`.
- Sparse (data-hole) runs are skipped and zero-filled logically; a size
  mismatch warning is printed if the output is incomplete.

## License

TBD
