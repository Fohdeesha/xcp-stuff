#!/usr/bin/env python
from __future__ import print_function
import argparse
import collections
import errno
import hashlib
import os
import re
import signal
import stat
import struct
import subprocess
import sys
import threading
import time
import xml.parsers.expat
VERSION = '1.2'
PYTHON = sys.version.split()[0]
DB_PATH = '/var/lib/xcp/state.db'
BACKUP_SUFFIX = '.snapshot_of.backup'
PRE_RESTORE_SUFFIX = '.snapshot_of.pre-restore-'
TMP_SUFFIX = '.snapshot_of.tmp-'
INVENTORY = '/etc/xensource-inventory'
POOL_CONF = '/etc/xensource/pool.conf'
DB_CONF = '/etc/xensource/db.conf'
LOCAL_DB = '/var/lib/xcp/local.db'
RESTORE_DB = '/var/lib/xcp/restore_db.db'
STAGING_DBS = ('/var/lib/xcp/ha_metadata.db', '/var/lib/xcp/gen_metadata.db')
STARTUP_COOKIE = '/var/run/xapi_startup.cookie'
INIT_COMPLETE_COOKIE = '/var/run/xapi_init_complete.cookie'
TOOLSTACK_LOCK = '/dev/shm/xe_toolstack_restart.lock'
XE = '/opt/xensource/bin/xe'
SYSTEMCTL = '/usr/bin/systemctl'
XAPI_UNIT = 'xapi.service'
PROC = '/proc'
SUPPORTED = ((8, 2), (8, 3))
NULL_REF = 'OpaqueRef:NULL'
LVM_SR_TYPES = ('lvm', 'lvmoiscsi', 'lvmohba', 'lvmofcoe')
POLL = 1.0
XE_TIMEOUT = 60
SYSTEMCTL_TIMEOUT = 60
STOP_TIMEOUT = 300
GONE_WAIT = 60
START_TIMEOUT = 120
READY_WAIT = 300
ANSWER_WAIT = 120
INIT_WAIT = 300
HA_DISABLE_TIMEOUT = 600
XHAD_GONE_WAIT = 60
HA_ENABLE_TIMEOUT = 900
HA_ENABLE_WINDOW = 300
HA_ENABLE_RETRY = 20
UUID_RE = re.compile(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$')
UUID_ANY = re.compile(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}')
_TEXT = type(u'')

def _text(value):
    if value is None:
        return u''
    if isinstance(value, _TEXT):
        return value
    if isinstance(value, bytes):
        return value.decode('utf-8', 'replace')
    try:
        return _TEXT(value)
    except Exception:
        pass
    try:
        return _text(str(value))
    except Exception:
        return _TEXT(value.__class__.__name__)

def _utf8(value):
    return _text(value).encode('utf-8')

def _native(value):
    if bytes is str:
        return _utf8(value)
    return _text(value)

_AUDIT = [False]
_SYSLOG = [None]

def _write(stream, text):
    data = _utf8(text + u'\n')
    out = getattr(stream, 'buffer', stream)
    try:
        out.write(data)
        out.flush()
    except (IOError, OSError, ValueError, RuntimeError):
        pass

def _log(level, text):
    if not _AUDIT[0]:
        return
    try:
        if _SYSLOG[0] is None:
            import syslog
            syslog.openlog('snapshot-fixer', syslog.LOG_PID, syslog.LOG_USER)
            _SYSLOG[0] = syslog
        mod = _SYSLOG[0]
        prio = {'info': mod.LOG_INFO, 'warning': mod.LOG_WARNING, 'err': mod.LOG_ERR}[level]
        for line in _text(text).splitlines():
            if line.strip():
                mod.syslog(prio, _native(line))
    except (ImportError, UnicodeError, TypeError, ValueError, EnvironmentError):
        pass

def say(text=u''):
    _write(sys.stdout, _text(text))
    _log('info', text)

def warn(text):
    _write(sys.stderr, u'WARNING: ' + _text(text))
    _log('warning', text)

def error(text):
    _write(sys.stderr, u'ERROR: ' + _text(text))
    _log('err', text)

def step(text):
    say(time.strftime('[%H:%M:%S] ') + _text(text))

class Refused(Exception):
    pass

class Failed(Exception):
    pass

class DbError(Exception):
    pass

class Interrupted(Exception):
    pass

_PENDING = [None]
_SETTLING = [False]

def _signame(signum):
    for name in ('SIGINT', 'SIGTERM', 'SIGHUP'):
        if getattr(signal, name, None) == signum:
            return name
    return 'signal %d' % signum

def _on_signal(signum, frame):
    if _SETTLING[0]:
        say('(%s ignored: xapi and HA are being put back - let this finish)' % _signame(signum))
        return
    if _PENDING[0] is None:
        _PENDING[0] = signum
        say('(%s received: stopping at the next safe point, then putting xapi and HA back)'
            % _signame(signum))

def arm_signals():
    signal.signal(signal.SIGINT, _on_signal)
    signal.signal(signal.SIGTERM, _on_signal)
    signal.signal(signal.SIGHUP, signal.SIG_IGN)

def checkpoint():
    if _PENDING[0] is not None and not _SETTLING[0]:
        raise Interrupted('interrupted by %s' % _signame(_PENDING[0]))

if hasattr(time, 'monotonic'):
    _now = time.monotonic
else:
    def _now():
        return os.times()[4]

def pause(seconds, interruptible=True):
    end = _now() + seconds
    while True:
        if interruptible:
            checkpoint()
        left = end - _now()
        if left <= 0:
            return
        time.sleep(min(left, 0.25))

class Ran(object):
    def __init__(self, argv, rc, out, err, timed_out):
        self.argv = argv
        self.rc = rc
        self.out = out
        self.err = err
        self.timed_out = timed_out
    @property
    def ok(self):
        return self.rc == 0 and not self.timed_out
    def why(self):
        if self.timed_out:
            return 'timed out'
        lines = [l.strip() for l in (self.err + u'\n' + self.out).splitlines() if l.strip()]
        detail = u' / '.join(lines[:3])
        if detail:
            return u'exit %d: %s' % (self.rc, detail[:400])
        return u'exit %d' % self.rc

def _killpg(proc):
    try:
        os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
    except OSError as exc:
        if exc.errno != errno.ESRCH:
            raise

def run(argv, timeout):
    devnull = open(os.devnull, 'rb')
    try:
        proc = subprocess.Popen(argv, stdin=devnull, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, close_fds=True,
                                preexec_fn=os.setsid)
    except OSError as exc:
        devnull.close()
        return Ran(argv, 127, u'', u'%s: %s' % (_text(argv[0]), _text(exc.strerror or exc)),
                   False)
    box = {}
    def reader():
        try:
            box['out'], box['err'] = proc.communicate()
        except (IOError, OSError, ValueError) as exc:
            box['failed'] = u'%s: %s' % (_text(argv[0]), _text(exc))
    worker = threading.Thread(target=reader)
    worker.daemon = True
    worker.start()
    worker.join(timeout)
    killed = worker.is_alive()
    if killed:
        try:
            _killpg(proc)
        except OSError:
            pass
        worker.join(5)
    devnull.close()
    if worker.is_alive():
        return Ran(argv, 124, u'', u'did not exit when killed', True)
    if 'failed' in box:
        return Ran(argv, 127, u'', box['failed'], False)
    return Ran(argv, proc.returncode, _text(box.get('out')), _text(box.get('err')), killed)

def xe(*args, **kwargs):
    return run([XE] + list(args), kwargs.get('timeout', XE_TIMEOUT))

def systemctl(*args, **kwargs):
    return run([SYSTEMCTL] + list(args), kwargs.get('timeout', SYSTEMCTL_TIMEOUT))

def read_file(path):
    with open(path, 'rb') as handle:
        return handle.read()

def read_text(path):
    return read_file(path).decode('utf-8', 'replace')

def fsync_dir(path):
    fd = os.open(os.path.dirname(os.path.abspath(path)), os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)

def write_new(path, data, mode=0o600, owner=None):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    done = False
    try:
        os.fchmod(fd, mode)
        if owner is not None and owner != (os.geteuid(), os.getegid()):
            os.fchown(fd, owner[0], owner[1])
        view = memoryview(data)
        pos = 0
        while pos < len(data):
            pos += os.write(fd, view[pos:pos + (1 << 20)])
        os.fsync(fd)
        done = True
    finally:
        os.close(fd)
        if not done:
            _unlink_quietly(path)
    fsync_dir(path)
    if read_file(path) != data:
        raise Failed('%s does not read back as written' % path)

def _unlink_quietly(path):
    try:
        os.unlink(path)
    except OSError:
        pass

def replace_file(path, data):
    try:
        st = os.stat(path)
        mode, owner = stat.S_IMODE(st.st_mode), (st.st_uid, st.st_gid)
    except OSError as exc:
        if exc.errno != errno.ENOENT:
            raise
        mode, owner = 0o600, None
    tmp = '%s%s%d' % (path, TMP_SUFFIX, os.getpid())
    _unlink_quietly(tmp)
    write_new(tmp, data, mode, owner)
    try:
        os.rename(tmp, path)
    except OSError:
        _unlink_quietly(tmp)
        raise
    fsync_dir(path)
    if read_file(path) != data:
        raise Failed('%s does not read back as written' % path)

def require_space(path, nbytes, copies):
    st = os.statvfs(os.path.dirname(os.path.abspath(path)))
    free = st.f_bavail * st.f_frsize
    need = nbytes * copies + (64 << 20)
    if free < need:
        raise Refused('%s has %d MiB free; this needs %d MiB (%d copies of the database and '
                      'a margin)' % (os.path.dirname(path), free >> 20, need >> 20, copies))

def same_file(a, b):
    try:
        sa, sb = os.stat(a), os.stat(b)
    except OSError:
        return False
    return (sa.st_dev, sa.st_ino) == (sb.st_dev, sb.st_ino)

class Record(object):
    __slots__ = ('cls', 'ref', 'uuid', 'name', 'is_snap', 'snap_of', 'sr', 'offset', 'names')

class Scan(object):
    def __init__(self):
        self.encoding = None
        self.manifest = []
        self.gen_offset = None
        self.tables = []
        self.rows = 0
        self.records = {'VM': collections.OrderedDict(), 'VDI': collections.OrderedDict()}
        self.srs = {}
        self.pool = None
    def meta(self, key, default='?'):
        return dict(self.manifest).get(key, default)

POOL_FIELDS = ('uuid', 'ha_enabled', 'redo_log_enabled')

def scan_db(data):
    scan = Scan()
    parser = xml.parsers.expat.ParserCreate()
    parser.ordered_attributes = True
    parser.buffer_text = True
    stack = []
    current = [None]
    def fail(msg):
        raise DbError('%s (at byte %d)' % (msg, parser.CurrentByteIndex))
    def on_decl(version, encoding, standalone):
        scan.encoding = encoding
    def on_doctype(*args):
        fail('unexpected DOCTYPE')
    def on_start(name, attrs):
        depth = len(stack)
        parent = stack[-1] if stack else None
        if depth == 0:
            if name != 'database':
                fail('the root element is <%s>, not <database>' % name)
        elif depth == 1:
            if name not in ('manifest', 'table'):
                fail('unexpected <%s> in <database>' % name)
        elif depth == 2:
            if not ((parent == 'manifest' and name == 'pair') or
                    (parent == 'table' and name == 'row')):
                fail('unexpected <%s> in <%s>' % (name, parent))
        else:
            fail('unexpected <%s> nested in <%s>' % (name, parent))
        fields = dict(zip(attrs[0::2], attrs[1::2]))
        if name == 'pair':
            scan.manifest.append((fields.get('key'), fields.get('value')))
            if fields.get('key') == 'generation_count':
                scan.gen_offset = parser.CurrentByteIndex
        elif name == 'table':
            table = fields.get('name')
            if not table:
                fail('a <table> without a name')
            if table in scan.tables:
                fail('table %s appears twice' % table)
            scan.tables.append(table)
            current[0] = table
        elif name == 'row':
            scan.rows += 1
            table = current[0]
            if table in scan.records:
                ref = fields.get('ref')
                if not ref:
                    fail('a %s row without a ref' % table)
                if ref in scan.records[table]:
                    fail('%s %s appears twice' % (table, ref))
                rec = Record()
                rec.cls = table
                rec.ref = ref
                rec.uuid = fields.get('uuid')
                rec.name = fields.get('name__label')
                rec.is_snap = fields.get('is_a_snapshot')
                rec.snap_of = fields.get('snapshot_of')
                rec.sr = fields.get('SR')
                rec.offset = parser.CurrentByteIndex
                rec.names = list(attrs[0::2]) if repairs_for(rec)[1] else None
                scan.records[table][ref] = rec
            elif table == 'SR':
                scan.srs[fields.get('ref')] = (fields.get('type'), fields.get('name__label'))
            elif table == 'pool':
                if scan.pool is not None:
                    fail('more than one pool row')
                scan.pool = dict((k, fields.get(k)) for k in POOL_FIELDS)
        stack.append(name)
    def on_end(name):
        stack.pop()
    def on_text(text):
        if text.strip():
            fail('unexpected text content')
    parser.XmlDeclHandler = on_decl
    parser.StartDoctypeDeclHandler = on_doctype
    parser.StartElementHandler = on_start
    parser.EndElementHandler = on_end
    parser.CharacterDataHandler = on_text
    try:
        parser.Parse(data, True)
    except xml.parsers.expat.ExpatError as exc:
        raise DbError('not well-formed XML: %s' % _text(exc))
    if scan.encoding is not None and scan.encoding.upper().replace('-', '') != 'UTF8':
        raise DbError('the database declares encoding %s, not UTF-8' % scan.encoding)
    for table in ('VM', 'VDI', 'pool'):
        if table not in scan.tables:
            raise DbError('the database has no %s table' % table)
    if scan.pool is None:
        raise DbError('the database has no pool row')
    if not re.match(r'^[0-9]+\Z', _text(scan.meta('generation_count', ''))):
        raise DbError('the manifest has no generation_count')
    return scan

class Repair(object):
    __slots__ = ('rec', 'reason', 'changes')
    def __init__(self, rec, reason, changes):
        self.rec = rec
        self.reason = reason
        self.changes = changes

def repairs_for(rec):
    if rec.is_snap is None or rec.snap_of is None:
        return None, []
    if rec.is_snap == 'false' and rec.snap_of != NULL_REF:
        return 'is not a snapshot, but its snapshot_of is set', [('snapshot_of', NULL_REF)]
    if rec.cls == 'VDI' and rec.is_snap == 'true' and rec.snap_of == rec.ref:
        return ('is a snapshot of itself',
                [('snapshot_of', NULL_REF), ('is_a_snapshot', 'false')])
    return None, []

def notes_for(rec):
    if rec.is_snap is None or rec.snap_of is None:
        return 'has no is_a_snapshot or snapshot_of field'
    if rec.is_snap not in ('true', 'false'):
        return 'has is_a_snapshot=%s' % rec.is_snap
    if rec.cls == 'VM' and rec.is_snap == 'true' and rec.snap_of == rec.ref:
        return 'is a snapshot of itself (the repair covers VDIs only, like the original)'
    return None

class Plan(object):
    def __init__(self, scan):
        self.scan = scan
        self.repairs = []
        self.notes = []
        for cls in ('VM', 'VDI'):
            for rec in scan.records[cls].values():
                reason, changes = repairs_for(rec)
                if changes:
                    old = {'snapshot_of': rec.snap_of, 'is_a_snapshot': rec.is_snap}
                    self.repairs.append(Repair(rec, reason,
                                               [(a, old[a], new) for a, new in changes]))
                note = notes_for(rec)
                if note:
                    self.notes.append((rec, note))

_WS = b'[ \t\r\n]'
_ATTR_RE = re.compile(_WS + b'+([^ \t\r\n=/>]+)' + _WS + b'*=' + _WS +
                      b'*(?:"([^"]*)"|\'([^\']*)\')')
_TAG_END_RE = re.compile(_WS + b'*/?>')

def tag_attributes(data, offset, tag):
    head = b'<' + tag
    if data[offset:offset + len(head)] != head:
        raise DbError('no <%s> start tag at byte %d' % (tag.decode('ascii'), offset))
    pos = offset + len(head)
    found = []
    while True:
        m = _ATTR_RE.match(data, pos)
        if m:
            group = 2 if m.group(2) is not None else 3
            found.append((m.group(1), m.start(group), m.end(group)))
            pos = m.end()
            continue
        if _TAG_END_RE.match(data, pos):
            return found
        raise DbError('cannot read the start tag at byte %d' % offset)

def build_patch(data, repairs):
    edits = []
    for rep in repairs:
        rec = rep.rec
        spans = tag_attributes(data, rec.offset, b'row')
        names = [_text(n) for n, _, _ in spans]
        if names != [_text(n) for n in rec.names]:
            raise DbError('%s %s: the attributes found at byte %d are not the ones the XML '
                          'parser reported' % (rec.cls, rec.uuid, rec.offset))
        where = dict((n, (s, e)) for n, (_, s, e) in zip(names, spans))
        for attr, old, new in rep.changes:
            start, end = where[attr]
            raw = data[start:end]
            if b'&' in raw or raw.decode('utf-8') != old:
                raise DbError('%s %s: %s is stored as "%s", expected "%s"' %
                              (rec.cls, rec.uuid, attr, _text(raw), old))
            edits.append((start, end, new.encode('ascii'), raw))
    edits.sort()
    for (s1, e1, _, _), (s2, _, _, _) in zip(edits, edits[1:]):
        if e1 > s2:
            raise DbError('two edits overlap at byte %d' % s2)
    out = []
    pos = 0
    for start, end, new, _ in edits:
        out.append(data[pos:start])
        out.append(new)
        pos = end
    out.append(data[pos:])
    return b''.join(out), edits

def canonical_digest(data, overrides=None):
    overrides = overrides or {}
    applied = set()
    digest = hashlib.sha256()
    stack = []
    table = [None]
    text = []
    def put(kind, *parts):
        digest.update(kind)
        for part in parts:
            raw = _utf8(part)
            digest.update(struct.pack('>Q', len(raw)))
            digest.update(raw)
    def flush():
        if text:
            put(b'T', u''.join(text))
            del text[:]
    def on_decl(version, encoding, standalone):
        put(b'D', version or u'', encoding or u'', _TEXT(standalone))
    def on_start(name, attrs):
        flush()
        pairs = list(zip(attrs[0::2], attrs[1::2]))
        key = None
        if name == 'table' and len(stack) == 1:
            table[0] = dict(pairs).get('name')
        elif name == 'row' and len(stack) == 2:
            key = (table[0], dict(pairs).get('ref'))
        elif name == 'pair' and stack == ['database', 'manifest']:
            key = ('manifest', dict(pairs).get('key'))
        if key is not None:
            change = overrides.get(key)
            if change is not None:
                if key in applied:
                    raise DbError('%s %s is in the document twice' % key)
                missing = set(change) - set(k for k, _ in pairs)
                if missing:
                    raise DbError('%s %s has no %s' % (key[0], key[1], ', '.join(sorted(missing))))
                pairs = [(k, change.get(k, v)) for k, v in pairs]
                applied.add(key)
        flat = []
        for k, v in pairs:
            flat.extend((k, v))
        put(b'S', name, _TEXT(len(pairs)), *flat)
        stack.append(name)
    def on_end(name):
        flush()
        put(b'E', name)
        stack.pop()
    def on_comment(data_):
        flush()
        put(b'C', data_)
    def on_pi(target, data_):
        flush()
        put(b'P', target, data_)
    parser = xml.parsers.expat.ParserCreate()
    parser.ordered_attributes = True
    parser.buffer_text = True
    parser.XmlDeclHandler = on_decl
    parser.StartElementHandler = on_start
    parser.EndElementHandler = on_end
    parser.CharacterDataHandler = text.append
    parser.CommentHandler = on_comment
    parser.ProcessingInstructionHandler = on_pi
    try:
        parser.Parse(data, True)
    except xml.parsers.expat.ExpatError as exc:
        raise DbError('not well-formed XML: %s' % _text(exc))
    flush()
    if applied != set(overrides):
        raise DbError('rows to change not found: %s' % ', '.join(
            '%s %s' % key for key in sorted(set(overrides) - applied)))
    return digest.hexdigest()

def verify_edits(original, patched, edits):
    out = []
    pos = 0
    shift = 0
    for start, end, new, old in edits:
        at = start + shift
        if patched[at:at + len(new)] != new:
            raise DbError('the patched file does not hold the new value at byte %d' % at)
        out.append(patched[pos:at])
        out.append(old)
        pos = at + len(new)
        shift += len(new) - (end - start)
    out.append(patched[pos:])
    if b''.join(out) != original:
        raise DbError('undoing the edits does not reproduce the original file')
    if len(patched) != len(original) + shift:
        raise DbError('the patched file is not the expected size')

def verify_patch(original, patched, edits, repairs):
    verify_edits(original, patched, edits)
    overrides = {}
    for rep in repairs:
        overrides[(rep.rec.cls, rep.rec.ref)] = dict((a, new) for a, _, new in rep.changes)
    if canonical_digest(patched) != canonical_digest(original, overrides):
        raise DbError('the patched file does not parse as the original plus the repairs')
    plan = Plan(scan_db(patched))
    if plan.repairs:
        raise DbError('the patched file still has %d record(s) to repair' % len(plan.repairs))

def with_generation(data, scan, generation):
    spans = tag_attributes(data, scan.gen_offset, b'pair')
    if [_text(n) for n, _, _ in spans] != ['key', 'value']:
        raise DbError('the generation_count <pair> is not key= then value=')
    _, start, end = spans[1]
    new = _utf8(_TEXT(generation))
    edits = [(start, end, new, data[start:end])]
    patched = data[:start] + new + data[end:]
    verify_edits(data, patched, edits)
    if canonical_digest(patched) != canonical_digest(
            data, {('manifest', 'generation_count'): {'value': _text(new)}}):
        raise DbError('the renumbered file does not parse as the original with a new generation')
    if scan_db(patched).meta('generation_count') != _text(new):
        raise DbError('the renumbered file does not read back as generation %s' % generation)
    return patched

def unprotect(value):
    return re.sub(r'%(.)', lambda m: {'.': ' ', '%': '%', 'n': '\n', 't': '\t', 'r': '\r',
                                      '_': '  '}.get(m.group(1), m.group(0)), _text(value))

def label(rec):
    name = unprotect(rec.name) if rec.name else u''
    return u'%s %s%s' % (rec.cls, rec.uuid, u'  "%s"' % name if name else u'')

def describe_target(scan, rec):
    if rec.snap_of == rec.ref:
        return u'itself'
    other = scan.records[rec.cls].get(rec.snap_of)
    if other is None:
        return u'%s, which is not in the database' % rec.snap_of
    return u'%s (%s)' % (label(other), u'a snapshot' if other.is_snap == 'true'
                         else u'not a snapshot')

def print_plan(plan, path, size):
    scan = plan.scan
    say(u'Database %s: %d bytes, generation %s, schema %s.%s' % (
        _text(path), size, scan.meta('generation_count'), scan.meta('schema_major_vsn'),
        scan.meta('schema_minor_vsn')))
    say(u'Checked %d VM and %d VDI records.' % (len(scan.records['VM']),
                                                len(scan.records['VDI'])))
    say(u'')
    if not plan.repairs:
        say(u'No incongruent snapshot links: nothing to repair.')
    else:
        say(u'%d record(s) to repair:' % len(plan.repairs))
        on_lvm = 0
        for rep in plan.repairs:
            rec = rep.rec
            say(u'')
            say(u'  ' + label(rec))
            if rec.cls == 'VDI':
                sr_type, sr_name = scan.srs.get(rec.sr, (None, None))
                say(u'      on SR "%s" (%s)' % (unprotect(sr_name or u'?'), sr_type or u'?'))
                on_lvm += sr_type in LVM_SR_TYPES
            say(u'      %s: snapshot_of is %s' % (rep.reason, describe_target(scan, rec)))
            for attr, old, new in rep.changes:
                say(u'      %s: %s -> %s' % (attr, old, new))
        by_target = collections.Counter((rep.rec.cls, rep.rec.snap_of) for rep in plan.repairs)
        shared = [(n, cls, ref) for (cls, ref), n in by_target.items() if n > 1]
        if shared:
            say(u'')
            for n, cls, ref in sorted(shared, reverse=True):
                say(u'  %d %ss point at %s' % (n, cls, ref))
        if on_lvm:
            say(u'')
            say(u'  %d of these VDIs are on LVM SRs. There, every SR scan sets snapshot_of again '
                u'from the SR\'s own metadata for each VDI it records as a snapshot, which '
                u'would undo the repair of such a VDI: run dry-run again after a scan to check.'
                % on_lvm)
    if plan.notes:
        say(u'')
        say(u'Also found, and NOT changed:')
        for rec, note in plan.notes:
            say(u'  %s %s' % (label(rec), note))

def require_root():
    if os.geteuid() != 0:
        raise Refused('run this as root: it stops xapi and edits its database')

def read_inventory():
    inv = {}
    try:
        text = read_text(INVENTORY)
    except EnvironmentError as exc:
        raise Refused('cannot read %s (%s): is this an XCP-ng host?' % (INVENTORY, _text(exc)))
    for line in text.splitlines():
        m = re.match(r'^\s*([A-Z0-9_]+)=(.*)$', line)
        if m:
            value = m.group(2).strip()
            if len(value) >= 2 and value[0] == value[-1] and value[0] in '\'"':
                value = value[1:-1]
            inv[m.group(1)] = value
    return inv

def check_platform():
    inv = read_inventory()
    version = inv.get('PRODUCT_VERSION', '')
    m = re.match(r'^(\d+)\.(\d+)', version)
    if not m:
        raise Refused('%s has no PRODUCT_VERSION: cannot tell which release this is'
                      % INVENTORY)
    if (int(m.group(1)), int(m.group(2))) not in SUPPORTED:
        raise Refused('this tool supports XCP-ng 8.2 and 8.3; this host runs %s %s'
                      % (inv.get('PRODUCT_BRAND', '?'), version))
    return inv

def require_master():
    try:
        role = read_text(POOL_CONF).strip()
    except EnvironmentError as exc:
        raise Refused('cannot read %s: %s' % (POOL_CONF, _text(exc)))
    if role == 'master':
        return
    if role.startswith('slave:'):
        raise Refused('this host is a pool member, not the master. Only the master\'s '
                      'database is live - a member keeps a stale backup copy - so run this '
                      'on the master, %s.' % role[len('slave:'):])
    raise Refused('%s says "%s", where "master" was expected' % (POOL_CONF, role))

def take_lock():
    import fcntl
    fd = os.open(TOOLSTACK_LOCK, os.O_RDWR | os.O_CREAT, 0o644)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except (IOError, OSError) as exc:
        os.close(fd)
        if exc.errno in (errno.EAGAIN, errno.EACCES):
            raise Refused('%s is held: xe-toolstack-restart, or another run of this tool, '
                          'is in progress. Wait for it to finish.' % TOOLSTACK_LOCK)
        raise Refused('cannot lock %s: %s' % (TOOLSTACK_LOCK, _text(exc)))
    return fd

def local_db_value(key):
    try:
        data = read_file(LOCAL_DB)
    except EnvironmentError:
        return None
    found = {}
    parser = xml.parsers.expat.ParserCreate()
    def on_start(name, attrs):
        if name == 'row' and 'key' in attrs:
            found[attrs['key']] = attrs.get('value')
    parser.StartElementHandler = on_start
    try:
        parser.Parse(data, True)
    except xml.parsers.expat.ExpatError:
        return None
    value = found.get(key)
    return None if value is None else _text(value)

def local_ha_armed():
    return local_db_value('ha.armed')

def read_generation(path, lenient):
    try:
        text = read_file(path).decode('ascii', 'replace')
    except EnvironmentError:
        return 0
    if lenient:
        text = text.strip()
    return int(text) if re.match(r'^[0-9]+\Z', text) else 0

def check_load_path():
    try:
        conf = read_text(DB_CONF)
    except EnvironmentError as exc:
        raise Refused('cannot read %s: %s' % (DB_CONF, _text(exc)))
    files = re.findall(r'^\s*\[(.*)\]\s*$', conf, re.M)
    if files != [DB_PATH]:
        raise Refused('%s names %s; this tool knows only the standard setup, the one '
                      'file %s' % (DB_CONF, ', '.join(files) or 'no database', DB_PATH))
    if re.search(r'^\s*compress\s*:\s*true\s*$', conf, re.M | re.I):
        raise Refused('%s asks for a compressed database, which this tool does not edit'
                      % DB_CONF)
    if os.path.lexists(RESTORE_DB):
        raise Refused('%s exists: a pool database restore is pending, and xapi loads that '
                      'file at its next start instead of %s' % (RESTORE_DB, DB_PATH))
    ours = read_generation(DB_PATH + '.generation', lenient=False)
    for staged in STAGING_DBS:
        if os.path.exists(staged):
            theirs = read_generation(staged + '.generation', lenient=True)
            if theirs >= ours:
                raise Refused('%s (generation %d) is not older than %s (generation %d), so '
                              'xapi would load it at its next start instead, ignoring the '
                              'change. It is what a start with HA or the database redo log '
                              'on leaves behind.' % (staged, theirs, DB_PATH, ours))

def pids_named(name):
    pids = []
    try:
        entries = os.listdir(PROC)
    except OSError:
        return pids
    for entry in entries:
        if not entry.isdigit():
            continue
        try:
            comm = read_file(os.path.join(PROC, entry, 'comm')).strip()
        except EnvironmentError:
            continue
        if comm == name:
            pids.append(int(entry))
    return sorted(pids)

def xapi_pids():
    return pids_named(b'xapi')

def xhad_pids():
    return pids_named(b'xhad')

def require_disarmed(interruptible=True):
    deadline = _now() + XHAD_GONE_WAIT
    while True:
        armed, pids = local_db_value('ha.armed'), xhad_pids()
        if armed in ('false', None) and not pids:
            step('HA is disarmed on this host (ha.armed=%s, no xhad process).' % armed)
            return
        if _now() > deadline:
            raise Failed('HA is not disarmed on this host after %ds (%s says ha.armed=%s; '
                         'xhad pid(s) %s), so xapi was not stopped'
                         % (XHAD_GONE_WAIT, LOCAL_DB, armed, pids or 'none'))
        pause(POLL, interruptible)

def unit_state():
    r = systemctl('is-active', XAPI_UNIT)
    return r.out.strip() or u'unknown'

def xapi_answers():
    r = xe('pool-list', '--minimal', timeout=30)
    return r.ok and bool(UUID_RE.match(r.out.strip()))

def stop_xapi(interruptible=True):
    step('Stopping xapi (xapi-init gives it up to a minute to write the database out)...')
    r = systemctl('stop', XAPI_UNIT, timeout=STOP_TIMEOUT)
    if not r.ok:
        warn('systemctl stop %s: %s' % (XAPI_UNIT, r.why()))
    deadline = _now() + GONE_WAIT
    while True:
        state, pids = unit_state(), xapi_pids()
        if state in ('inactive', 'failed') and not pids:
            break
        if _now() > deadline:
            raise Failed('xapi did not stop: the service is %s, xapi pid(s) %s'
                         % (state, pids or 'none'))
        pause(POLL, interruptible)
    result = systemctl('show', '-p', 'Result', XAPI_UNIT).out.strip()
    step('xapi is stopped (%s).' % (result or 'Result unknown'))

class Started(object):
    def __init__(self):
        self.ready = False
        self.answering = False
        self.complete = False
        self.detail = u''

def start_xapi(interruptible=True):
    step('Starting xapi...')
    res = Started()
    systemctl('reset-failed', XAPI_UNIT)
    r = systemctl('start', XAPI_UNIT, timeout=START_TIMEOUT)
    if not r.ok:
        warn('systemctl start %s: %s' % (XAPI_UNIT, r.why()))
    deadline = _now() + READY_WAIT
    while not os.path.exists(STARTUP_COOKIE):
        state = unit_state()
        if state == 'failed':
            res.detail = u'the xapi service failed while starting'
            return res
        if _now() > deadline:
            res.detail = u'xapi did not become ready within %ds (service %s)' % (
                READY_WAIT, state)
            return res
        pause(POLL, interruptible)
    res.ready = True
    deadline = _now() + ANSWER_WAIT
    while not xapi_answers():
        if _now() > deadline:
            res.detail = u'xapi is up but its CLI got no answer within %ds' % ANSWER_WAIT
            return res
        pause(POLL, interruptible)
    res.answering = True
    step('xapi is up and answering; waiting for it to finish initialising...')
    deadline = _now() + INIT_WAIT
    while not os.path.exists(INIT_COMPLETE_COOKIE):
        if _now() > deadline:
            res.detail = u'xapi has not finished initialising after %ds' % INIT_WAIT
            return res
        pause(POLL, interruptible)
    res.complete = True
    step('xapi has finished initialising.')
    return res

def ensure_xapi():
    if xapi_answers():
        return
    step('xapi is not answering; starting it to check the pool...')
    res = start_xapi()
    if not res.answering:
        raise Refused('xapi is not running and could not be started: %s. Nothing was '
                      'changed.' % res.detail)

def pool_uuid():
    r = xe('pool-list', '--minimal')
    uuid = r.out.strip()
    if not r.ok or not UUID_RE.match(uuid):
        raise Failed('cannot read the pool uuid: %s' % (r.why() if not r.ok else u'"%s"' % uuid))
    return uuid

def pool_param(pool, name):
    r = xe('pool-param-get', 'uuid=' + pool, 'param-name=' + name)
    if not r.ok:
        raise Failed('cannot read the pool\'s %s: %s' % (name, r.why()))
    return r.out.strip()

def ha_enabled(pool):
    value = pool_param(pool, 'ha-enabled')
    if value not in ('true', 'false'):
        raise Failed('the pool\'s ha-enabled reads "%s"' % value)
    return value == 'true'

def require_master_is_us(pool, inv):
    master = pool_param(pool, 'master')
    me = inv.get('INSTALLATION_UUID')
    if not me or master != me:
        raise Refused('xapi says the pool master is %s, but this host is %s'
                      % (master, me or '(no INSTALLATION_UUID)'))

def parse_xe_map(text):
    pairs = []
    for item in text.split('; '):
        if item.strip():
            key, sep, value = item.partition(': ')
            if not sep:
                raise Failed('cannot read the map "%s"' % text)
            pairs.append((key.strip(), value.strip()))
    return pairs

def parse_xe_records(text):
    records = []
    current = collections.OrderedDict()
    for line in text.splitlines():
        if not line.strip():
            if current:
                records.append(current)
                current = collections.OrderedDict()
            continue
        m = re.match(r'^\s*(\S.*?)\s*\(\s*[A-Z]+\s*\)\s*:\s?(.*)$', line)
        if m:
            current[m.group(1)] = m.group(2)
    if current:
        records.append(current)
    return records

def check_tasks(ignore):
    r = xe('task-list', 'status=pending', 'params=uuid,name-label')
    if not r.ok:
        raise Refused('cannot list pending tasks: %s' % r.why())
    tasks = parse_xe_records(r.out)
    if not tasks:
        return
    say('Pending tasks - stopping xapi on the master fails them:')
    for task in tasks:
        say('  %s  %s' % (task.get('uuid', '?'), task.get('name-label', '')))
    if not ignore:
        raise Refused('%d task(s) pending. Wait for them (backups, migrations...) to finish, '
                      'or pass --ignore-tasks to go ahead and let them fail.' % len(tasks))
    warn('going ahead with %d pending task(s): --ignore-tasks' % len(tasks))

class HaSettings(object):
    def __init__(self, srs, config, tolerate, overcommit):
        self.srs = srs
        self.config = config
        self.tolerate = tolerate
        self.overcommit = overcommit
    def enable_args(self):
        args = ['pool-ha-enable', 'heartbeat-sr-uuids=' + ','.join(self.srs)]
        for key, value in self.config:
            args.append('ha-config:%s=%s' % (key, value))
        return args
    def command(self):
        return 'xe ' + ' '.join(self.enable_args())

def capture_ha(pool):
    if not ha_enabled(pool):
        return None
    vdis = UUID_ANY.findall(pool_param(pool, 'ha-statefiles'))
    if not vdis:
        raise Refused('HA is enabled but its statefile cannot be found, so the heartbeat SR '
                      'it would have to be re-enabled on cannot be established')
    srs = []
    for vdi in vdis:
        r = xe('vdi-param-get', 'uuid=' + vdi, 'param-name=sr-uuid')
        sr = r.out.strip()
        if not r.ok or not UUID_RE.match(sr):
            raise Refused('cannot find the SR of HA statefile %s: %s'
                          % (vdi, r.why() if not r.ok else u'"%s"' % sr))
        if sr not in srs:
            srs.append(sr)
    return HaSettings(srs, parse_xe_map(pool_param(pool, 'ha-configuration')),
                      pool_param(pool, 'ha-host-failures-to-tolerate'),
                      pool_param(pool, 'ha-allow-overcommit'))

def disable_ha(pool, interruptible=True):
    step('Disabling HA...')
    r = xe('pool-ha-disable', timeout=HA_DISABLE_TIMEOUT)
    if not r.ok:
        raise Failed('xe pool-ha-disable: %s' % r.why())
    if ha_enabled(pool):
        raise Failed('HA still reads enabled after xe pool-ha-disable')
    step('HA is disabled.')

def enable_ha(pool, ha, interruptible=False):
    step('Re-enabling HA (heartbeat SR %s)...' % ', '.join(ha.srs))
    deadline = _now() + HA_ENABLE_WINDOW
    while True:
        r = xe(*ha.enable_args(), timeout=HA_ENABLE_TIMEOUT)
        try:
            if ha_enabled(pool):
                break
        except Failed:
            pass
        if _now() > deadline:
            raise Failed('%s: %s' % (ha.command(), r.why()))
        step('HA did not enable yet (%s); retrying in %ds...' % (r.why(), HA_ENABLE_RETRY))
        pause(HA_ENABLE_RETRY, interruptible)
    for param, want in (('ha-host-failures-to-tolerate', ha.tolerate),
                        ('ha-allow-overcommit', ha.overcommit)):
        now = pool_param(pool, param)
        if now != want:
            r = xe('pool-param-set', 'uuid=' + pool, '%s=%s' % (param, want))
            if not r.ok:
                raise Failed('HA is enabled, but %s is %s where it was %s, and setting it '
                             'back failed: %s' % (param, now, want, r.why()))
    step('HA is enabled again.')

def verify_live(repairs):
    try:
        import XenAPI
    except ImportError:
        return ['cannot check through the API: the XenAPI python module is not here']
    session = None
    problems = []
    try:
        session = XenAPI.xapi_local()
        session.xenapi.login_with_password('root', '', '', 'snapshot-fixer')
        for rep in repairs:
            rec = rep.rec
            api = session.xenapi.VM if rec.cls == 'VM' else session.xenapi.VDI
            is_snap = api.get_is_a_snapshot(rec.ref)
            snap_of = api.get_snapshot_of(rec.ref)
            if is_snap is not False or snap_of != NULL_REF:
                problems.append('%s %s reads is_a_snapshot=%s snapshot_of=%s'
                                % (rec.cls, rec.uuid, is_snap, snap_of))
    except Exception as exc:
        problems.append('reading the repaired objects back failed: %s' % _text(exc))
    finally:
        if session is not None:
            try:
                session.xenapi.session.logout()
            except Exception:
                pass
    return problems

class Run(object):
    def __init__(self, pool, ha):
        self.pool = pool
        self.ha = ha
        self.ha_touched = False
        self.xapi_touched = False
        self.fallback = None
        self.fallback_file = None
        self.installed = False
        self.rolled_back = False
        self.verified = False
        self.repairs = []
        self.written = []
        self.problems = []
    def fail(self, text):
        self.problems.append(_text(text))
        error(text)

def begin_disruptive():
    _AUDIT[0] = True
    arm_signals()
    _log('info', 'started: %s (python %s)' % (' '.join(sys.argv), PYTHON))

def settle(run_):
    _SETTLING[0] = True
    if run_.xapi_touched or not xapi_pids():
        try:
            up = start_xapi(interruptible=False)
            if not up.ready and run_.installed and run_.fallback is not None:
                run_.fail('xapi did not come up with the new database (%s).' % up.detail)
                rollback(run_)
            elif not up.answering:
                run_.fail('xapi is not answering: %s. Check it with: systemctl status xapi'
                          % up.detail)
            elif not up.complete:
                warn(up.detail)
        except Exception as exc:
            run_.fail('starting xapi failed: %s' % _text(exc))
    if run_.installed and run_.repairs:
        if xapi_answers():
            problems = verify_live(run_.repairs)
            for problem in problems:
                run_.fail(problem)
            if not problems:
                run_.verified = True
                step('All %d repaired record(s) read back as intended.' % len(run_.repairs))
        else:
            run_.fail('xapi is not answering, so the repair could not be read back')
    if run_.ha is not None and run_.ha_touched:
        try:
            if not ha_enabled(run_.pool):
                enable_ha(run_.pool, run_.ha)
        except Exception as exc:
            run_.fail('HA is not enabled again: %s' % _text(exc))
            run_.fail('Re-enable it with: %s' % run_.ha.command())

def rollback(run_):
    step('Putting the database back as it was before this run...')
    by_hand = ('by hand: systemctl stop xapi; cp -p %s %s; systemctl start xapi'
               % (run_.fallback_file, DB_PATH))
    try:
        stop_xapi(interruptible=False)
    except Failed as exc:
        run_.fail('cannot stop xapi to roll back (%s). Roll back %s' % (_text(exc), by_hand))
        return
    try:
        replace_file(DB_PATH, run_.fallback)
    except (EnvironmentError, Failed) as exc:
        run_.fail('cannot put the previous database back (%s). Roll back %s'
                  % (_describe(exc), by_hand))
        return
    run_.installed = False
    run_.rolled_back = True
    up = start_xapi(interruptible=False)
    if up.answering:
        step('xapi is running again, on the database as it was before this run.')
    else:
        run_.fail('xapi does not start with the previous database either (%s), so the '
                  'cause is not this change. Check: systemctl status xapi; journalctl -u '
                  'xapi; /var/log/xensource.log' % up.detail)

def ha_hint(ha):
    say('HA will be re-enabled at the end with:')
    say('    ' + ha.command())
    say('If this run is killed before then, run that command yourself.')

def check_stopped_db(scan):
    if scan.pool.get('ha_enabled') != 'false':
        raise Failed('the database written at shutdown says ha_enabled=%s'
                     % scan.pool.get('ha_enabled'))
    if scan.pool.get('redo_log_enabled') not in ('false', None):
        raise Failed('the database written at shutdown says redo_log_enabled=%s'
                     % scan.pool.get('redo_log_enabled'))
    check_host_flags()
    check_load_path()

def check_host_flags():
    for key in ('ha.armed', 'redo_log.enabled'):
        value = local_db_value(key)
        if value not in ('false', None):
            raise Failed('%s says %s=%s' % (LOCAL_DB, key, value))

def refuse_redo_log(scan):
    if scan.pool.get('redo_log_enabled') == 'true' or \
            local_db_value('redo_log.enabled') == 'true':
        raise Refused('the pool has the database redo log enabled (xe pool-enable-redo-log). '
                      'xapi loads it instead of the file at start, undoing the repair. '
                      'Disable it first with: xe pool-disable-redo-log')

def confirm(question, assume_yes):
    if assume_yes:
        return True
    if not sys.stdin.isatty():
        raise Refused('no terminal to confirm on: pass --yes to go ahead')
    _write(sys.stdout, u'%s Type "yes" to go ahead: ' % question)
    answer = getattr(sys.stdin, 'buffer', sys.stdin).readline()
    return _text(answer).strip().lower() == u'yes'

def read_live_db():
    last = None
    for attempt in range(3):
        try:
            data = read_file(DB_PATH)
        except EnvironmentError as exc:
            raise Refused('cannot read %s: %s' % (DB_PATH, _text(exc)))
        try:
            return data, scan_db(data)
        except DbError as exc:
            last = exc
            time.sleep(1)
    raise Refused('%s cannot be used: %s' % (DB_PATH, _text(last)))

def format_age(seconds):
    seconds = int(max(seconds, 0))
    if seconds < 3600:
        return '%dm' % (seconds // 60)
    if seconds < 86400 * 2:
        return '%dh%02dm' % (seconds // 3600, seconds % 3600 // 60)
    return '%dd' % (seconds // 86400)

def report(run_, what):
    say('')
    if run_.problems:
        error('%s did not complete cleanly:' % what)
        for problem in run_.problems:
            _write(sys.stderr, u'  - ' + problem)
    for path in run_.written:
        say('Kept: %s' % path)
    if run_.rolled_back:
        say('The database was put back as it was before this run.')
    elif run_.installed and run_.verified:
        say('Repaired %d record(s).' % len(run_.repairs))
    elif run_.installed and run_.repairs:
        say('The repaired database was installed, but the repair was not confirmed.')
    elif not run_.installed:
        say('The database was not changed.')
    _log('info', 'finished: %s' % ('with problems' if run_.problems else 'ok'))
    return 1 if run_.problems else 0

def cmd_dry_run(args):
    if args.database:
        path = args.database
        try:
            data = read_file(path)
        except EnvironmentError as exc:
            raise Refused('cannot read %s: %s' % (_text(path), _text(exc)))
        scan = scan_db(data)
    else:
        require_root()
        check_platform()
        require_master()
        path = DB_PATH
        data, scan = read_live_db()
    plan = Plan(scan)
    print_plan(plan, path, len(data))
    if not args.database:
        backup = DB_PATH + BACKUP_SUFFIX
        if os.path.lexists(backup):
            say('')
            say('Note: %s exists, from an earlier run (%s ago); rewrite will refuse until '
                'it is moved away.' % (backup, format_age(time.time() -
                                                           os.lstat(backup).st_mtime)))
        for check in (lambda: refuse_redo_log(scan), check_load_path):
            try:
                check()
            except Refused as exc:
                say('')
                say('Note: rewrite will refuse: %s' % _text(exc))
        if plan.repairs:
            say('')
            say('Nothing was changed. To repair: %s rewrite' % sys.argv[0])
    return 0

def locked(func, *args):
    fd = take_lock()
    try:
        return func(*args)
    finally:
        os.close(fd)

def cmd_rewrite(args):
    if args.database:
        return offline_rewrite(args.database)
    require_root()
    inv = check_platform()
    require_master()
    return locked(live_rewrite, args, inv)

def live_rewrite(args, inv):
    backup = DB_PATH + BACKUP_SUFFIX
    if os.path.lexists(backup):
        raise Refused('%s exists, from an earlier run (%s ago). If that run is over and the '
                      'pool is fine, move it away and run this again: mv %s %s.%s'
                      % (backup, format_age(time.time() - os.lstat(backup).st_mtime),
                         backup, backup, time.strftime('%Y%m%d-%H%M%S')))
    data, scan = read_live_db()
    plan = Plan(scan)
    print_plan(plan, DB_PATH, len(data))
    if not plan.repairs:
        return 0
    refuse_redo_log(scan)
    check_load_path()
    require_space(DB_PATH, len(data), 2)
    say('')
    ensure_xapi()
    pool = pool_uuid()
    require_master_is_us(pool, inv)
    check_tasks(args.ignore_tasks)
    ha = capture_ha(pool)
    say('')
    say('To repair, xapi is stopped for about a minute: no VM can be started, stopped or '
        'migrated meanwhile, and backups fail. Running VMs are not affected.')
    if ha:
        ha_hint(ha)
    if not confirm('Stop xapi and repair now?', args.yes):
        say('Nothing was changed.')
        return 1
    begin_disruptive()
    run_ = Run(pool, ha)
    try:
        do_rewrite(run_)
    except BaseException as exc:
        run_.fail(_describe(exc))
        settle(run_)
        if not isinstance(exc, (Interrupted, Failed, DbError, EnvironmentError)):
            raise
        return report(run_, 'The repair')
    settle(run_)
    return report(run_, 'The repair')

def do_rewrite(run_):
    if run_.ha:
        run_.ha_touched = True
        disable_ha(run_.pool)
        checkpoint()
    require_disarmed()
    run_.xapi_touched = True
    stop_xapi()
    checkpoint()
    data = read_file(DB_PATH)
    scan = scan_db(data)
    check_stopped_db(scan)
    plan = Plan(scan)
    if not plan.repairs:
        step('The database as xapi left it needs no repair after all: nothing written.')
        return
    step('Repairing %d record(s) in the database as xapi left it...' % len(plan.repairs))
    for rep in plan.repairs:
        step('  %s: %s' % (label(rep.rec), ', '.join('%s %s -> %s' % c for c in rep.changes)))
    patched, edits = build_patch(data, plan.repairs)
    verify_patch(data, patched, edits, plan.repairs)
    step('The repaired database is verified: only those %d value(s) differ.' % len(edits))
    backup = DB_PATH + BACKUP_SUFFIX
    write_new(backup, data)
    run_.written.append(backup)
    step('Backup written and read back: %s' % backup)
    checkpoint()
    run_.fallback, run_.fallback_file = data, backup
    run_.repairs = plan.repairs
    run_.installed = True
    replace_file(DB_PATH, patched)
    step('Repaired database in place.')

def cmd_restore(args):
    if args.database:
        return offline_restore(args.database)
    require_root()
    inv = check_platform()
    require_master()
    return locked(live_restore, args, inv)

def live_restore(args, inv):
    backup = DB_PATH + BACKUP_SUFFIX
    try:
        saved = read_file(backup)
    except EnvironmentError as exc:
        raise Refused('cannot read the backup %s: %s' % (backup, _text(exc)))
    try:
        bscan = scan_db(saved)
    except DbError as exc:
        raise Refused('the backup %s cannot be used: %s' % (backup, _text(exc)))
    taken = os.stat(backup).st_mtime
    say('Backup %s: %d bytes, generation %s, written %s (%s ago).' % (
        backup, len(saved), bscan.meta('generation_count'),
        time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(taken)),
        format_age(time.time() - taken)))
    try:
        current = read_file(DB_PATH)
    except EnvironmentError:
        current = None
    if current == saved:
        say('The live database is identical to the backup: nothing to restore.')
        return 0
    check_load_path()
    require_space(DB_PATH, len(saved), 2)
    was_up = xapi_answers()
    pool = ha = None
    if was_up:
        pool = pool_uuid()
        require_master_is_us(pool, inv)
        check_tasks(args.ignore_tasks)
        ha = capture_ha(pool)
    else:
        armed = local_ha_armed()
        if armed != 'false':
            raise Refused('xapi is not answering, so HA cannot be checked or disabled through '
                          'it, and %s says ha.armed=%s. Deal with HA first.'
                          % (LOCAL_DB, armed))
        warn('xapi is not answering. HA is not armed on this host; the backup is put in '
             'place and xapi started. Check HA afterwards.')
    say('')
    say('Restoring puts the whole database back to the moment the backup was taken: every '
        'change the pool has seen since (VMs, disks, snapshots, settings) is lost from '
        'xapi\'s records. The current database is kept beside it.')
    if ha:
        ha_hint(ha)
    if not confirm('Stop xapi and restore now?', args.yes):
        say('Nothing was changed.')
        return 1
    begin_disruptive()
    run_ = Run(pool, ha)
    try:
        do_restore(run_, saved, bscan, was_up)
    except BaseException as exc:
        run_.fail(_describe(exc))
        settle(run_)
        if not isinstance(exc, (Interrupted, Failed, DbError, EnvironmentError)):
            raise
        return report(run_, 'The restore')
    settle(run_)
    code = report(run_, 'The restore')
    if run_.installed and not run_.problems:
        say('The backup is back in place.')
    return code

def do_restore(run_, saved, bscan, was_up):
    if run_.ha:
        run_.ha_touched = True
        disable_ha(run_.pool)
        checkpoint()
    require_disarmed()
    run_.xapi_touched = True
    stop_xapi()
    checkpoint()
    check_host_flags()
    check_load_path()
    try:
        current = read_file(DB_PATH)
    except EnvironmentError as exc:
        if exc.errno != errno.ENOENT:
            raise
        current = None
    install = saved
    was = int(bscan.meta('generation_count'))
    now = read_generation(DB_PATH + '.generation', lenient=True)
    if current is not None:
        try:
            now = max(now, int(scan_db(current).meta('generation_count')))
        except DbError:
            pass
    if was <= now:
        install = with_generation(saved, bscan, now + 1)
        step('The backup (generation %d) goes in as generation %d: the database it '
             'replaces is generation %d, and the count must not go back.' % (was, now + 1, now))
    keep = None
    if current is not None:
        keep = DB_PATH + PRE_RESTORE_SUFFIX + time.strftime('%Y%m%d-%H%M%S')
        write_new(keep, current)
        run_.written.append(keep)
        step('The database being replaced is kept as %s' % keep)
    if was_up:
        run_.fallback, run_.fallback_file = current, keep
    run_.installed = True
    replace_file(DB_PATH, install)
    step('Backup in place.')

def offline_target(path):
    if same_file(path, DB_PATH):
        raise Refused('%s is the live database: run without --database, which stops xapi '
                      'first - editing it under a running xapi would be undone, or worse'
                      % _text(path))

def offline_rewrite(path):
    offline_target(path)
    backup = path + BACKUP_SUFFIX
    if os.path.lexists(backup):
        raise Refused('%s exists: move it away first' % _text(backup))
    try:
        data = read_file(path)
    except EnvironmentError as exc:
        raise Refused('cannot read %s: %s' % (_text(path), _text(exc)))
    plan = Plan(scan_db(data))
    print_plan(plan, path, len(data))
    if not plan.repairs:
        return 0
    patched, edits = build_patch(data, plan.repairs)
    verify_patch(data, patched, edits, plan.repairs)
    write_new(backup, data)
    replace_file(path, patched)
    say('')
    say('Repaired %d record(s) in %s; the original is %s'
        % (len(plan.repairs), _text(path), _text(backup)))
    return 0

def offline_restore(path):
    offline_target(path)
    backup = path + BACKUP_SUFFIX
    try:
        saved = read_file(backup)
    except EnvironmentError as exc:
        raise Refused('cannot read the backup %s: %s' % (_text(backup), _text(exc)))
    try:
        scan_db(saved)
    except DbError as exc:
        raise Refused('the backup %s cannot be used: %s' % (_text(backup), _text(exc)))
    try:
        current = read_file(path)
    except EnvironmentError:
        current = None
    if current == saved:
        say('%s is identical to its backup: nothing to restore.' % _text(path))
        return 0
    if current is not None:
        keep = path + PRE_RESTORE_SUFFIX + time.strftime('%Y%m%d-%H%M%S')
        write_new(keep, current)
        say('The file being replaced is kept as %s' % _text(keep))
    replace_file(path, saved)
    say('%s is back to its backup.' % _text(path))
    return 0

def _describe(exc):
    if isinstance(exc, EnvironmentError) and getattr(exc, 'filename', None):
        return u'%s: %s' % (_text(exc.filename), _text(exc.strerror or exc))
    return _text(exc) or _TEXT(exc.__class__.__name__)

def build_parser():
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument('--database', metavar='FILE', default=argparse.SUPPRESS,
                        help='work on this database file instead of the live one; '
                             'xapi and HA are not touched')
    parser = argparse.ArgumentParser(
        prog=os.path.basename(sys.argv[0]),
        description='Repair incongruent snapshot links (snapshot_of) in the xapi database. '
                    'For XCP-ng 8.2 and 8.3; run it on the pool master.',
        parents=[common])
    parser.add_argument('--version', action='version',
                        version='%(prog)s ' + VERSION + ' (python ' + PYTHON + ')')
    sub = parser.add_subparsers(dest='cmd', metavar='COMMAND')
    sub.required = True
    dry = sub.add_parser('dry-run', parents=[common],
                         help='show what would be repaired; stops nothing, changes nothing')
    dry.set_defaults(func=cmd_dry_run)
    for name, func, text in (
            ('rewrite', cmd_rewrite,
             'stop xapi, back the database up, repair it, start xapi (HA handled)'),
            ('restore-backup', cmd_restore,
             'stop xapi, put back the database rewrite saved, start xapi (HA handled)')):
        cmd = sub.add_parser(name, parents=[common], help=text)
        cmd.add_argument('-y', '--yes', action='store_true',
                         help='do not ask for confirmation')
        cmd.add_argument('--ignore-tasks', action='store_true',
                         help='go ahead even though xapi has tasks pending')
        cmd.set_defaults(func=func)
    return parser

def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    parser = build_parser()
    if not argv:
        parser.print_help()
        return 1
    args = parser.parse_args(argv)
    if not hasattr(args, 'database'):
        args.database = None
    say(u'snapshot-fixer %s (python %s)' % (VERSION, PYTHON))
    try:
        return args.func(args)
    except Refused as exc:
        error(_text(exc))
        return 1
    except DbError as exc:
        error('the database cannot be used: %s. Nothing was changed.' % _text(exc))
        return 1
    except (Failed, EnvironmentError) as exc:
        error('%s. Nothing was changed.' % _describe(exc))
        return 1

if __name__ == '__main__':
    sys.exit(main())
