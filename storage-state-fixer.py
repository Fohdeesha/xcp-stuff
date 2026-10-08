#!/usr/bin/env python3
import sys
if sys.version_info < (3, 6):
    sys.stderr.write('storage-state-fixer needs python 3.6 or later (XCP-ng 8.3): run it as python3 %s\n'
                     % (sys.argv[0] if sys.argv else 'storage-state-fixer.py'))
    sys.exit(2)
import argparse
import ast
import atexit
import base64
import collections
import errno
import gzip
import hashlib
import json
import math
import os
import re
import shutil
import signal
import socket
import stat
import subprocess
import tempfile
import threading
import time
import xml.parsers.expat

VERSION = '1.6'
PYTHON = sys.version.split()[0]
PROG = 'storage-state-fixer'
STORAGE_DB = '/var/run/nonpersistent/xapi/storage.db'
STORAGE_DPS = '/var/run/nonpersistent/xapi/storage-dps'
SM_BACKEND = '/dev/sm/backend'
SM_PHY = '/dev/sm/phy'
BLKTAP_DIR = '/dev/xen/blktap-2'
SYS_BLKTAP = '/sys/class/blktap2'
SYS_DEV_BLOCK = '/sys/dev/block'
SYS_BLOCK = '/sys/block'
XENSOURCE_LOG = '/var/log/xensource.log'
VHD_UTIL = '/usr/bin/vhd-util'
IPC_DIR = '/var/run/sm/ipc'
SM_REFCOUNT = '/var/run/sm/refcount'
SR_MOUNT = '/var/run/sr-mount'
DRBD_BY_RES = '/dev/drbd/by-res'
NBD_VBDS = '/var/lib/xapi-nbd/VBDs_to_clean_up'
SM_LOCK_DIR = '/var/lock/sm'
SMLOG = '/var/log/SMlog'
LOCAL_DB = '/var/lib/xcp/local.db'
INVENTORY = '/etc/xensource-inventory'
POOL_CONF = '/etc/xensource/pool.conf'
STATIC_VDIS = '/etc/xensource/static-vdis'
STARTUP_COOKIE = '/var/run/xapi_startup.cookie'
INIT_COOKIE = '/var/run/xapi_init_complete.cookie'
TOOLSTACK_LOCK = '/dev/shm/xe_toolstack_restart.lock'
TOOLSTACK_SCRIPT = '/opt/xensource/bin/xe-toolstack-restart'
SM_DIR = '/opt/xensource/sm'
PLUGIN_DIR = '/etc/xapi.d/plugins'
PROC = '/proc'
XE = '/opt/xensource/bin/xe'
SYSTEMCTL = '/usr/bin/systemctl'
TAPCTL = '/usr/sbin/tap-ctl'
XENSTORE_LS = '/usr/bin/xenstore-ls'
XENSTORE_LIST = '/usr/bin/xenstore-list'
XENSTORE_READ = '/usr/bin/xenstore-read'
SS = '/usr/sbin/ss'
DRBDSETUP = '/usr/sbin/drbdsetup'
RPM = '/usr/bin/rpm'
LVS = '/usr/sbin/lvs'
VGS = '/usr/sbin/vgs'
PVS = '/usr/sbin/pvs'
DMSETUP = '/usr/sbin/dmsetup'
RUN_ROOT = '/var/lib/storage-state-fixer'
RUN_LOCK = '/var/lock/storage-state-fixer.lock'
REMOTE_PYTHON = 'python3'
XAPI_UNIT = 'xapi.service'
NBD_PORT = 10809
UUID_PAT = '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'
UUID_RE = re.compile('^' + UUID_PAT + '$')
NULL_REF = 'OpaqueRef:NULL'
LETTERS = 'abcdefghijklmnopqrstuvwxyz'
PAUSED = 0x20
RESUME_FAILED = 0x200
LOG_DROPPED = 0x100
SETTLE_FLOOR = 150
POLL = 1.0
XE_TIMEOUT = 60
SYSTEMCTL_TIMEOUT = 60
AGENT_TIMEOUT = 300
SSH_CONNECT = 15
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
REARM_WAIT = 120
LIVE_WAIT = 300
GUARDIAN_POLL = 10
GUARDIAN_BACKSTOP = 2700
GUARDIAN_STALL = 600
GUARD_LOCK_WAIT = 600
ACT_WAIT = 1800
LONE_WAIT = 30
ENSURE_TIMEOUT = 1800
ENSURE_MARGIN = 60
ACT_START_TIMEOUT = 120
FETCH_TIMEOUT = 120
TASK_WAIT = 120
HOUSEKEEPING_TASKS = ('SR.scan',)
UNPLUG_TIMEOUT = 300
CANCEL_WAIT = 60
DP_DESTROY_TIMEOUT = 300
SCAN_TIMEOUT = 300
PLUGIN_TIMEOUT = 300
PROBE_TIMEOUT = 60
VERIFY_DELAY = 30
RETEST_EVERY = 60
IO_WAIT = 30
IO_EVERY = 5
KICK_WAIT = 60
STUCK_SM_AGE = 900
ACTIVATE_QUIET = 1800
ABORT_MIN_AGE = 900
API_TIMEOUT = 120
QUIET_WAIT = 30
FENCE_HOLD = 45
FENCE_ACQUIRE = 10
FENCE_POLL = 0.2
FENCE_MARGIN = 15
C12_FENCE_HOLD = 120
UNPAUSE_WAIT = 300
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
        return _text(repr(value))
    except Exception:
        return _TEXT(value.__class__.__name__)


def _quote(value):
    value = _text(value)
    if re.match(u'^[A-Za-z0-9@%+=:,./_-]+\\Z', value):
        return value
    return u"'" + value.replace(u"'", u"'\"'\"'") + u"'"


_AUDIT = [False]
_SYSLOG = [None]
_OUT = {'quiet': False, 'json': False}


def _write(stream, text):
    data = (_text(text) + u'\n').encode('utf-8', 'replace')
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
            syslog.openlog(PROG, syslog.LOG_PID, syslog.LOG_USER)
            _SYSLOG[0] = syslog
        mod = _SYSLOG[0]
        prio = {'info': mod.LOG_INFO, 'warning': mod.LOG_WARNING, 'err': mod.LOG_ERR}[level]
        for line in _text(text).splitlines():
            if line.strip():
                mod.syslog(prio, line)
    except (ImportError, UnicodeError, TypeError, ValueError, EnvironmentError):
        pass


def say(text=u''):
    _write(sys.stderr if _OUT['json'] else sys.stdout, _text(text))
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
    def __init__(self, text, code=1):
        Exception.__init__(self, text)
        self.code = code


class Failed(Exception):
    pass


class Interrupted(Exception):
    pass


class Skip(Exception):
    pass


class Usage(Exception):
    pass


_PENDING = [None]
_SETTLING = [False]
_SIGNALS = [0]
_STOP_NOTE = [u'stopping at the next safe point, then putting xapi and HA back']
_WAITING = [None]


def _signame(signum):
    for name in ('SIGINT', 'SIGTERM', 'SIGHUP'):
        if getattr(signal, name, None) == signum:
            return name
    return 'signal %d' % signum


def waiting(text):
    _WAITING[0] = text


def _on_signal(signum, frame):
    _SIGNALS[0] += 1
    now = (u'; now: %s' % _WAITING[0]) if _WAITING[0] else u''
    if _SETTLING[0]:
        say(u'(%s ignored (%d so far): xapi and HA are being put back - let this finish%s)'
            % (_signame(signum), _SIGNALS[0], now))
        return
    if _PENDING[0] is None:
        _PENDING[0] = signum
        say(u'(%s received: %s%s)' % (_signame(signum), _STOP_NOTE[0], now))
    else:
        say(u'(%s again (%d so far): still %s%s)' % (_signame(signum), _SIGNALS[0], _STOP_NOTE[0], now))


def arm_signals():
    signal.signal(signal.SIGINT, _on_signal)
    signal.signal(signal.SIGTERM, _on_signal)
    signal.signal(signal.SIGHUP, signal.SIG_IGN)


def checkpoint():
    if _PENDING[0] is not None and not _SETTLING[0]:
        raise Interrupted('interrupted by %s' % _signame(_PENDING[0]))


_now = time.monotonic


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
            return u'timed out'
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


_DEADLINE = [None]
_ENSURE_END = [None]


def tmo(seconds):
    if _DEADLINE[0] is None:
        return seconds
    left = _DEADLINE[0] - _now()
    if left < 1:
        raise Failed('not asked: the facts call ran out of its time budget')
    return min(seconds, left)


def run(argv, timeout, data=None, env=None, raw=False):
    timeout = tmo(timeout)
    try:
        proc = subprocess.Popen(argv, stdin=subprocess.PIPE if data is not None else subprocess.DEVNULL,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True,
                                start_new_session=True, env=env)
    except OSError as exc:
        return Ran(argv, 127, b'' if raw else u'',
                   u'%s: %s' % (_text(argv[0]), _text(exc.strerror or exc)), False)
    box = {}

    def reader():
        try:
            box['out'], box['err'] = proc.communicate(data)
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
    if worker.is_alive():
        return Ran(argv, 124, b'' if raw else u'', u'did not exit when killed', True)
    if 'failed' in box:
        return Ran(argv, 127, b'' if raw else u'', box['failed'], False)
    out = box.get('out') or b''
    return Ran(argv, proc.returncode, out if raw else _text(out), _text(box.get('err')), killed)


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
    fd = os.open(os.path.dirname(os.path.abspath(path)) or '/', os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _unlink_quietly(path):
    try:
        os.unlink(path)
    except OSError:
        pass


def append_all(fd, data):
    view = memoryview(data)
    pos = 0
    while pos < len(data):
        n = os.write(fd, view[pos:pos + (1 << 20)])
        if not n:
            raise IOError(errno.ENOSPC, 'the write made no progress')
        pos += n


def write_new(path, data, mode=0o600):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    done = False
    try:
        os.fchmod(fd, mode)
        append_all(fd, data)
        os.fsync(fd)
        done = True
    finally:
        os.close(fd)
        if not done:
            _unlink_quietly(path)
    fsync_dir(path)
    if read_file(path) != data:
        raise Failed('%s does not read back as written' % path)


def replace_file(path, data, tmp_tag='ssf-tmp'):
    try:
        st = os.stat(path)
        mode = stat.S_IMODE(st.st_mode)
    except OSError as exc:
        if exc.errno != errno.ENOENT:
            raise
        mode = 0o644
    tmp = '%s.%s-%d' % (path, tmp_tag, os.getpid())
    _unlink_quietly(tmp)
    write_new(tmp, data, mode)
    try:
        os.rename(tmp, path)
    except OSError:
        _unlink_quietly(tmp)
        raise
    fsync_dir(path)
    if read_file(path) != data:
        raise Failed('%s does not read back as written' % path)


def write_json_atomic(path, obj):
    data = json.dumps(obj, sort_keys=True).encode('utf-8')
    tmp = '%s.tmp-%d' % (path, os.getpid())
    _unlink_quietly(tmp)
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        append_all(fd, data)
        os.fsync(fd)
    finally:
        os.close(fd)
    os.rename(tmp, path)
    fsync_dir(path)


def read_json(path):
    return json.loads(read_text(path))


def sha256_bytes(data):
    return hashlib.sha256(data).hexdigest()


def canon(obj):
    return json.dumps(obj, sort_keys=True, separators=(',', ':'))


def devname(userdevice):
    n = int(_text(userdevice))
    if n < 0 or n >= 26 * 27:
        raise ValueError('userdevice %d is out of the xvd naming range' % n)
    if n < 26:
        return 'xvd' + LETTERS[n]
    return 'xvd' + LETTERS[n // 26 - 1] + LETTERS[n % 26]


def format_age(seconds):
    if seconds is None:
        return u'?'
    seconds = int(max(seconds, 0))
    if seconds < 120:
        return u'%ds' % seconds
    if seconds < 3600:
        return u'%dm' % (seconds // 60)
    if seconds < 86400 * 2:
        return u'%dh%02dm' % (seconds // 3600, seconds % 3600 // 60)
    return u'%dd%02dh' % (seconds // 86400, seconds % 86400 // 3600)


def parse_inventory(text):
    inv = {}
    for line in text.splitlines():
        m = re.match(r'^\s*([A-Z0-9_]+)=(.*)$', line)
        if m:
            value = m.group(2).strip()
            if len(value) >= 2 and value[0] == value[-1] and value[0] in '\'"':
                value = value[1:-1]
            inv[m.group(1)] = value
    return inv


def unit_name(sr_uuid):
    return 'SMGC@' + sr_uuid.replace('-', '\\x2d')


def short(uuid):
    return _text(uuid)[:8]


def boot_time():
    for line in read_text(PROC + '/stat').splitlines():
        if line.startswith('btime '):
            return int(line.split()[1])
    raise Failed('no btime in %s/stat' % PROC)


_CLK = [None]


def clk_tck():
    if _CLK[0] is None:
        _CLK[0] = os.sysconf('SC_CLK_TCK')
    return _CLK[0]


def proc_stat(pid):
    data = read_text('%s/%d/stat' % (PROC, pid))
    rp = data.rindex(')')
    comm = data[data.index('(') + 1:rp]
    rest = data[rp + 2:].split()
    return {'comm': comm, 'state': rest[0], 'ticks': int(rest[11]) + int(rest[12]),
            'start_ticks': int(rest[19]), 'flags': int(rest[6])}


def proc_start(pid, btime):
    return btime + proc_stat(pid)['start_ticks'] / float(clk_tck())


def proc_cmdline(pid):
    raw = read_file('%s/%d/cmdline' % (PROC, pid))
    return [_text(a) for a in raw.split(b'\0') if a]


def proc_io(pid):
    out = {}
    try:
        for line in read_text('%s/%d/io' % (PROC, pid)).splitlines():
            k, _, v = line.partition(':')
            if v.strip().isdigit():
                out[k.strip()] = int(v.strip())
    except EnvironmentError:
        return None
    return out


def pids():
    out = []
    for entry in os.listdir(PROC):
        if entry.isdigit():
            out.append(int(entry))
    return sorted(out)


GONE_ERRNOS = (errno.ENOENT, errno.ESRCH)


def gone(exc):
    return getattr(exc, 'errno', None) in GONE_ERRNOS


def pid_alive(pid, start=None, btime=None):
    try:
        st = proc_stat(pid)
    except EnvironmentError as exc:
        return not gone(exc)
    except (ValueError, IndexError):
        return True
    if st['state'] == 'Z':
        return False
    if start is not None and btime is not None:
        return abs(btime + st['start_ticks'] / float(clk_tck()) - start) < 2
    return True


def pids_named(name):
    found = []
    for pid in pids():
        try:
            if read_file('%s/%d/comm' % (PROC, pid)).strip() != name:
                continue
            if proc_stat(pid)['state'] == 'Z':
                continue
        except EnvironmentError as exc:
            if gone(exc):
                continue
            raise Failed('pid %d cannot be read, so whether it is %s is not established: %s'
                         % (pid, _text(name), _text(exc)))
        found.append(pid)
    return found


def comm_strict(pid):
    try:
        return read_file('%s/%d/comm' % (PROC, pid)).strip().decode('utf-8', 'replace')
    except EnvironmentError as exc:
        if gone(exc):
            return None
        raise


class SchemaError(Exception):
    pass


DP_STATES = ('Attached', 'Activated')
DP_MODES = ('RO', 'RW')
ENTRY_KEYS = ('attach_info', 'dps', 'dpv', 'leaked')
ERROR_KEYS = ('dp', 'time', 'sr', 'vdi', 'error')
IMPL_FIELDS = {'XenDisk': ('params', 'extra', 'backend_type'), 'BlockDevice': ('path',), 'File': ('path',),
               'Nbd': ('uri',)}


def _is_str(v):
    return isinstance(v, _TEXT)


def _shape(v):
    return canon(v)[:120]


def check_backend(where, ai):
    if not isinstance(ai, dict) or set(ai) != set(['implementations']):
        raise SchemaError('%s attach_info is not {"implementations": [...]}: %s' % (where, _shape(ai)))
    impls = ai['implementations']
    if not isinstance(impls, list):
        raise SchemaError('%s attach_info implementations is not a list: %s' % (where, _shape(impls)))
    for imp in impls:
        if not (isinstance(imp, list) and len(imp) == 2 and _is_str(imp[0]) and imp[0] in IMPL_FIELDS and
                isinstance(imp[1], dict)):
            raise SchemaError('%s attach_info names an implementation xapi does not know: %s' % (where, _shape(imp)))
        fields = IMPL_FIELDS[imp[0]]
        if set(imp[1]) != set(fields):
            raise SchemaError('%s attach_info %s has the fields %s, where xapi has %s'
                              % (where, imp[0], ', '.join(sorted(imp[1])), ', '.join(sorted(fields))))
        for f in fields:
            v = imp[1][f]
            if f == 'extra':
                if not isinstance(v, dict) or any(not _is_str(x) for x in v.values()):
                    raise SchemaError('%s attach_info %s extra is not a map of strings: %s'
                                      % (where, imp[0], _shape(v)))
            elif not _is_str(v):
                raise SchemaError('%s attach_info %s %s is not a string: %s' % (where, imp[0], f, _shape(v)))


def check_storage_db(obj):
    if not isinstance(obj, dict):
        raise SchemaError('the document is not an object')
    extra = set(obj) - set(['errors', 'host'])
    if extra:
        raise SchemaError('unknown top-level key(s) %s' % ', '.join(sorted(extra)))
    for k in ('errors', 'host'):
        if k not in obj:
            raise SchemaError('it has no %s, which xapi requires' % k)
    if not isinstance(obj['errors'], list):
        raise SchemaError('errors is not a list')
    for rec in obj['errors']:
        if not isinstance(rec, dict) or set(rec) != set(ERROR_KEYS):
            raise SchemaError('an errors record is not {%s}: %s' % (', '.join(ERROR_KEYS), _shape(rec)))
        if any(not _is_str(rec[k]) for k in ('dp', 'sr', 'vdi', 'error')) or \
                not isinstance(rec['time'], (int, float)) or isinstance(rec['time'], bool):
            raise SchemaError('an errors record has a field of the wrong type: %s' % _shape(rec))
    host = obj['host']
    if not isinstance(host, dict):
        raise SchemaError('host is not an object')
    if set(host) != set(['srs']):
        raise SchemaError('host has the key(s) %s, where xapi has srs' % (', '.join(sorted(host)) or 'none'))
    srs = host['srs']
    if not isinstance(srs, dict):
        raise SchemaError('host.srs is not an object')
    entries = []
    for sr, srd in srs.items():
        if not UUID_RE.match(sr):
            raise SchemaError('SR key %s is not a uuid' % sr)
        if not isinstance(srd, dict) or set(srd) != set(['vdis']):
            raise SchemaError('SR %s is not {"vdis": {...}}' % sr)
        vdis = srd['vdis']
        if not isinstance(vdis, dict):
            raise SchemaError('SR %s vdis is not an object' % sr)
        for vdi, e in vdis.items():
            if not isinstance(vdi, _TEXT) or not vdi:
                raise SchemaError('a VDI key in SR %s is not a string' % sr)
            if not isinstance(e, dict):
                raise SchemaError('VDI %s entry is not an object' % vdi)
            bad = set(e) - set(ENTRY_KEYS)
            if bad:
                raise SchemaError('VDI %s has unknown key(s) %s' % (vdi, ', '.join(sorted(bad))))
            for k in ('dps', 'leaked'):
                if k not in e:
                    raise SchemaError('VDI %s has no %s, which xapi requires' % (vdi, k))
            dps = e['dps']
            if not isinstance(dps, dict):
                raise SchemaError('VDI %s dps is not an object' % vdi)
            for dp, st in dps.items():
                if not isinstance(dp, _TEXT) or not dp:
                    raise SchemaError('VDI %s has a datapath name that is not a string' % vdi)
                if (not isinstance(st, list) or len(st) != 2 or st[0] not in DP_STATES
                        or st[1] not in DP_MODES):
                    raise SchemaError('VDI %s datapath %s has state %s' % (vdi, dp, canon(st)))
            leaked = e['leaked']
            if not isinstance(leaked, list) or any(not isinstance(v, _TEXT) or not v for v in leaked):
                raise SchemaError('VDI %s leaked has an unexpected shape' % vdi)
            dpv = e.get('dpv', {})
            if not isinstance(dpv, dict) or any(not isinstance(v, _TEXT) for v in dpv.values()):
                raise SchemaError('VDI %s dpv has an unexpected shape' % vdi)
            loose = sorted(set(dpv) - set(dps) - set(leaked))
            if loose:
                raise SchemaError('VDI %s dpv names %s, which is neither a datapath nor leaked'
                                  % (vdi, ', '.join(loose[:4])))
            if 'attach_info' in e:
                check_backend('VDI %s' % vdi, e['attach_info'])
            entries.append((sr, vdi, e))
    return entries


def dp_claimants(entries):
    out = {}
    for sr, vdi, e in entries:
        for dp, st in e.get('dps', {}).items():
            out.setdefault(dp, []).append((sr, vdi, list(st)))
    return out


DOM0_DP_RE = re.compile(r'^vbd/0/(xvd[a-z]{1,2})$')
GUEST_DP_RE = re.compile(r'^vbd/([0-9]+)/([A-Za-z0-9]+)$')


class TapctlError(Exception):
    pass


def parse_tapctl(text):
    rows = []
    for line in text.splitlines():
        if not line.strip():
            continue
        head, sep, args = line.partition(' args=')
        fields = {}
        for tok in head.split():
            k, eq, v = tok.partition('=')
            if not eq or k not in ('pid', 'minor', 'state') or k in fields:
                raise TapctlError('cannot read the tap-ctl line: %s' % line)
            fields[k] = v
        if 'pid' not in fields and 'minor' not in fields:
            raise TapctlError('cannot read the tap-ctl line: %s' % line)
        row = {'raw': line}
        for k in ('pid', 'minor'):
            v = fields.get(k, '-')
            if v == '-':
                row[k] = None
            elif v.isdigit():
                row[k] = int(v)
            else:
                raise TapctlError('cannot read %s in the tap-ctl line: %s' % (k, line))
        sv = fields.get('state', '-')
        if sv == '-':
            row['state'] = None
        else:
            try:
                row['state'] = int(sv, 16) if sv.lower().startswith('0x') else int(sv)
            except ValueError:
                raise TapctlError('cannot read state in the tap-ctl line: %s' % line)
        row['type'] = None
        row['path'] = None
        if sep:
            typ, colon, path = args.partition(':')
            if colon:
                row['type'] = typ
                row['path'] = path
            elif args.strip() not in ('', '-'):
                raise TapctlError('cannot read args in the tap-ctl line: %s' % line)
        rows.append(row)
    return rows


XS_LINE = re.compile(r'^(/\S+) = "(.*)"$')


def parse_xenstore(text):
    out = {}
    for line in text.splitlines():
        if not line.strip():
            continue
        m = XS_LINE.match(line)
        if m:
            out[m.group(1)] = m.group(2)
        elif ' = ' in line and line.startswith('/'):
            k, _, v = line.partition(' = ')
            out[k] = v.strip('"')
        else:
            raise ValueError('cannot read the xenstore line: %s' % line[:200])
    return out


def parse_proc_locks(text):
    out = []
    for line in text.splitlines():
        parts = line.split()
        if '->' in parts:
            continue
        try:
            i = parts.index('ADVISORY') if 'ADVISORY' in parts else parts.index('MANDATORY')
        except ValueError:
            continue
        try:
            kind, mode, pid, devino = parts[i - 1], parts[i + 1], int(parts[i + 2]), parts[i + 3]
            maj, mn, ino = devino.split(':')
            out.append({'kind': kind, 'mode': mode, 'pid': pid, 'dev': [int(maj, 16), int(mn, 16)],
                        'ino': int(ino)})
        except (IndexError, ValueError):
            raise ValueError('cannot read the /proc/locks line: %s' % line)
    return out


DIAG_DP = re.compile(r'^DP: (.+): (attached  R[OW]|activated R[OW]|detached)(  \*\* LEAKED)?$')


def parse_sm_diagnostics(text):
    out = set()
    sr = vdi = None
    seen_header = False
    for raw in text.splitlines():
        line = raw.strip()
        if line == 'The following SRs are attached:':
            seen_header = True
            continue
        if not seen_header:
            continue
        if line.startswith('The following errors have been logged') or line.startswith('No errors have been logged'):
            break
        if raw.startswith('    SR ') and not raw.startswith('     '):
            sr, vdi = line[3:], None
        elif raw.startswith('        VDI ') and not raw.startswith('         '):
            vdi = raw[len('        VDI '):]
        else:
            m = DIAG_DP.match(line)
            if m and sr is not None and vdi is not None:
                out.add((sr, vdi, m.group(1)))
    if not seen_header:
        raise ValueError('no "The following SRs are attached:" line in the diagnostics')
    return out


def file_dp_set(obj):
    out = set()
    for sr, vdi, e in check_storage_db(obj):
        for dp in e.get('dps', {}):
            out.add((sr, vdi, dp))
    return out


SYSLOG_TS = re.compile(r'^([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d\d):(\d\d):(\d\d)\s')


def log_lines_since(path, since, now=None, must=None):
    return log_lines_covered(path, since, now, must)[0]


def log_lines_covered(path, since, now=None, must=None):
    now = time.time() if now is None else now
    files = [path]
    try:
        first = first_line_time(path, now)
        if first is None or first > since:
            files.insert(0, path + '.1')
    except EnvironmentError:
        files.insert(0, path + '.1')
    out = []
    read = []
    for p in files:
        try:
            h = open(p, 'rb')
        except EnvironmentError:
            continue
        read.append(p)
        ref = file_ref_time(p, now)
        with h:
            for raw in h:
                if must is not None and must not in raw:
                    continue
                line = raw.decode('utf-8', 'replace').rstrip('\n')
                m = SYSLOG_TS.match(line)
                if not m:
                    continue
                t = syslog_epoch(*(m.groups() + (ref,)))
                if t is not None and t >= since:
                    out.append(line)
    if not read:
        raise Failed('%s cannot be read' % path)
    try:
        start = first_line_time(read[0], now)
    except EnvironmentError:
        start = None
    return out, start is not None and start <= since


def first_line_time(path, now):
    with open(path, 'rb') as h:
        first = h.readline().decode('utf-8', 'replace')
    m = SYSLOG_TS.match(first)
    return syslog_epoch(*(m.groups() + (file_ref_time(path, now),))) if m else None


def parse_local_db(data):
    found = {}
    parser = xml.parsers.expat.ParserCreate()

    def on_start(name, attrs):
        if name == 'row' and 'key' in attrs:
            found[attrs['key']] = attrs.get('value')
    parser.StartElementHandler = on_start
    try:
        parser.Parse(data, True)
    except xml.parsers.expat.ExpatError as exc:
        raise ValueError('%s cannot be read as XML: %s' % (LOCAL_DB, _text(exc)))
    return found


def parse_net_tcp(text, port):
    out = []
    for line in text.splitlines()[1:]:
        parts = line.split()
        if len(parts) < 4:
            continue
        local, remote, st = parts[1], parts[2], parts[3]
        try:
            lport = int(local.rsplit(':', 1)[1], 16)
        except (IndexError, ValueError):
            raise ValueError('cannot read the tcp line: %s' % line)
        if st == '01' and lport == port:
            out.append({'local': local, 'remote': remote})
    return out


MONTHS = {'Jan': 1, 'Feb': 2, 'Mar': 3, 'Apr': 4, 'May': 5, 'Jun': 6, 'Jul': 7, 'Aug': 8,
          'Sep': 9, 'Oct': 10, 'Nov': 11, 'Dec': 12}
SMLOG_RE = re.compile(r'^([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d\d):(\d\d):(\d\d)\s+\S+\s+([A-Za-z0-9_.-]+):\s+'
                      r'\[(\d+)\](?:\[[^\]]*\])?\s?(.*)$')


def syslog_epoch(mon, day, hh, mm, ss, now):
    year = time.localtime(now).tm_year
    for y in (year, year - 1):
        try:
            t = time.mktime((y, MONTHS[mon], int(day), int(hh), int(mm), int(ss), 0, 0, -1))
        except (OverflowError, ValueError, KeyError):
            return None
        if t <= now + 86400:
            return t
    return None


def parse_smlog_line(line, now):
    m = SMLOG_RE.match(line)
    if not m:
        return None
    t = syslog_epoch(m.group(1), m.group(2), m.group(3), m.group(4), m.group(5), now)
    if t is None:
        return None
    return (t, m.group(6), int(m.group(7)), m.group(8))


RENDER = r'\*?([0-9a-f]{8})(?:\[|\()'
RE_SET_RELINK = re.compile(r'Set relinking = True for ' + RENDER)
RE_DEL_RELINK = re.compile(r'Removed relinking from ' + RENDER)
RE_RELINKING = re.compile(r'^\s*Relinking ' + RENDER)
RE_IPC = re.compile(r'IPCFlag: (set|clear) (' + UUID_PAT + r'):([A-Za-z0-9_]+)')
RE_SR_ABORT = re.compile(r'=== SR (' + UUID_PAT + r'): abort ===')
RE_GC_LOCK = re.compile(r'/var/lock/sm/(' + UUID_PAT + r')/(gc_active|running)\b')
RE_SR_ERROR = re.compile(r'\* \* \* \* \* SR (' + UUID_PAT + r'): ERROR')
RE_ACTIVATE = re.compile(r"'command': 'vdi_activate'")
RE_VDI_UUID = re.compile(r"'vdi_uuid': '(" + UUID_PAT + r")'")
RE_REFUSAL = re.compile(r'not detached cleanly|is still open on host')
RE_PAUSE = re.compile(r'^(Pause|Unpause) for (' + UUID_PAT + r')\s*$')
RE_PAUSE_REQ = re.compile(r'^(Pause|Unpause) request for (' + UUID_PAT + r')(?:\s|$)')
RE_LOCK_WAIT = re.compile(r'Failed to lock (\S+) on first attempt, blocked by PID (\d+)')
RE_PHY = re.compile(r'phy/(' + UUID_PAT + r')/(' + UUID_PAT + r')\b.*?(xcp-volume-' + UUID_PAT + r')')
RE_PHY_UPDATE = re.compile(r'Update LINSTOR PhyLink \(previous=.*?, current=.*?(xcp-volume-' + UUID_PAT + r')')
RE_NO_TAPDISK = re.compile(r'tap\.deactivate: Warning, No such Tapdisk\(minor=(\d+)')
RE_FAILED_TAG = re.compile(r'Failed to tag vdi ' + RENDER)
SMLOG_PREFILTER = re.compile(br'relinking|Relinking|IPCFlag|: abort ===|/gc_active|/running|SMGC|'
                             br'vdi_activate|not detached cleanly|is still open on host|ause for |'
                             br'ause request for |Failed to lock|xcp-volume-|No such Tapdisk|Failed to tag|: ERROR')


def lsof_bug_probe(src):
    tree = ast.parse(src)
    found = None
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == 'get_pid_for_path':
            found = node
            break
    if found is None:
        return False
    for node in ast.walk(found):
        s = _ast_str(node)
        if isinstance(s, str) and s.endswith('/lsof'):
            return True
    return False


def _ast_str(node):
    if hasattr(ast, 'Constant') and isinstance(node, getattr(ast, 'Constant')):
        return node.value if isinstance(node.value, str) else None
    if hasattr(ast, 'Str') and isinstance(node, getattr(ast, 'Str')):
        return node.s
    return None


def add_tag_probe(src):
    found = None
    for node in ast.walk(ast.parse(src)):
        if isinstance(node, ast.FunctionDef) and node.name == '_add_tag':
            found = node
            break
    out = {'found': found is not None, 'relinking': False, 'paused': False, 'activating': False}
    if found is None:
        return out
    for node in ast.walk(found):
        if isinstance(node, ast.Compare) and len(node.ops) == 1 and isinstance(node.ops[0], ast.In):
            s = _ast_str(node.left)
            if s in ('relinking', 'paused'):
                out[s] = True
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and \
                node.func.attr == 'add_to_sm_config':
            if any(_ast_str(arg) == 'activating' for arg in node.args):
                out['activating'] = True
    return out


def tap_state_text(state):
    if state is None:
        return u'-'
    return u'%#x' % state


TAP_BITS = ((0x1, 'DEAD'), (0x2, 'CLOSED'), (0x4, 'QUIESCE_REQUESTED'), (0x8, 'QUIESCED'), (0x10, 'PAUSE_REQUESTED'),
            (0x20, 'PAUSED'), (0x40, 'SHUTDOWN_REQUESTED'), (0x80, 'LOCKING'), (0x100, 'LOG_DROPPED'),
            (0x200, 'RESUME_FAILED'))


def tap_state_names(state):
    names = [n for b, n in TAP_BITS if state & b]
    rest = state & ~sum(b for b, n in TAP_BITS)
    return ', '.join(names + (['%#x' % rest] if rest else [])) or 'running'


MARK_BEGIN = '<<<SSF-AGENT-BEGIN>>>'
MARK_END = '<<<SSF-AGENT-END>>>'
BOOT = ('import sys,base64,json;d=sys.stdin.buffer.read();r,s=d.split(b"\\n",1);'
        'g={"__name__":"ssf_agent","SSF_SOURCE":s,"SSF_REQUEST":r};'
        'exec(compile(s,"storage-state-fixer","exec"),g)')
WATCH_COMMS = ('vhd-tool', 'sparse_dd', 'xapi-nbd', 'qemu-img', 'qemu-nbd', 'xhad', 'xapi', 'lsof',
               'vhd-util', 'tap-ctl')
SM_PREFIXES = (SM_DIR + '/', PLUGIN_DIR + '/')
TERMINAL = ('done', 'refused', 'rolled-back', 'failed')
ACT_ENDS = TERMINAL + ('unverified',)
PATH_KEYS = ('STORAGE_DB', 'STORAGE_DPS', 'SM_BACKEND', 'SM_PHY', 'BLKTAP_DIR', 'SYS_BLKTAP', 'SYS_DEV_BLOCK',
             'SYS_BLOCK', 'XENSOURCE_LOG', 'VHD_UTIL', 'IPC_DIR', 'SM_REFCOUNT', 'SR_MOUNT', 'DRBD_BY_RES', 'NBD_VBDS',
             'XENSTORE_LIST', 'XENSTORE_READ', 'VGS', 'PVS', 'SS', 'SM_LOCK_DIR', 'SMLOG', 'LOCAL_DB', 'INVENTORY',
             'POOL_CONF', 'STATIC_VDIS',
             'STARTUP_COOKIE', 'INIT_COOKIE', 'TOOLSTACK_LOCK', 'TOOLSTACK_SCRIPT', 'SM_DIR', 'PLUGIN_DIR',
             'PROC', 'XE', 'SYSTEMCTL', 'TAPCTL', 'XENSTORE_LS', 'DRBDSETUP', 'RPM', 'LVS', 'DMSETUP',
             'RUN_ROOT', 'POLL', 'STOP_TIMEOUT', 'GONE_WAIT', 'START_TIMEOUT', 'READY_WAIT', 'ANSWER_WAIT',
             'INIT_WAIT', 'GUARDIAN_POLL', 'GUARDIAN_BACKSTOP', 'GUARDIAN_STALL', 'GUARD_LOCK_WAIT', 'XHAD_GONE_WAIT',
             'API_TIMEOUT', 'QUIET_WAIT', 'XAPI_LOCAL', 'ENSURE_TIMEOUT', 'ENSURE_MARGIN', 'FENCE_HOLD',
             'FENCE_ACQUIRE', 'FENCE_POLL')
XAPI_LOCAL = None


def apply_paths(paths):
    if not paths:
        return
    g = globals()
    for k, v in paths.items():
        if k in PATH_KEYS:
            g[k] = v
    global SM_PREFIXES
    SM_PREFIXES = (g['SM_DIR'] + '/', g['PLUGIN_DIR'] + '/')


def fact(fn, *args):
    try:
        return {'ok': True, 'value': fn(*args)}
    except Exception as exc:
        return {'ok': False, 'error': u'%s: %s' % (exc.__class__.__name__, _text(exc))}


def f_identity():
    inv = parse_inventory(read_text(INVENTORY))
    try:
        boot_id = read_text(PROC + '/sys/kernel/random/boot_id').strip()
    except EnvironmentError:
        boot_id = None
    try:
        role = read_text(POOL_CONF).strip()
    except EnvironmentError as exc:
        role = None
        if exc.errno != errno.ENOENT:
            raise
    return {'hostname': socket.gethostname(), 'uuid': inv.get('INSTALLATION_UUID'),
            'product_version': inv.get('PRODUCT_VERSION'), 'dom0': inv.get('CONTROL_DOMAIN_UUID'),
            'time': time.time(), 'btime': boot_time(), 'boot_id': boot_id, 'pool_conf': role}


def f_storage_db():
    data = read_file(STORAGE_DB)
    st = os.stat(STORAGE_DB)
    out = {'sha256': sha256_bytes(data), 'size': len(data), 'mtime': st.st_mtime, 'ino': st.st_ino,
           'obj': None, 'schema_error': None}
    try:
        obj = json.loads(data.decode('utf-8'))
    except ValueError as exc:
        out['schema_error'] = u'not valid JSON: %s' % _text(exc)
        return out
    out['obj'] = obj
    try:
        check_storage_db(obj)
    except SchemaError as exc:
        out['schema_error'] = _text(exc)
    return out


def f_storage_dps():
    out = {}
    try:
        names = sorted(os.listdir(STORAGE_DPS))
    except OSError as exc:
        if exc.errno == errno.ENOENT:
            return out
        raise
    for name in names:
        p = os.path.join(STORAGE_DPS, name)
        try:
            data = read_file(p)
            st = os.stat(p)
        except EnvironmentError as exc:
            if exc.errno == errno.ENOENT:
                continue
            raise
        try:
            content = json.loads(data.decode('utf-8'))
        except ValueError:
            content = None
        out[name] = {'content': content, 'raw': _text(data[:400]), 'mtime': st.st_mtime}
    return out


def f_tapdisks():
    r = run([TAPCTL, 'list'], 20)
    if r.timed_out:
        raise Failed('tap-ctl list timed out after 20s: a tapdisk is not answering its control socket')
    if r.rc != 0:
        raise Failed('tap-ctl list %s' % r.why())
    return parse_tapctl(r.out)


def _listdir(path):
    try:
        return sorted(os.listdir(path))
    except OSError as exc:
        if exc.errno == errno.ENOENT:
            return []
        raise


def f_backend():
    out = []
    for sr in _listdir(SM_BACKEND):
        d = os.path.join(SM_BACKEND, sr)
        if not os.path.isdir(d):
            continue
        for name in _listdir(d):
            p = os.path.join(d, name)
            try:
                st = os.lstat(p)
                rec = {'sr': sr, 'name': name, 'mtime': st.st_mtime, 'size': st.st_size, 'ino': st.st_ino}
                if name.endswith('.attach_info'):
                    rec['kind'] = 'attach_info'
                    rec['vdi'] = name[:-len('.attach_info')]
                else:
                    rec['vdi'] = name
                    if stat.S_ISBLK(st.st_mode):
                        rec['kind'] = 'block'
                        rec['rdev'] = [os.major(st.st_rdev), os.minor(st.st_rdev)]
                    elif stat.S_ISLNK(st.st_mode):
                        rec['kind'] = 'link'
                        rec['target'] = os.readlink(p)
                    elif stat.S_ISREG(st.st_mode) and st.st_size < 4096 and \
                            read_file(p).startswith(INERT_MARK):
                        rec['kind'] = 'inert'
                    else:
                        rec['kind'] = 'other'
            except EnvironmentError as exc:
                if gone(exc):
                    continue
                raise
            out.append(rec)
    return out


def f_phy():
    out = []
    for sr in _listdir(SM_PHY):
        d = os.path.join(SM_PHY, sr)
        if not os.path.isdir(d):
            continue
        for name in _listdir(d):
            p = os.path.join(d, name)
            rec = {'sr': sr, 'vdi': name}
            try:
                rec['target'] = os.readlink(p)
            except OSError as exc:
                if gone(exc):
                    continue
                if exc.errno != errno.EINVAL:
                    raise
                rec['target'] = None
                rec['kind'] = 'not-a-link'
                out.append(rec)
                continue
            if rec['target'].startswith('/dev/'):
                try:
                    st = os.stat(p)
                    if stat.S_ISBLK(st.st_mode):
                        rec['kind'] = 'block'
                        rec['rdev'] = [os.major(st.st_rdev), os.minor(st.st_rdev)]
                    else:
                        rec['kind'] = 'dev-other'
                except OSError as exc:
                    if exc.errno not in (errno.ENOENT, errno.ENOTDIR):
                        raise
                    rec['kind'] = 'dangling'
            else:
                rec['kind'] = 'file'
            out.append(rec)
    return out


def proc_devices():
    out = {}
    section = None
    for line in read_text(PROC + '/devices').splitlines():
        if line.startswith('Character devices'):
            section = 'c'
        elif line.startswith('Block devices'):
            section = 'b'
        else:
            parts = line.split()
            if len(parts) == 2 and parts[0].isdigit() and section:
                out[(section, parts[1])] = int(parts[0])
    return out


def f_blktap():
    devs = proc_devices()
    out = {'blktap': {}, 'tapdev': {}, 'other': [],
           'majors': {'tapdev': devs.get(('b', 'tapdev')), 'blktap': devs.get(('c', 'blktap2')) or devs.get(('c', 'blktap'))}}
    for name in _listdir(BLKTAP_DIR):
        p = os.path.join(BLKTAP_DIR, name)
        try:
            st = os.lstat(p)
        except OSError as exc:
            if gone(exc):
                continue
            raise
        m = re.match(r'^(blktap|tapdev)(\d+)$', name)
        if not m:
            out['other'].append(name)
            continue
        kind = 'char' if stat.S_ISCHR(st.st_mode) else 'block' if stat.S_ISBLK(st.st_mode) else 'other'
        out[m.group(1)][m.group(2)] = {'kind': kind, 'rdev': [os.major(st.st_rdev), os.minor(st.st_rdev)],
                                       'mtime': st.st_mtime}
    return out


def f_sys_minors():
    if not os.path.isdir(SYS_BLKTAP):
        raise Failed('%s is not a directory' % SYS_BLKTAP)
    out = []
    for name in _listdir(SYS_BLKTAP):
        m = re.match(r'^blktap!blktap(\d+)$', name)
        if m:
            out.append(int(m.group(1)))
    return sorted(out)


def f_xenstore():
    r = run([XENSTORE_LS, '-f', '/local/domain/0/backend'], 20)
    if not r.ok:
        raise Failed('xenstore-ls %s' % r.why())
    allv = parse_xenstore(r.out)
    return dict((k, v) for k, v in allv.items() if k.endswith('/physical-device') or k.endswith('/params'))


def is_sm_argv(argv):
    if not argv:
        return False
    if argv[0].startswith(SM_PREFIXES):
        return True
    base = os.path.basename(argv[0])
    if base.startswith('python') and len(argv) > 1:
        i = 1
        while i < len(argv) and argv[i].startswith('-') and argv[i] not in ('-c', '-m'):
            i += 1
        if i < len(argv) and argv[i].startswith(SM_PREFIXES):
            return True
    return False


def f_procs():
    btime = boot_time()
    out = []
    for pid in pids():
        if pid == os.getpid():
            continue
        try:
            argv = proc_cmdline(pid)
            st = proc_stat(pid)
        except EnvironmentError as exc:
            if exc.errno in (errno.ENOENT, errno.ESRCH):
                continue
            raise
        comm = st['comm']
        sm = is_sm_argv(argv)
        if not (sm or comm in WATCH_COMMS or comm == 'tapdisk'):
            continue
        rec = {'pid': pid, 'comm': comm, 'state': st['state'], 'ticks': st['ticks'],
               'start': btime + st['start_ticks'] / float(clk_tck()), 'sm': sm}
        if comm != 'tapdisk':
            rec['argv'] = [a[:300] for a in argv[:24]]
            rec['io'] = proc_io(pid)
        out.append(rec)
    return out


def sm_lock_files():
    out = {}
    for d in _listdir(SM_LOCK_DIR):
        p = os.path.join(SM_LOCK_DIR, d)
        try:
            st = os.lstat(p)
        except OSError as exc:
            if gone(exc):
                continue
            raise
        if stat.S_ISDIR(st.st_mode):
            for name in _listdir(p):
                q = os.path.join(p, name)
                try:
                    sq = os.lstat(q)
                except OSError as exc:
                    if gone(exc):
                        continue
                    raise
                out[(os.major(sq.st_dev), os.minor(sq.st_dev), sq.st_ino)] = q
        else:
            out[(os.major(st.st_dev), os.minor(st.st_dev), st.st_ino)] = p
    return out


def f_locks():
    files = sm_lock_files()
    try:
        st = os.stat(SM_LOCK_DIR)
        ldev = [os.major(st.st_dev), os.minor(st.st_dev)]
    except OSError:
        ldev = None
    held = []
    for l in parse_proc_locks(read_text(PROC + '/locks')):
        key = (l['dev'][0], l['dev'][1], l['ino'])
        if key in files:
            held.append({'path': files[key], 'pid': l['pid'], 'kind': l['kind'], 'mode': l['mode']})
        elif ldev is not None and l['dev'] == ldev and l['pid'] > 0 and pid_info(l['pid']).get('sm'):
            held.append({'path': None, 'pid': l['pid'], 'kind': l['kind'], 'mode': l['mode'], 'ino': l['ino']})
    return held


def f_ipc():
    out = []
    for sr in _listdir(IPC_DIR):
        d = os.path.join(IPC_DIR, sr)
        if not os.path.isdir(d):
            continue
        for name in _listdir(d):
            p = os.path.join(d, name)
            try:
                st = os.lstat(p)
                with open(p, 'rb') as h:
                    content = h.read(64)
            except EnvironmentError as exc:
                if exc.errno == errno.ENOENT:
                    continue
                raise
            rec = {'sr': sr, 'name': name, 'content': _text(content), 'mtime': st.st_mtime,
                   'ino': st.st_ino, 'size': st.st_size, 'writer': None}
            m = re.match(r'^\s*(\d+)\s*$', rec['content'])
            if m:
                rec['writer'] = pid_info(int(m.group(1)))
            out.append(rec)
    return out


def pid_info(pid):
    try:
        st = proc_stat(pid)
        argv = proc_cmdline(pid)
    except EnvironmentError as exc:
        if exc.errno in (errno.ENOENT, errno.ESRCH):
            return {'pid': pid, 'alive': False}
        raise
    if st['state'] == 'Z':
        return {'pid': pid, 'alive': False}
    return {'pid': pid, 'alive': True, 'start': boot_time() + st['start_ticks'] / float(clk_tck()),
            'argv': [a[:200] for a in argv[:8]], 'sm': is_sm_argv(argv) or any('cleanup.py' in a for a in argv)}


def f_pids(want):
    return dict((str(p), pid_info(int(p))) for p in want or [])


def f_statfiles(paths):
    out = {}
    for p in paths or []:
        r = run(['stat', '-c', '%s %Y', p], 10, env=dict(os.environ, LC_ALL='C'))
        if r.timed_out:
            out[p] = {'ok': False, 'error': 'stat timed out'}
        elif r.rc != 0 and 'No such file or directory' in r.err:
            out[p] = {'ok': True, 'value': {'exists': False, 'detail': r.why()}}
        elif r.rc != 0:
            out[p] = {'ok': False, 'error': 'stat %s' % r.why()}
        else:
            out[p] = {'ok': True, 'value': {'exists': True, 'detail': r.out.strip()}}
    return out


def f_lvnames(vgs):
    out = {}
    for vg in vgs or []:
        if not re.match(r'^VG_XenStorage-' + UUID_PAT + '$', vg):
            continue
        r = run([LVS, '--noheadings', '-o', 'lv_name,lv_attr', vg], 60)
        if not r.ok:
            out[vg] = {'ok': False, 'error': 'lvs %s' % r.why()}
            continue
        rows = []
        for line in r.out.splitlines():
            parts = line.split()
            if len(parts) >= 2:
                rows.append([parts[0], parts[1]])
        if not rows:
            out[vg] = {'ok': False, 'error': 'lvs listed no volumes'}
        else:
            out[vg] = {'ok': True, 'value': rows}
    return out


def f_srdir(srs):
    out = {}
    for sr in srs or []:
        if not UUID_RE.match(sr):
            continue
        r = run(['ls', '-1a', '/var/run/sr-mount/' + sr], 20)
        if not r.ok:
            out[sr] = {'ok': False, 'error': 'ls %s' % r.why()}
        else:
            out[sr] = {'ok': True, 'value': [l for l in r.out.splitlines() if l not in ('.', '..')]}
    return out


def f_xsread(paths):
    out = {}
    for p in paths or []:
        if not re.match(r'^/local/domain/\d+/control/shutdown$', p):
            continue
        r = run([XENSTORE_READ, p], 10)
        if r.ok:
            out[p] = {'ok': True, 'value': {'present': True, 'value': r.out.strip()}}
        elif not r.timed_out and r.rc == 1 and "couldn't read path" in (r.err + r.out):
            out[p] = {'ok': True, 'value': {'present': False}}
        else:
            out[p] = {'ok': False, 'error': 'xenstore-read %s' % r.why()}
    return out


def f_vhdcheck(paths):
    out = {}
    for p in paths or []:
        if not (p.startswith('/dev/VG_XenStorage-') or p.startswith('/var/run/sr-mount/') or
                p.startswith('/run/sr-mount/')):
            out[p] = {'ok': False, 'detail': 'not an SR image path'}
            continue
        r = run([VHD_UTIL, 'check', '--debug', '-p', '-n', p], 120)
        lines = [l.strip() for l in (r.out + u'\n' + r.err).splitlines() if l.strip()]
        rec = {'ok': r.ok, 'detail': ('; '.join(lines[-3:]) or r.why())[:400]}
        q = run([VHD_UTIL, 'query', '--debug', '-n', p, '-p', '-u'], 60)
        text = q.out.strip()
        last = text.splitlines()[-1] if text else ''
        names = re.findall(UUID_PAT, os.path.basename(last))
        if not q.ok:
            rec['parent_error'] = 'vhd-util query -p %s' % q.why()
        elif last.endswith(' has no parent'):
            rec['parent'] = ''
        elif len(names) == 1:
            rec['parent'] = names[0]
            rec['parent_raw'] = last[:300]
        else:
            rec['parent_error'] = 'the parent cannot be named from %s' % canon(last[:200])
        out[p] = rec
    return out


def dm_vs_lvm(vg, lv):
    name = '%s-%s' % (vg.replace('-', '--'), lv.replace('-', '--'))
    r = run([DMSETUP, 'table', name], 20)
    if not r.ok:
        raise Failed('dmsetup table %s %s' % (name, r.why()))
    dm = []
    for line in r.out.splitlines():
        p = line.split()
        if len(p) == 5 and p[2] == 'linear' and p[0].isdigit() and p[1].isdigit() and p[4].isdigit():
            dm.append([int(p[0]), int(p[1]), 'linear', p[3], int(p[4])])
        elif line.strip():
            dm.append(['?', line.strip()[:200]])
    units = ['--noheadings', '--units', 's', '--nosuffix']
    r = run([LVS] + units + ['--segments', '-o', 'seg_start,seg_size,segtype,seg_pe_ranges', vg + '/' + lv], 60)
    if not r.ok:
        raise Failed('lvs %s' % r.why())
    segs = [l.split() for l in r.out.splitlines() if l.strip()]
    r = run([VGS] + units + ['-o', 'vg_extent_size', vg], 60)
    if not r.ok or not r.out.strip().isdigit():
        raise Failed('vgs %s' % r.why())
    extent = int(r.out.strip())
    r = run([PVS] + units + ['-o', 'pv_name,vg_name,pe_start'], 60)
    if not r.ok:
        raise Failed('pvs %s' % r.why())
    starts = {}
    for l in r.out.splitlines():
        p = l.split()
        if len(p) == 3 and p[1] == vg and p[2].isdigit():
            starts[p[0]] = int(p[2])
    lvm = []
    for s in segs:
        m = re.match(r'^(.+):(\d+)-(\d+)$', s[3]) if len(s) == 4 else None
        if not (m and s[0].isdigit() and s[1].isdigit() and m.group(1) in starts):
            lvm.append(['?', ' '.join(s)[:200]])
            continue
        st = os.stat(m.group(1))
        dev = '%d:%d' % (os.major(st.st_rdev), os.minor(st.st_rdev))
        lvm.append([int(s[0]), int(s[1]), s[2], dev, starts[m.group(1)] + int(m.group(2)) * extent])
    return {'dm': dm, 'lvm': lvm, 'match': bool(dm) and dm == lvm}


def f_dmcheck(items):
    out = {}
    for vg, lv in items or []:
        if not re.match(r'^VG_XenStorage-' + UUID_PAT + '$', vg) or not re.match(r'^(VHD|LV)-' + UUID_PAT + '$', lv):
            continue
        out[vg + '/' + lv] = fact(dm_vs_lvm, vg, lv)
    return out


def f_nbd():
    out = []
    read_any = False
    for name in ('tcp', 'tcp6'):
        p = PROC + '/net/' + name
        if not os.path.exists(p):
            continue
        out.extend(parse_net_tcp(read_text(p), NBD_PORT))
        read_any = True
    if not read_any:
        raise Failed('neither %s/net/tcp nor %s/net/tcp6 exists' % (PROC, PROC))
    return out


def f_nbd_vbds():
    try:
        data = read_text(NBD_VBDS)
    except EnvironmentError as exc:
        if exc.errno == errno.ENOENT:
            return []
        raise
    return [l.strip() for l in data.splitlines() if l.strip()]


def f_smrefs():
    out = {}
    for ns in _listdir(SM_REFCOUNT):
        d = os.path.join(SM_REFCOUNT, ns)
        if not os.path.isdir(d):
            continue
        objs = {}
        for name in _listdir(d):
            try:
                objs[name] = read_text(os.path.join(d, name)).strip()[:40]
            except EnvironmentError as exc:
                if exc.errno != errno.ENOENT:
                    raise
        out[ns] = objs
    return out


def f_domains():
    r = run([XENSTORE_LIST, '/local/domain'], 20)
    if not r.ok:
        raise Failed('xenstore-list /local/domain %s' % r.why())
    out = r.out.split()
    for d in out:
        if not d.isdigit():
            raise Failed('xenstore-list /local/domain answered %s' % canon(d[:40]))
    if '0' not in out:
        raise Failed('xenstore-list /local/domain does not list domain 0')
    return out


CTL_LINE = re.compile(r'^u_str\s*LISTEN\s+(\d+)\s+(\d+)\s+(\S+)')
CTL_PATH = re.compile(r'^(?:/var)?/run/blktap-control/ctl(\d+)$')


def f_ctl_backlog(tap_pids=None):
    r = run([SS, '-xlpn'], 20)
    if not r.ok:
        raise Failed('ss -xlpn %s' % r.why())
    out = {}
    for line in r.out.splitlines():
        m = CTL_LINE.match(line)
        if not m:
            continue
        p = CTL_PATH.match(m.group(3))
        if p:
            out[p.group(1)] = int(m.group(1))
    missing = [p for p in tap_pids or [] if str(p) not in out and pid_alive(p)]
    if missing:
        raise Failed('ss -xlpn lists no control socket for tapdisk pid %s, so whether connections wait on it is not '
                     'established' % ', '.join(str(p) for p in missing[:4]))
    return out


def f_room():
    p = RUN_ROOT
    while not os.path.isdir(p):
        parent = os.path.dirname(p)
        if parent == p:
            break
        p = parent
    st = os.statvfs(p)
    return {'path': p, 'free': st.f_bavail * st.f_frsize}


def f_blockmap():
    dm = {}
    for name in _listdir(SYS_BLOCK):
        if not name.startswith('dm-'):
            continue
        base = os.path.join(SYS_BLOCK, name)
        try:
            dmname = read_text(os.path.join(base, 'dm', 'name')).strip()
            dev = _sys_dev(os.path.join(base, 'dev'))
        except EnvironmentError as exc:
            if gone(exc) and not os.path.lexists(base):
                continue
            raise Failed('device-mapper device %s cannot be read, so the active LVs are not all known: %s'
                         % (name, _text(exc)))
        if dev is None:
            if not os.path.lexists(base):
                continue
            raise Failed('device-mapper device %s (%s) has no device number, so the active LVs are not all known'
                         % (name, dmname))
        if not dmname:
            raise Failed('device-mapper device %s has an empty name' % name)
        dm[dmname] = dev
    drbd = {}
    for res in _listdir(DRBD_BY_RES):
        try:
            st = os.stat(os.path.join(DRBD_BY_RES, res, '0'))
        except OSError as exc:
            if exc.errno in (errno.ENOENT, errno.ENOTDIR):
                continue
            raise
        if stat.S_ISBLK(st.st_mode):
            drbd[res] = '%d:%d' % (os.major(st.st_rdev), os.minor(st.st_rdev))
    devs = proc_devices()
    majors = sorted(v for (sec, name), v in devs.items() if sec == 'b' and name in ('device-mapper', 'drbd'))
    return {'dm': dm, 'drbd': drbd, 'majors': majors}


def local_armed():
    data = read_file(LOCAL_DB)
    rows = parse_local_db(data)
    v = rows.get('ha.armed')
    return 'absent' if v is None else _text(v)


def f_ha():
    return {'armed': local_armed(), 'xhad': pids_named(b'xhad')}


def f_cookies():
    out = {}
    for k, p in (('startup', STARTUP_COOKIE), ('init', INIT_COOKIE)):
        try:
            out[k] = os.stat(p).st_mtime
        except OSError:
            out[k] = None
    return out


def f_xapi_state():
    r = systemctl('is-active', XAPI_UNIT)
    xp = pids_named(b'xapi')
    start = exe = None
    if len(xp) == 1:
        try:
            start = proc_start(xp[0], boot_time())
        except (EnvironmentError, ValueError, IndexError):
            start = None
        try:
            exe = os.readlink('%s/%d/exe' % (PROC, xp[0]))
        except OSError:
            exe = None
    return {'unit': r.out.strip() or 'unknown', 'pids': xp, 'start': start, 'exe': exe}


def xapi_ready(xapi, cookies):
    if not xapi or not cookies or xapi.get('unit') != 'active' or len(xapi.get('pids') or []) != 1:
        return False
    start = xapi.get('start')
    if start is None:
        return False
    return all(cookies.get(k) is not None and cookies[k] >= start - 2 for k in ('startup', 'init'))


def f_static_vdis():
    out = []
    for d in _listdir(STATIC_VDIS):
        entry = os.path.join(STATIC_VDIS, d)
        for tries in range(3):
            try:
                out.append(read_text(os.path.join(entry, 'vdi-uuid')).strip())
                break
            except EnvironmentError as exc:
                if exc.errno in (errno.ENOENT, errno.ENOTDIR) and not os.path.isdir(entry):
                    break
                if exc.errno != errno.ENOENT or tries == 2:
                    raise
                time.sleep(1)
    return out


def f_units(srs):
    if not srs:
        return {}
    units = [unit_name(sr) for sr in srs]
    r = run([SYSTEMCTL, 'is-active'] + units, SYSTEMCTL_TIMEOUT)
    if r.timed_out or r.rc not in (0, 3):
        raise Failed('systemctl is-active %s' % r.why())
    lines = r.out.splitlines()
    if len(lines) != len(units):
        raise Failed('systemctl is-active answered %d lines for %d units' % (len(lines), len(units)))
    return dict((sr, lines[i].strip()) for i, sr in enumerate(srs))


def lv_dm_names(sr, vdi):
    vg = ('VG_XenStorage-' + sr).replace('-', '--')
    return ['%s-%s' % (vg, (p + vdi).replace('-', '--')) for p in ('VHD-', 'LV-', 'QCOW2-')]


def image_paths(sr, vdi):
    out = set()
    for ext in ('vhd', 'qcow2', 'raw'):
        out |= path_variants('%s/%s/%s.%s' % (SR_MOUNT, sr, vdi, ext))
    return out


def path_variants(path):
    out = set([path])
    if path.startswith('/var/run/'):
        out.add(path[len('/var'):])
    elif path.startswith('/run/'):
        out.add('/var' + path)
    return out


def interest_set(backend, phy, blktap):
    rdevs = collections.defaultdict(list)
    paths = collections.defaultdict(list)
    for rec in backend or []:
        if rec.get('kind') == 'block':
            rdevs[('b', rec['rdev'][0], rec['rdev'][1])].append('backend %s/%s' % (rec['sr'], rec['vdi']))
    for rec in phy or []:
        if rec.get('kind') == 'block':
            rdevs[('b', rec['rdev'][0], rec['rdev'][1])].append('phy %s/%s' % (rec['sr'], rec['vdi']))
        elif rec.get('kind') == 'file' and rec.get('target'):
            for t in path_variants(rec['target']):
                paths[t].append('phy %s/%s' % (rec['sr'], rec['vdi']))
    for kind, table in (('blktap', 'c'), ('tapdev', 'b')):
        for n, rec in ((blktap or {}).get(kind) or {}).items():
            if rec.get('kind') in ('char', 'block'):
                rdevs[(table, rec['rdev'][0], rec['rdev'][1])].append('%s%s' % (kind, n))
    return rdevs, paths


def fd_dir(pid):
    d = '%s/%d/fd' % (PROC, pid)
    try:
        fds = os.listdir(d)
    except OSError as exc:
        if gone(exc):
            return None, None, None
        return None, None, 'its fd directory cannot be listed: %s' % _text(exc)
    if fds:
        return d, fds, None
    try:
        if proc_stat(pid)['state'] != 'Z':
            return d, fds, None
    except EnvironmentError as exc:
        if gone(exc):
            return None, None, None
        return None, None, 'its state cannot be read: %s' % _text(exc)
    except (ValueError, IndexError) as exc:
        return None, None, 'its state cannot be parsed: %s' % _text(exc)
    try:
        tids = _listdir('%s/%d/task' % (PROC, pid))
    except OSError as exc:
        return None, None, 'its threads cannot be listed: %s' % _text(exc)
    for tid in tids:
        if tid == str(pid):
            continue
        d2 = '%s/%d/task/%s/fd' % (PROC, pid, tid)
        try:
            fds = os.listdir(d2)
        except OSError as exc:
            if gone(exc):
                continue
            return None, None, 'the fd directory of its thread %s cannot be listed: %s' % (tid, _text(exc))
        if fds:
            return d2, fds, None
    return d, [], None


def f_openers(backend, phy, blktap, budget=20.0, generic=False):
    rdevs, paths = interest_set(backend, phy, blktap)
    majors, prefixes = set(), ()
    if generic:
        devs = proc_devices()
        majors = set(v for (sec, name), v in devs.items() if sec == 'b' and name in ('device-mapper', 'drbd'))
        prefixes = tuple(sorted(p + '/' for p in path_variants(SR_MOUNT)))
    btime = boot_time()
    deadline = _now() + budget
    holders = []
    for pid in pids():
        if _now() > deadline:
            raise Failed('the /proc fd scan did not finish within %ds' % budget)
        if pid == os.getpid():
            continue
        d, fds, why = fd_dir(pid)
        if why:
            holders.append({'pid': pid, 'comm': comm_of(pid) or '?', 'argv': [], 'start': None, 'hits': [],
                            'unread': why})
            continue
        hits = []
        unread = None
        for fd in fds or []:
            p = d + '/' + fd
            try:
                tgt = os.readlink(p)
            except OSError as exc:
                if gone(exc):
                    continue
                unread = 'fd %s cannot be read: %s' % (fd, _text(exc))
                break
            if tgt in paths:
                hits.append({'fd': fd, 'target': tgt, 'what': paths[tgt][0], 'whats': list(paths[tgt])})
                continue
            if prefixes and tgt.startswith(prefixes):
                hits.append({'fd': fd, 'target': tgt, 'what': 'file %s' % tgt, 'whats': [], 'generic': True})
                continue
            if not tgt.startswith('/dev/'):
                continue
            try:
                st = os.stat(p)
            except OSError as exc:
                if gone(exc):
                    continue
                unread = 'fd %s (%s) cannot be examined: %s' % (fd, tgt, _text(exc))
                break
            if stat.S_ISBLK(st.st_mode):
                key = ('b', os.major(st.st_rdev), os.minor(st.st_rdev))
            elif stat.S_ISCHR(st.st_mode):
                key = ('c', os.major(st.st_rdev), os.minor(st.st_rdev))
            else:
                continue
            if key in rdevs:
                hits.append({'fd': fd, 'target': tgt, 'what': rdevs[key][0], 'whats': list(rdevs[key]),
                             'rdev': list(key)})
            elif key[0] == 'b' and key[1] in majors:
                hits.append({'fd': fd, 'target': tgt, 'what': 'block %d:%d' % key[1:], 'whats': [],
                             'rdev': list(key), 'generic': True})
        if hits or unread:
            try:
                ps = proc_stat(pid)
                argv = proc_cmdline(pid)
                comm, start = ps['comm'], btime + ps['start_ticks'] / float(clk_tck())
            except (EnvironmentError, ValueError, IndexError):
                comm, start, argv = comm_of(pid) or '?', None, []
            rec = {'pid': pid, 'comm': comm, 'argv': [a[:200] for a in argv[:12]], 'start': start, 'hits': hits}
            if unread:
                rec['unread'] = unread
            holders.append(rec)
    return holders


def f_tap_stats(rows, budget=60.0):
    out = {}
    deadline = _now() + budget
    for row in rows or []:
        if row.get('pid') is None or row.get('minor') is None:
            continue
        key = '%d:%d' % (row['pid'], row['minor'])
        if _now() > deadline:
            out[key] = {'ok': False, 'error': 'not asked: the stats probes ran out of their %ds budget' % budget,
                        'gone': not pid_alive(row['pid'])}
            continue
        r = run([TAPCTL, 'stats', '-p', str(row['pid']), '-m', str(row['minor'])], 5)
        if r.timed_out or r.rc == 124:
            out[key] = {'ok': False, 'error': 'deaf: tap-ctl stats timed out after 5s', 'gone': not pid_alive(row['pid'])}
        elif r.rc != 0:
            out[key] = {'ok': False, 'error': 'tap-ctl stats %s' % r.why(), 'gone': not pid_alive(row['pid'])}
        else:
            try:
                out[key] = {'ok': True, 'value': json.loads(r.out, object_pairs_hook=sum_rings)}
            except ValueError:
                out[key] = {'ok': True, 'value': {'raw': r.out[:2000]}}
    return out


def sum_rings(pairs):
    out = {}
    for k, v in pairs:
        if k not in out:
            out[k] = v
            continue
        old = out[k]
        if isinstance(old, bool) or isinstance(v, bool):
            out[k] = v
        elif isinstance(old, int) and isinstance(v, int):
            out[k] = old + v
        elif isinstance(old, list) and isinstance(v, list) and len(old) == len(v) and \
                all(isinstance(x, int) and not isinstance(x, bool) for x in old + v):
            out[k] = [x + y for x, y in zip(old, v)]
        elif isinstance(old, dict) and isinstance(v, dict):
            out[k] = sum_rings(list(old.items()) + list(v.items()))
        else:
            out[k] = v
    return out


def _sys_dev(path):
    try:
        text = read_text(path).strip()
    except EnvironmentError as exc:
        if gone(exc):
            return None
        raise
    parts = text.split(':')
    try:
        return '%d:%d' % (int(parts[0]), int(parts[1]))
    except (ValueError, IndexError):
        raise Failed('%s reads %s, not major:minor' % (path, canon(text[:40])))


def mount_namespaces():
    out = [(None, read_text(PROC + '/self/mountinfo'))]
    seen = set()
    try:
        seen.add(os.readlink(PROC + '/self/ns/mnt'))
    except OSError:
        pass
    for pid in pids():
        try:
            ns = os.readlink('%s/%d/ns/mnt' % (PROC, pid))
        except OSError as exc:
            if gone(exc):
                continue
            raise
        if ns in seen:
            continue
        try:
            text = read_text('%s/%d/mountinfo' % (PROC, pid))
        except EnvironmentError as exc:
            if exc.errno in (errno.ENOENT, errno.ESRCH):
                continue
            if exc.errno == errno.EINVAL and not pid_alive(pid):
                continue
            raise
        seen.add(ns)
        out.append((pid, text))
    return out


def f_kholders(backend, phy, blktap, extra=None):
    want = set(extra or [])
    for rec in backend or []:
        if rec.get('kind') == 'block':
            want.add('%d:%d' % tuple(rec['rdev']))
    for rec in phy or []:
        if rec.get('kind') == 'block':
            want.add('%d:%d' % tuple(rec['rdev']))
    for n, rec in ((blktap or {}).get('tapdev') or {}).items():
        if rec.get('kind') == 'block':
            want.add('%d:%d' % tuple(rec['rdev']))
    mounts = collections.defaultdict(list)
    for pid, text in mount_namespaces():
        where = '' if pid is None else ' (in the mount namespace of pid %d)' % pid
        for line in text.splitlines():
            parts = line.split()
            if len(parts) >= 5:
                mounts[parts[2]].append(parts[4] + where)
    swaps = []
    for line in read_text(PROC + '/swaps').splitlines()[1:]:
        parts = line.split()
        if parts:
            swaps.append(parts[0])
    swap_devs = collections.defaultdict(list)
    for s in swaps:
        if s.startswith('/dev/'):
            try:
                st = os.stat(s)
            except OSError as exc:
                if exc.errno in (errno.ENOENT, errno.ENOTDIR):
                    continue
                raise
            if stat.S_ISBLK(st.st_mode):
                swap_devs['%d:%d' % (os.major(st.st_rdev), os.minor(st.st_rdev))].append(s)
    loops = []
    for name in _listdir(SYS_BLOCK):
        if not name.startswith('loop'):
            continue
        try:
            back = read_text(os.path.join(SYS_BLOCK, name, 'loop', 'backing_file')).strip()
        except EnvironmentError as exc:
            if gone(exc):
                continue
            raise
        rec = {'loop': name, 'file': back, 'dev': None}
        if back.startswith('/dev/'):
            try:
                st = os.stat(back)
                if stat.S_ISBLK(st.st_mode):
                    rec['dev'] = '%d:%d' % (os.major(st.st_rdev), os.minor(st.st_rdev))
            except OSError as exc:
                if exc.errno not in (errno.ENOENT, errno.ENOTDIR):
                    raise
        loops.append(rec)
    out = {'devs': {}, 'loops': loops, 'swap_files': [s for s in swaps if not s.startswith('/dev/')]}
    for key in sorted(want):
        base = os.path.join(SYS_DEV_BLOCK, key)
        if not os.path.isdir(base):
            out['devs'][key] = {'exists': False, 'users': []}
            continue
        devs = [(key, base)]
        for sub in _listdir(base):
            p = os.path.join(base, sub)
            if os.path.isfile(os.path.join(p, 'partition')):
                d = _sys_dev(os.path.join(p, 'dev'))
                if d:
                    devs.append((d, p))
        users = []
        for d, p in devs:
            for h in _listdir(os.path.join(p, 'holders')):
                users.append('%s is held by %s' % (d, h))
            for m in mounts.get(d, []):
                users.append('%s is mounted on %s' % (d, m))
            for s in swap_devs.get(d, []):
                users.append('%s is swap (%s)' % (d, s))
            for l in loops:
                if l['dev'] == d:
                    users.append('%s backs loop device %s' % (d, l['loop']))
        out['devs'][key] = {'exists': True, 'users': users}
    return out


def _file_info(path):
    data = read_file(path)
    return data, sha256_bytes(data)


def code_words(data):
    tree = ast.parse(data.decode('utf-8', 'replace'))
    docs = set(id(n.value) for n in ast.walk(tree) if isinstance(n, ast.Expr) and _ast_str(n.value) is not None)
    strings, names = set(), set()
    for node in ast.walk(tree):
        s = _ast_str(node)
        if s is not None and id(node) not in docs:
            strings.add(s)
        if isinstance(node, (ast.FunctionDef, ast.ClassDef)):
            names.add(node.name)
        elif isinstance(node, ast.Attribute):
            names.add(node.attr)
        elif isinstance(node, ast.Name):
            names.add(node.id)
    return strings, names


def plugin_funcs(data):
    out = []
    for node in ast.walk(ast.parse(data.decode('utf-8', 'replace'))):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == 'dispatch' \
                and node.args and isinstance(node.args[0], ast.Dict):
            out.extend(s for s in (_ast_str(k) for k in node.args[0].keys) if s)
    return sorted(set(out))


def f_caps():
    caps = {}
    try:
        data, sha = _file_info(SM_DIR + '/blktap2.py')
        src = data.decode('utf-8', 'replace')
        caps['blktap2'] = {'sha256': sha}
        try:
            caps['blktap2']['lsof_bug'] = lsof_bug_probe(src)
            caps['blktap2']['add_tag'] = add_tag_probe(src)
        except SyntaxError as exc:
            caps['blktap2']['error'] = u'does not parse: %s' % _text(exc)
    except EnvironmentError as exc:
        caps['blktap2'] = {'error': _text(exc)}
    for key, name, probe in (
            ('cleanup', 'cleanup.py', lambda s, n: {
                'set_fmt': 'Set %s = %s for %s' in s, 'del_fmt': 'Removed %s from %s' in s,
                'relinking_key': 'relinking' in s,
                'gc_task': 'Garbage Collection' in s and 'Garbage collection for SR %s' in s,
                'gc_active': 'gc_active' in s, 'abort_from_openers': '_abort_gc_from_openers' in n}),
            ('lock', 'lock.py', lambda s, n: {'running': 'running' in s, 'base': '/var/lock/sm' in s,
                                              'flock': 'WriteLock' in n}),
            ('ipc', 'ipc.py', lambda s, n: {'base': '/var/run/sm/ipc' in s, 'pid': 'getpid' in n,
                                            'set_log': 'IPCFlag: set %s:%s' in s,
                                            'clear_log': 'IPCFlag: clear %s:%s' in s})):
        try:
            data, sha = _file_info(SM_DIR + '/' + name)
            words = code_words(data)
            caps[key] = dict(probe(*words), sha256=sha)
        except EnvironmentError as exc:
            caps[key] = {'error': _text(exc)}
        except SyntaxError as exc:
            caps[key] = {'error': u'%s does not parse: %s' % (name, _text(exc))}
    for key, name, funcs in (('on_slave', 'on-slave', ('is_open',)),
                             ('tapdisk_pause', 'tapdisk-pause', ('pause', 'unpause', 'refresh'))):
        try:
            data, sha = _file_info(PLUGIN_DIR + '/' + name)
            found = plugin_funcs(data)
            caps[key] = {'sha256': sha, 'funcs': [f for f in funcs if f in found]}
        except EnvironmentError as exc:
            caps[key] = {'error': _text(exc)}
        except SyntaxError as exc:
            caps[key] = {'error': u'%s does not parse: %s' % (name, _text(exc))}
    caps['toolstack_lock'] = toolstack_lockfile()
    return caps


def toolstack_lockfile():
    try:
        data = read_file(TOOLSTACK_SCRIPT)
    except EnvironmentError:
        return TOOLSTACK_LOCK
    m = re.search(br"^LOCKFILE=['\"]?([^'\"\n]+)", data, re.M)
    if m and m.group(1).startswith(b'/'):
        return _text(m.group(1))
    return TOOLSTACK_LOCK


def toolstack_flock(wait=0, on_wait=None):
    import fcntl
    lockpath = toolstack_lockfile()
    fd = os.open(lockpath, os.O_RDWR | os.O_CREAT, 0o644)
    deadline = _now() + wait
    told = False
    while True:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return fd, lockpath
        except (IOError, OSError):
            if _now() >= deadline:
                os.close(fd)
                return None, lockpath
        if on_wait is not None and not told:
            on_wait(lockpath)
            told = True
        time.sleep(max(min(POLL * 5, 2), 0.05))


def f_rpm():
    r = run([RPM, '-q', '--qf', '%{NAME} %{INSTALLTIME}\\n', 'sm', 'xapi-core', 'blktap', 'kernel',
             'xen-hypervisor'], 60)
    out = {}
    for line in r.out.splitlines():
        parts = line.split()
        if len(parts) == 2 and parts[1].isdigit():
            out[parts[0]] = max(out.get(parts[0], 0), int(parts[1]))
    if not out:
        raise Failed('rpm -q %s' % r.why())
    return out


def f_xapi_pkg():
    r = run([RPM, '-q', '--qf', '%{VERSION} %{RELEASE} %{INSTALLTIME}\\n', 'xapi-core'], 60)
    rows = [l.split() for l in r.out.splitlines() if len(l.split()) == 3 and l.split()[2].isdigit()]
    if not r.ok or len(rows) != 1:
        raise Failed('rpm -q xapi-core %s' % (r.why() if not r.ok else 'answered %d packages' % len(rows)))
    inv = parse_inventory(read_text(INVENTORY))
    return {'version': rows[0][0], 'release': rows[0][1], 'installed': int(rows[0][2]),
            'platform_version': inv.get('PLATFORM_VERSION')}


def smlog_files():
    files = []
    if os.path.exists(SMLOG):
        files.append(SMLOG)
    if os.path.exists(SMLOG + '.1'):
        files.append(SMLOG + '.1')
    rot = []
    d = os.path.dirname(SMLOG)
    base = os.path.basename(SMLOG)
    for name in _listdir(d):
        m = re.match('^' + re.escape(base) + r'\.(\d+)\.gz$', name)
        if m:
            rot.append((int(m.group(1)), os.path.join(d, name)))
    files.extend(p for _, p in sorted(rot))
    return files


def _open_log(path):
    if path.endswith('.gz'):
        return gzip.open(path, 'rb')
    return open(path, 'rb')


class OutOfTime(Exception):
    pass


def file_ref_time(path, now):
    try:
        return min(now, os.stat(path).st_mtime + 60)
    except OSError:
        return now


def scan_log(path, now, sink, deadline=None):
    ref = file_ref_time(path, now)
    n = 0
    with _open_log(path) as h:
        for raw in h:
            n += 1
            if deadline is not None and not n % 2048 and _now() > deadline:
                raise OutOfTime(path)
            if not SMLOG_PREFILTER.search(raw):
                continue
            line = raw.rstrip(b'\n').decode('utf-8', 'replace')
            ev = parse_smlog_line(line, ref)
            if ev is not None:
                sink(ev)


def log_number(path):
    if path == SMLOG:
        return 0
    if path == SMLOG + '.1':
        return 1
    m = re.match('^' + re.escape(SMLOG) + r'\.(\d+)\.gz$', path)
    return int(m.group(1)) if m else None


GC_START = re.compile(r'^=== SR (' + UUID_PAT + r'): (gc|gc_force) ===')
NOT_GC_WORK = ('Aborting currently-running instance', 'abort: releasing the process lock', 'New PID [',
               'Will finish as PID [')
PHY_UPDATE_WINDOW = 300
GC_TAIL = 900
SMLOG_LISTS = ('refusals', 'lockwaits', 'notap', 'failed_tag')


class SmlogScan(object):
    def __init__(self, q, now):
        self.now = now
        self.relink = set(q.get('relink') or [])
        self.abort_srs = set(q.get('abort') or [])
        self.activate = set(q.get('activate') or [])
        self.pause = set(q.get('pause') or [])
        self.phy = set(q.get('phy') or [])
        self.events = collections.defaultdict(list)
        self.runs = []
        self.refusals = []
        self.lockwaits = []
        self.notap = []
        self.failed_tag = []

    def file(self, num):
        return SmlogFile(self, num)

    def commit(self, fs):
        for k, v in fs.events.items():
            self.events[k].extend(v)
        self.runs.extend(fs.runs)
        for name in SMLOG_LISTS:
            getattr(self, name).extend(getattr(fs, name))

    def gc_runs(self):
        tail = {}
        for f in sorted(set(r['file'] for r in self.runs), reverse=True):
            recs = [r for r in self.runs if r['file'] == f]
            firsts = {}
            for r in recs:
                firsts.setdefault(r['pid'], r)
            for pid, r in firsts.items():
                prev = tail.get((f + 1, pid))
                if r['kind'] is not None or prev is None or prev['kind'] == 'abort':
                    continue
                if prev.get('closing') is not None and r['first'] - prev['closing'] > GC_TAIL:
                    continue
                prev['last'] = max(prev['last'], r['last'])
                prev['aborted'] = prev['aborted'] or r['aborted']
                prev['error'] = prev['error'] or r['error']
                if r['outcome'] is not None and (prev['outcome'] is None or r['outcome'] == 'Aborted'):
                    prev['outcome'] = r['outcome']
                prev['sr'] = prev['sr'] or r['sr']
                prev['work'] = prev['work'] or r['work']
                if r.get('closing') is not None:
                    prev['closing'] = r['closing']
                r['into'] = prev
            for r in recs:
                tail[(f, r['pid'])] = r['into'] or r
        out = []
        for r in self.runs:
            if r['into'] is None and r['work']:
                out.append(dict((k, r[k]) for k in ('pid', 'first', 'last', 'outcome', 'sr', 'aborted', 'error')))
        return out


class SmlogFile(object):
    def __init__(self, scan, num):
        self.scan = scan
        self.num = num
        self.events = collections.defaultdict(list)
        self.runs = []
        self.open = {}
        self.lock_sr = {}
        self.unpausing = {}
        for name in SMLOG_LISTS:
            setattr(self, name, [])

    def run(self, pid, t, kind=None, sr=None):
        r = {'pid': pid, 'first': t, 'last': t, 'outcome': None, 'sr': sr or self.lock_sr.pop(pid, None),
             'aborted': False, 'error': None, 'kind': kind, 'file': self.num, 'work': False, 'into': None}
        self.open[pid] = r
        self.runs.append(r)
        return r

    def sink(self, ev):
        s = self.scan
        t, ident, pid, msg = ev
        text = msg.strip()
        m = RE_PAUSE.match(text)
        if m:
            if m.group(1) == 'Unpause':
                self.unpausing[pid] = (m.group(2), t)
            if m.group(2) in s.pause:
                self.events['pause:' + m.group(2)].append([t, m.group(1).lower(), pid])
            return
        m = RE_PAUSE_REQ.match(text)
        if m:
            if m.group(2) in s.pause:
                self.events['preq:' + m.group(2)].append([t, m.group(1).lower(), pid])
            return
        m = RE_PHY_UPDATE.search(msg)
        if m:
            u = self.unpausing.get(pid)
            if u is not None and 0 <= t - u[1] <= PHY_UPDATE_WINDOW and u[0] in s.phy:
                self.events['phy:' + u[0]].append([t, m.group(1), pid])
            return
        m = RE_SET_RELINK.search(msg)
        if m and m.group(1) in s.relink:
            self.events['relink:' + m.group(1)].append([t, 'set', pid])
            return
        m = RE_DEL_RELINK.search(msg)
        if m and m.group(1) in s.relink:
            self.events['relink:' + m.group(1)].append([t, 'removed', pid])
            return
        m = RE_IPC.search(msg)
        if m and m.group(3) == 'abort':
            self.events['abort:' + m.group(2)].append([t, m.group(1), pid])
            return
        m = RE_SR_ABORT.search(msg)
        if m:
            self.events['abort:' + m.group(1)].append([t, 'cleanup-abort', pid])
            if ident == 'SMGC':
                self.run(pid, t, 'abort', m.group(1))
            return
        m = RE_GC_LOCK.search(msg)
        if m and m.group(2) == 'gc_active':
            r = self.open.get(pid)
            if r is not None and r.get('closing') is not None and t - r['closing'] > GC_TAIL:
                r = None
            if r is None:
                self.lock_sr[pid] = m.group(1)
            elif r['sr'] is None:
                r['sr'] = m.group(1)
        if ident == 'SMGC':
            ms = GC_START.match(text)
            r = self.open.get(pid)
            if ms:
                r = self.run(pid, t, 'gc', ms.group(1))
            elif r is None or (r.get('closing') is not None and t - r['closing'] > GC_TAIL):
                r = self.run(pid, t)
            r['last'] = t
            if not ms and not text.startswith(NOT_GC_WORK):
                r['work'] = True
            if text == 'Aborted':
                r['aborted'] = True
                r['outcome'] = 'Aborted'
            elif ('EXCEPTION' in msg or RE_SR_ERROR.search(msg)) and r['error'] is None:
                r['error'] = msg[:300]
                r['outcome'] = r['outcome'] or 'exception'
            elif msg.startswith('GC process exiting'):
                r['outcome'] = r['outcome'] or 'exited'
                r['closing'] = t
            mf = RE_FAILED_TAG.search(msg)
            if mf:
                self.failed_tag.append([t, pid, mf.group(1)])
            return
        m = RE_SR_ERROR.search(msg)
        if m:
            r = self.open.get(pid) or self.run(pid, t)
            r['last'] = t
            r['work'] = True
            r['error'] = msg[:300]
            return
        if s.activate and RE_ACTIVATE.search(msg):
            mv = RE_VDI_UUID.search(msg)
            if mv and mv.group(1) in s.activate:
                self.events['activate:' + mv.group(1)].append([t, 'activate', pid])
            return
        if RE_REFUSAL.search(msg):
            if t >= s.now - 86400:
                self.refusals.append([t, pid, msg[:240]])
            return
        m = RE_LOCK_WAIT.search(msg)
        if m:
            if t >= s.now - 86400:
                self.lockwaits.append([t, pid, m.group(1), int(m.group(2))])
            return
        m = RE_PHY.search(msg)
        if m and m.group(2) in s.phy:
            self.events['phy:' + m.group(2)].append([t, m.group(3), pid])
            return
        m = RE_NO_TAPDISK.search(msg)
        if m and t >= s.now - 86400:
            self.notap.append([t, pid, int(m.group(1))])


def pid_infos(want):
    return dict((str(p), pid_info(p)) for p in sorted(want))


def f_smlog(q):
    now = time.time()
    files = smlog_files()
    if not files or files[0] != SMLOG:
        raise Failed('%s is missing' % SMLOG)
    scan = SmlogScan(q, now)
    read = []
    complete = True
    budget = float(q.get('budget') or 150)
    deadline = _now() + budget
    if _DEADLINE[0] is not None:
        deadline = min(deadline, _DEADLINE[0] - 20)
    for i, path in enumerate(files):
        if i >= 2:
            need = [u for u in scan.relink if not any(e[1] == 'set' for e in scan.events.get('relink:' + u, []))]
            need += [s for s in scan.abort_srs if not any(e[1] == 'set' for e in scan.events.get('abort:' + s, []))]
            need += [v for v in scan.pause if not scan.events.get('pause:' + v) and not any(
                e[1] == 'pause' for e in scan.events.get('preq:' + v, []))]
            need += [v for v in scan.phy if not scan.events.get('phy:' + v)]
            if not need:
                break
            if _now() > deadline:
                complete = False
                break
        num = log_number(path)
        if num is None or num != (log_number(files[i - 1]) + 1 if i else 0):
            complete = False
            break
        st = os.stat(path)
        fs = scan.file(num)
        try:
            scan_log(path, now, fs.sink, deadline)
        except OutOfTime:
            if i < 2:
                raise Failed('%s was not read within the %ds budget' % (path, budget))
            complete = False
            break
        scan.commit(fs)
        read.append({'path': path, 'ino': st.st_ino, 'size': st.st_size, 'mtime': st.st_mtime})
    by_sr = collections.defaultdict(list)
    for run_ in sorted(scan.gc_runs(), key=lambda r: r['first']):
        by_sr[run_['sr']].append(run_)
    kept = {}
    for sr, runs in by_sr.items():
        for run_ in runs[-20:] + [r for r in runs if r['aborted'] or r['error']][-50:]:
            kept[id(run_)] = run_
    for k in scan.events:
        scan.events[k].sort()
    for name in SMLOG_LISTS:
        getattr(scan, name).sort()
    want_pids = set()
    for k, evs in scan.events.items():
        if k.startswith('relink:'):
            sets = [e for e in evs if e[1] == 'set']
            if sets:
                want_pids.add(sets[-1][2])
        elif k.startswith('pause:') or k.startswith('preq:'):
            ps = [e for e in evs if e[1] == 'pause']
            if ps:
                want_pids.add(ps[-1][2])
            if evs and k.startswith('preq:'):
                want_pids.add(evs[-1][2])
    try:
        pids_ = bounded(pid_infos, 20, want_pids)
    except (Failed, EnvironmentError, ValueError, IndexError):
        pids_ = {}
    drbd = {}
    if q.get('drbd'):
        vols = sorted(set(e[1] for k, evs in scan.events.items() if k.startswith('phy:') for e in evs))
        if vols:
            drbd = fact(f_drbd, vols)
    return {'files': read, 'all_files': len(files), 'complete': complete, 'events': dict(scan.events),
            'gc': sorted(kept.values(), key=lambda r: r['first']), 'refusals': scan.refusals[-50:],
            'refusal_count': len(scan.refusals), 'lockwaits': scan.lockwaits[-50:],
            'notap': scan.notap[-50:], 'failed_tag': scan.failed_tag[-200:], 'now': now, 'pids': pids_,
            'drbd': drbd}


DRBD_ROLE = re.compile(r'\brole:(\S+)')
DRBD_DISK = re.compile(r'\bdisk:(\S+)')
DRBD_OPEN = re.compile(r'\bopen:(\S+)')
DRBD_SUSP = re.compile(r'\bsuspended:(\S+)')
DRBD_QUORUM = re.compile(r'\bquorum:(\S+)')
DRBD_CONN = re.compile(r'\bconnection:(\S+)')
DRBD_PDISK = re.compile(r'\bpeer-disk:(\S+)')


def drbd_health(rec):
    if not rec:
        return 'unknown', 'it was not asked'
    if not rec.get('ok'):
        return 'unknown', rec.get('error') or 'drbdsetup failed'
    d = rec['value']
    if d.get('exists') is False:
        return 'bad', 'the resource does not exist on this host'
    if d.get('suspended') is None or d.get('disk') is None:
        return 'unknown', 'drbdsetup status could not be read (suspended:%s disk:%s)' % (d.get('suspended'), d.get('disk'))
    if d['suspended'] != 'no':
        return 'bad', 'suspended:%s' % d['suspended']
    if d.get('quorum') == 'no':
        return 'bad', 'quorum:no'
    if d['disk'] == 'UpToDate':
        return 'ok', 'disk:UpToDate'
    if d['disk'] == 'Diskless':
        good = [p for p in d.get('peers') or [] if p.get('connection') == 'Connected' and p.get('disk') == 'UpToDate']
        if good:
            return 'ok', 'disk:Diskless, %d connected peer(s) UpToDate' % len(good)
        return 'bad', 'disk:Diskless and no connected peer is UpToDate'
    return 'bad', 'disk:%s' % d['disk']


def f_drbd(resources):
    out = {}
    if not resources:
        return out
    if not os.path.exists(DRBDSETUP):
        raise Failed('%s is not installed' % DRBDSETUP)
    for res in resources:
        if not re.match(r'^xcp-volume-' + UUID_PAT + '$', res):
            out[res] = {'ok': False, 'error': 'not a LINSTOR volume name'}
            continue
        r = run([DRBDSETUP, 'status', '--verbose', res], 10)
        text = r.out + r.err
        if not r.timed_out and r.rc != 0 and 'No such resource' in text:
            out[res] = {'ok': True, 'value': {'exists': False}}
        elif not r.ok:
            out[res] = {'ok': False, 'error': 'drbdsetup status %s' % r.why()}
        else:
            lines = r.out.splitlines()
            role = DRBD_ROLE.search(lines[0]) if lines else None
            susp = DRBD_SUSP.search(lines[0]) if lines else None
            disk = opn = quo = None
            seen = False
            peers = []
            for line in lines[1:]:
                if line.startswith('    '):
                    pd = DRBD_PDISK.search(line)
                    if peers and pd and peers[-1]['disk'] is None:
                        peers[-1]['disk'] = pd.group(1)
                    continue
                if not line.startswith('  '):
                    continue
                if 'connection:' in line:
                    cm = DRBD_CONN.search(line)
                    peers.append({'name': line.split()[0], 'connection': cm.group(1) if cm else None, 'disk': None})
                elif not seen and (line.startswith('  volume:') or 'disk:' in line and 'peer' not in line):
                    seen = True
                    disk, opn, quo = DRBD_DISK.search(line), DRBD_OPEN.search(line), DRBD_QUORUM.search(line)
            out[res] = {'ok': True, 'value': {'exists': True, 'role': role.group(1) if role else None,
                                              'suspended': susp.group(1) if susp else None,
                                              'disk': disk.group(1) if disk else None,
                                              'open': opn.group(1) if opn else None,
                                              'quorum': quo.group(1) if quo else None, 'peers': peers,
                                              'raw': r.out[:1500]}}
    return out


FACTS_BUDGET = AGENT_TIMEOUT - 40


def agent_facts(args):
    _DEADLINE[0] = _now() + float(args.get('budget') or FACTS_BUDGET)
    try:
        return facts_doc(args)
    finally:
        _DEADLINE[0] = None


def facts_doc(args):
    want = set(args.get('want') or ['core'])
    doc = {'agent': {'version': VERSION, 'python': PYTHON, 'pid': os.getpid(), 'time': time.time()}}
    doc['identity'] = fact(f_identity)
    if 'core' in want:
        doc['storage_db'] = fact(f_storage_db)
        doc['storage_dps'] = fact(f_storage_dps)
        doc['tapdisks'] = fact(f_tapdisks)
        doc['backend'] = fact(f_backend)
        doc['phy'] = fact(f_phy)
        doc['blktap'] = fact(f_blktap)
        doc['sys_minors'] = fact(f_sys_minors)
        doc['xenstore'] = fact(f_xenstore)
        doc['procs'] = fact(bounded, f_procs, 30)
        doc['locks'] = fact(bounded, f_locks, 20)
        doc['ipc'] = fact(bounded, f_ipc, 20)
        doc['nbd'] = fact(f_nbd)
        doc['ha'] = fact(f_ha)
        doc['cookies'] = fact(f_cookies)
        doc['xapi'] = fact(f_xapi_state)
        doc['static_vdis'] = fact(f_static_vdis)
        doc['units'] = fact(f_units, args.get('srs') or [])
        doc['nbd_vbds'] = fact(f_nbd_vbds)
        doc['smrefs'] = fact(f_smrefs)
        doc['domains'] = fact(f_domains)
        doc['room'] = fact(f_room)
        doc['blockmap'] = fact(f_blockmap)
        parts = [doc['backend'], doc['phy'], doc['blktap'], doc['blockmap']]
        if all(p['ok'] for p in parts):
            bm = doc['blockmap']['value']
            extra = sorted(set([v for k, v in bm['dm'].items() if k.startswith('VG_XenStorage--')] +
                               list(bm['drbd'].values())))
            doc['openers'] = fact(bounded, f_openers, 35, doc['backend']['value'], doc['phy']['value'],
                                  doc['blktap']['value'], 20.0, True)
            doc['kholders'] = fact(bounded, f_kholders, 30, doc['backend']['value'], doc['phy']['value'],
                                   doc['blktap']['value'], extra)
        else:
            doc['openers'] = {'ok': False, 'error': 'the device facts the fd scan needs were not established'}
            doc['kholders'] = {'ok': False, 'error': 'the device facts the holder scan needs were not established'}
        if doc['tapdisks']['ok']:
            doc['tap_stats'] = fact(f_tap_stats, doc['tapdisks']['value'])
            doc['ctl_backlog'] = fact(f_ctl_backlog, [r['pid'] for r in doc['tapdisks']['value']
                                                      if r['pid'] is not None])
        else:
            doc['ctl_backlog'] = {'ok': False, 'error': 'the tapdisks were not listed, so their control sockets '
                                                        'cannot be matched'}
        doc['identity_after'] = fact(f_identity)
    if 'ha' in want and 'core' not in want:
        doc['ha'] = fact(f_ha)
        doc['xapi'] = fact(f_xapi_state)
        doc['cookies'] = fact(f_cookies)
    if 'caps' in want:
        doc['caps'] = fact(f_caps)
    if 'rpm' in want:
        doc['rpm'] = fact(f_rpm)
        doc['xapi_pkg'] = fact(f_xapi_pkg)
    if 'smlog' in want:
        doc['smlog'] = fact(f_smlog, args.get('smlog') or {})
    if 'drbd' in want:
        doc['drbd'] = fact(f_drbd, args.get('drbd') or [])
    if 'extra' in want:
        doc['pids'] = fact(bounded, f_pids, 20, args.get('pids') or [])
        doc['statfiles'] = fact(f_statfiles, args.get('statfiles') or [])
        doc['lvnames'] = fact(f_lvnames, args.get('vgs') or [])
        doc['srdir'] = fact(f_srdir, args.get('srdirs') or [])
        doc['xsread'] = fact(f_xsread, args.get('xsread') or [])
        doc['vhdcheck'] = fact(f_vhdcheck, args.get('vhdcheck') or [])
        doc['dmcheck'] = fact(f_dmcheck, args.get('dmcheck') or [])
    return doc


RESTORE_UNITS = ('xapi-wait-init-complete.service',)
RUN_ID_RE = re.compile(r'^[0-9]{8}-[0-9]{6}-[0-9a-f]{6}$')
SCAN_BUDGET = 20


def act_dir(run_id, host_uuid, attempt):
    if not RUN_ID_RE.match(run_id or '') or not UUID_RE.match(host_uuid or ''):
        raise Failed('bad run id or host uuid')
    return os.path.join(RUN_ROOT, 'runs', run_id, 'act-%s-%d' % (host_uuid[:8], int(attempt)))


def bounded(fn, timeout, *args):
    box = {}

    def work():
        try:
            box['value'] = fn(*args)
        except Exception as exc:
            box['error'] = exc
    wait = tmo(timeout)
    t = threading.Thread(target=work)
    t.daemon = True
    t.start()
    t.join(wait)
    if t.is_alive():
        raise Failed('%s did not finish within %ds (a process may be wedged)' % (fn.__name__, wait))
    if 'error' in box:
        raise box['error']
    return box['value']


def write_status(d, state, **fields):
    path = os.path.join(d, 'status.json')
    try:
        cur = read_json(path)
    except (EnvironmentError, ValueError):
        cur = {}
    cur.update(fields)
    cur['state'] = state
    cur['time'] = time.time()
    hist = cur.setdefault('history', [])
    hist.append([cur['time'], state, fields.get('detail')])
    write_json_atomic(path, cur)
    return cur


def safe_status(d, state, **fields):
    try:
        return write_status(d, state, **fields)
    except Exception as exc:
        act_log(d, 'cannot write the status %s: %s' % (state, _text(exc)))
        return None


def read_status(d):
    try:
        return read_json(os.path.join(d, 'status.json'))
    except (EnvironmentError, ValueError):
        return None


def act_log(d, text):
    try:
        with open(os.path.join(d, 'action.log'), 'ab') as h:
            h.write((time.strftime('%Y-%m-%d %H:%M:%S ') + _text(text) + u'\n').encode('utf-8', 'replace'))
    except EnvironmentError:
        pass
    _AUDIT[0] = True
    _log('info', text)


def protect_self():
    try:
        with open('/proc/self/oom_score_adj', 'w') as h:
            h.write('-1000')
    except EnvironmentError:
        pass


def spawn_detached(argv, log_path):
    log = open(log_path, 'ab')
    try:
        proc = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=log, stderr=log, close_fds=True,
                                start_new_session=True)
    finally:
        log.close()
    return proc.pid


def agent_act_start(args, source):
    spec = args['spec']
    d = act_dir(spec['run_id'], spec['host_uuid'], spec['attempt'])
    if not os.path.isdir(d):
        os.makedirs(d, 0o700)
    spec_path = os.path.join(d, 'spec.json')
    fd = os.open(spec_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        data = json.dumps(spec, sort_keys=True).encode('utf-8')
        append_all(fd, data)
        os.fsync(fd)
    finally:
        os.close(fd)
    agent_path = os.path.join(d, 'agent.py')
    if not os.path.exists(agent_path):
        write_new(agent_path, source, 0o700)
    pid = spawn_detached([sys.executable, agent_path, '--ssf-act', spec_path], os.path.join(d, 'action.out'))
    try:
        start = proc_start(pid, boot_time())
    except (EnvironmentError, ValueError, IndexError):
        start = None
    write_json_atomic(os.path.join(d, 'spawned.json'), {'pid': pid, 'start': start})
    deadline = _now() + 15
    while _now() < deadline:
        st = read_status(d)
        if st is not None:
            return {'pid': pid, 'dir': d, 'status': st}
        time.sleep(0.2)
    return {'pid': pid, 'dir': d, 'status': None}


def agent_act_status(args, source):
    d = act_dir(args['run_id'], args['host_uuid'], args['attempt'])
    st = read_status(d)
    btime = boot_time()
    alive, pids_ = {}, {}
    for who in ('action', 'guardian'):
        try:
            rec = read_json(os.path.join(d, who + '.json'))
        except (EnvironmentError, ValueError):
            rec = None
        if rec is None and who == 'action':
            try:
                rec = read_json(os.path.join(d, 'spawned.json'))
            except (EnvironmentError, ValueError):
                rec = None
        try:
            alive[who] = pid_alive(rec['pid'], rec['start'], btime) if rec['start'] is not None else False
            pids_[who] = rec['pid']
        except (TypeError, KeyError):
            alive[who] = None
            pids_[who] = None
    try:
        backstop = read_json(os.path.join(d, 'backstop.json'))
    except (EnvironmentError, ValueError):
        backstop = None
    return {'status': st, 'alive': alive, 'pids': pids_, 'backstop': backstop, 'dir': d, 'exists': os.path.isdir(d)}


ACT_DIR_RE = re.compile(r'^act-([0-9a-f]{8})-([0-9]+)$')


def agent_act_list(args, source):
    run_id = args.get('run_id') or ''
    if not RUN_ID_RE.match(run_id):
        raise Failed('bad run id')
    me = parse_inventory(read_text(INVENTORY)).get('INSTALLATION_UUID')
    root = os.path.join(RUN_ROOT, 'runs', run_id)
    out, odd = [], []
    for name in _listdir(root):
        m = ACT_DIR_RE.match(name)
        if not m:
            continue
        d = os.path.join(root, name)
        try:
            spec = read_json(os.path.join(d, 'spec.json'))
        except (EnvironmentError, ValueError) as exc:
            odd.append('%s: its spec.json cannot be read (%s)' % (name, _text(exc)))
            continue
        host = spec.get('host_uuid') if isinstance(spec, dict) else None
        if not host or not UUID_RE.match(host) or host[:8] != m.group(1) or host != me:
            odd.append('%s names host %s' % (name, host))
            continue
        out.append({'host_uuid': host, 'attempt': int(m.group(2)), 'status': read_status(d),
                    'items': spec.get('items') or []})
    return {'host': me, 'acts': out, 'odd': odd, 'exists': os.path.isdir(root)}


def record_self(d, who):
    pid = os.getpid()
    write_json_atomic(os.path.join(d, who + '.json'), {'pid': pid, 'start': proc_start(pid, boot_time())})


def xapi_unit_state():
    r = systemctl('is-active', XAPI_UNIT)
    return r.out.strip() or 'unknown'


def comm_of(pid):
    try:
        return read_file('%s/%d/comm' % (PROC, pid)).strip().decode('utf-8', 'replace')
    except EnvironmentError:
        return None


XAPI_UNIT_NAMES = (XAPI_UNIT, 'xapi', 'toolstack.target', 'toolstack')
SYSTEMCTL_VERBS = ('stop', 'start', 'restart', 'try-restart', 'reload-or-restart', 'try-reload-or-restart',
                   'isolate', 'kill')


def inflight_systemctl():
    out = []
    for pid in pids():
        if pid == os.getpid():
            continue
        try:
            if comm_strict(pid) != 'systemctl':
                continue
            argv = proc_cmdline(pid)
        except EnvironmentError as exc:
            if not gone(exc):
                out.append(pid)
            continue
        if any(u in argv for u in XAPI_UNIT_NAMES) and any(v in argv for v in SYSTEMCTL_VERBS):
            out.append(pid)
    return out


def settle_xapi_jobs(limit):
    deadline = _now() + limit
    while True:
        try:
            busy = bounded(inflight_systemctl, SCAN_BUDGET)
        except Failed:
            busy = ['?']
        state = xapi_unit_state()
        if not busy and state not in ('deactivating', 'activating', 'reloading'):
            return state
        if _now() > deadline:
            return state
        time.sleep(POLL)


def xapi_answers():
    r = xe('pool-list', '--minimal', timeout=30)
    return r.ok and bool(UUID_RE.match(r.out.strip()))


def xapi_stopped():
    try:
        return xapi_unit_state() in ('inactive', 'failed') and not pids_named(b'xapi')
    except Failed:
        return False


def active_units():
    r = systemctl('list-units', '--type=service', '--state=active', '--no-legend', '--plain', '--all')
    if not r.ok:
        r = systemctl('list-units', '--type=service', '--state=active', '--no-legend')
    if not r.ok:
        return None
    out = []
    for line in r.out.splitlines():
        parts = line.split()
        if parts and parts[0].endswith('.service'):
            out.append(parts[0].lstrip('*'))
    return sorted(out)


def local_session():
    import XenAPI
    socket.setdefaulttimeout(API_TIMEOUT)
    s = XenAPI.xapi_local()
    s.xenapi.login_with_password('root', '', '', PROG)
    return s


def ha_stop_problems():
    problems = []
    try:
        armed = local_armed()
    except (EnvironmentError, ValueError) as exc:
        armed = None
        problems.append('HA state not established: %s cannot be read (%s)' % (LOCAL_DB, _text(exc)))
    if armed is not None and armed not in ('false', 'absent'):
        problems.append('%s says ha.armed=%s' % (LOCAL_DB, armed))
    try:
        xh = pids_named(b'xhad')
    except Failed as exc:
        xh = []
        problems.append('whether xhad runs is not established: %s' % _text(exc))
    if xh:
        problems.append('xhad is running (pid %s)' % ', '.join(str(p) for p in xh))
    return problems


def local_recheck(spec):
    problems = []
    inv = parse_inventory(read_text(INVENTORY))
    if inv.get('INSTALLATION_UUID') != spec['host_uuid']:
        problems.append('this host is %s, not %s' % (inv.get('INSTALLATION_UUID'), spec['host_uuid']))
    if socket.gethostname() != spec['hostname']:
        problems.append('the hostname is %s, not %s' % (socket.gethostname(), spec['hostname']))
    problems.extend(ha_stop_problems())
    if problems:
        return problems
    try:
        rows = f_tapdisks()
    except Exception as exc:
        return ['tap-ctl list: %s' % _text(exc)]
    known = set(tuple(x) for x in spec.get('paused') or [])
    for row in rows:
        if row['state'] is not None and row['state'] & PAUSED and (row['pid'], row['minor']) not in known:
            problems.append('tapdisk pid %s minor %s is paused (state %s)'
                            % (row['pid'], row['minor'], tap_state_text(row['state'])))
    if problems:
        return problems
    try:
        served = served_vdis(rows)
    except Exception as exc:
        return ['the disks served here cannot be mapped: %s' % _text(exc)]
    try:
        s = local_session()
    except Exception as exc:
        return ['the local xapi cannot be asked: %s' % _text(exc)]
    try:
        x = s.xenapi
        me = x.host.get_by_uuid(spec['host_uuid'])
        if served:
            for ref, v in x.VDI.get_all_records().items():
                if v['uuid'] not in served:
                    continue
                smc = v['sm_config']
                for key in ('paused', 'relinking'):
                    if key in smc:
                        problems.append('VDI %s, served here, now carries %s' % (v['uuid'], key))
        if problems:
            return problems
        deadline = _now() + QUIET_WAIT
        while True:
            busy = bounded(local_sm_activity, SCAN_BUDGET)
            for ref, t in x.task.get_all_records().items():
                if t['status'] == 'pending' and (spec.get('is_master') or t['resident_on'] == me):
                    busy.append('task %s "%s" is pending' % (t['uuid'], t['name_label']))
            if not busy:
                break
            if _now() > deadline:
                return ['xapi and SM are not quiet here after %ds: %s' % (QUIET_WAIT, '; '.join(busy[:5]))]
            time.sleep(1)
    except Failed as exc:
        problems.append(_text(exc))
    except Exception as exc:
        problems.append('reading the pool through the local xapi failed: %s' % _text(exc))
    finally:
        try:
            s.xenapi.session.logout()
        except Exception:
            pass
    return problems


def served_vdis(rows):
    out = set()
    back = {}
    tapmaj = proc_devices().get(('b', 'tapdev'))
    for rec in f_backend():
        if rec.get('kind') == 'block' and tapmaj is not None and rec['rdev'][0] == tapmaj:
            back.setdefault(rec['rdev'][1], set()).add(rec['vdi'])
    by_target = {}
    for rec in f_phy():
        for t in path_variants(rec.get('target') or ''):
            if t:
                by_target[t] = rec['vdi']
    for row in rows:
        if row.get('pid') is None:
            continue
        hit = False
        if row.get('minor') is not None and row['minor'] in back:
            out |= back[row['minor']]
            hit = True
        if (row.get('path') or '') in by_target:
            out.add(by_target[row['path']])
            hit = True
        for m in re.findall(UUID_PAT, row.get('path') or ''):
            out.add(m)
            hit = True
        if not hit:
            raise Failed('tapdisk pid %s minor %s %s' % (row.get('pid'), row.get('minor'), unmapped_why(row)))
    return out


def unmapped_why(row):
    if row.get('minor') is None or not row.get('path'):
        return 'did not say what it serves (tap-ctl lists it with no disk)'
    return 'serves an image that maps to no VDI'


def gc_lock_sr(path):
    m = re.match('^' + re.escape(SM_LOCK_DIR) + '/(' + UUID_PAT + ')/(gc_active|running)$', path or '')
    return m.group(1) if m else None


def local_sm_activity():
    busy = []
    for pid in pids():
        if pid == os.getpid():
            continue
        try:
            argv = proc_cmdline(pid)
        except EnvironmentError as exc:
            if not gone(exc):
                busy.append('pid %d cannot be read, so whether it is an SM process is not established (%s)'
                            % (pid, _text(exc)))
            continue
        if is_sm_argv(argv):
            gc = [a for a in argv if UUID_RE.match(a)] if any(a.endswith('cleanup.py') for a in argv) else []
            if gc:
                busy.append('the GC of SR %s runs (pid %d); a coalesce can take hours' % (gc[0], pid))
            else:
                busy.append('pid %d %s' % (pid, ' '.join(argv[:3])[:160]))
    try:
        for l in f_locks():
            sr = gc_lock_sr(l['path'])
            if sr:
                busy.append('the GC of SR %s holds %s (pid %d); a coalesce can take hours' % (sr, l['path'], l['pid']))
            else:
                busy.append('lock %s held by pid %d' % (l['path'] or '(an unlinked SM lock file)', l['pid']))
    except Exception as exc:
        busy.append('the SM lock holders cannot be read: %s' % _text(exc))
    r = systemctl('list-units', '--all', '--no-legend', '--plain', 'SMGC@*')
    if not r.ok:
        busy.append('the GC units cannot be listed: %s' % r.why())
    else:
        for line in r.out.splitlines():
            f = line.split()
            if len(f) >= 3 and f[2] in ('active', 'activating', 'deactivating', 'reloading'):
                busy.append('%s is %s' % (f[0].replace('\\x2d', '-'), f[2]))
    return busy


def stop_xapi_local(d):
    r = systemctl('stop', XAPI_UNIT, timeout=STOP_TIMEOUT)
    if not r.ok:
        act_log(d, 'systemctl stop %s: %s' % (XAPI_UNIT, r.why()))
    deadline = _now() + GONE_WAIT
    while True:
        state, xp = xapi_unit_state(), pids_named(b'xapi')
        if state in ('inactive', 'failed') and not xp:
            return
        if _now() > deadline:
            raise Failed('xapi did not stop: the service is %s, xapi pid(s) %s' % (state, xp or 'none'))
        time.sleep(POLL)


def fresh_since(path, t):
    try:
        return os.stat(path).st_mtime >= t - 1
    except OSError:
        return False


def start_xapi_local(d, units_before):
    issued = time.time()
    res = {'ready': False, 'answering': False, 'complete': False, 'detail': '', 'restored': [],
           'missing_units': [], 'units_notes': [], 'issued': issued}
    systemctl('reset-failed', XAPI_UNIT)
    r = systemctl('start', XAPI_UNIT, timeout=START_TIMEOUT)
    if not r.ok:
        act_log(d, 'systemctl start %s: %s' % (XAPI_UNIT, r.why()))
    deadline = _now() + READY_WAIT
    while True:
        state = xapi_unit_state()
        if state == 'failed':
            res['detail'] = 'the xapi service failed while starting'
            return res
        if fresh_since(STARTUP_COOKIE, issued):
            break
        if _now() > deadline:
            res['detail'] = 'xapi did not become ready within %ds (service %s)' % (READY_WAIT, state)
            return res
        time.sleep(POLL)
    res['ready'] = True
    deadline = _now() + ANSWER_WAIT
    while not xapi_answers():
        if _now() > deadline:
            res['detail'] = 'xapi is up but its CLI got no answer within %ds' % ANSWER_WAIT
            return res
        time.sleep(POLL)
    res['answering'] = True
    deadline = _now() + INIT_WAIT
    while not fresh_since(INIT_COOKIE, issued):
        if _now() > deadline:
            res['detail'] = 'xapi has not finished initialising after %ds' % INIT_WAIT
            break
        time.sleep(POLL)
    else:
        res['complete'] = True
    try:
        restore_units(d, units_before, res)
    except Exception as exc:
        res['units_notes'].append('the services could not be compared after the start: %s' % _text(exc))
    return res


def restore_units(d, units_before, res):
    now = active_units()
    notes = res.setdefault('units_notes', [])
    if now is None or units_before is None:
        started = []
        for u in RESTORE_UNITS:
            if units_before is not None and u not in units_before:
                continue
            if now is not None and u in now:
                continue
            r = systemctl('start', '--no-block', u)
            started.append('%s (%s)' % (u, 'started' if r.ok else r.why()))
        res['restored'].extend(started)
        notes.append('the active services were not listed %s, so they were not compared%s'
                     % ('again after the start' if now is None else 'before xapi was stopped',
                        ('; started again in any case: %s' % ', '.join(started)) if started else ''))
        return
    for u in units_before:
        if u in now or u == XAPI_UNIT:
            continue
        if u in RESTORE_UNITS:
            r = systemctl('start', '--no-block', u)
            res['restored'].append('%s (%s)' % (u, 'started' if r.ok else r.why()))
        else:
            res['missing_units'].append(u)


def plan_from_file(obj, spec):
    entries = check_storage_db(obj)
    backed = set(tuple(x) for x in spec.get('backed') or [])
    for item in spec['items']:
        sr, vdi, dp = item['sr'], item['vdi'], item['dp']
        if not DOM0_DP_RE.match(dp):
            raise Failed('%s is not a dom0 datapath' % dp)
        e = obj['host']['srs'].get(sr, {}).get('vdis', {}).get(vdi)
        if e is None or dp not in e.get('dps', {}):
            raise Failed('%s of VDI %s is no longer in the file' % (dp, vdi))
        if e['dps'][dp] != ['Attached', 'RO']:
            raise Failed('%s of VDI %s is now %s' % (dp, vdi, canon(e['dps'][dp])))
        if dp in (e.get('leaked') or []):
            raise Failed('%s of VDI %s is listed in leaked' % (dp, vdi))
        for odp, st in e.get('dps', {}).items():
            if (vdi, odp) in backed:
                raise Failed('%s of VDI %s is backed by an attached dom0 VBD' % (odp, vdi))
            if DOM0_DP_RE.match(odp) and st[0] == 'Activated':
                raise Failed('VDI %s now has an activated dom0 datapath %s' % (vdi, odp))
    return entries


def edit_storage_db(obj, spec):
    new = json.loads(json.dumps(obj))
    removed = []
    for item in spec['items']:
        e = new['host']['srs'][item['sr']]['vdis'][item['vdi']]
        del e['dps'][item['dp']]
        if item['dp'] in e.get('dpv', {}):
            del e['dpv'][item['dp']]
        removed.append([item['sr'], item['vdi'], item['dp']])
    gone = []
    for item in spec['items']:
        vdis = new['host']['srs'][item['sr']]['vdis']
        e = vdis.get(item['vdi'])
        if e is not None and not e.get('dps') and not e.get('leaked'):
            del vdis[item['vdi']]
            gone.append([item['sr'], item['vdi']])
    return new, removed, gone


def verify_edit(old, new, spec):
    planned = set((i['sr'], i['vdi'], i['dp']) for i in spec['items'])
    olde = dict(((sr, vdi), e) for sr, vdi, e in check_storage_db(old))
    newe = dict(((sr, vdi), e) for sr, vdi, e in check_storage_db(new))
    if canon(old.get('errors')) != canon(new.get('errors')):
        raise Failed('the errors array changed')
    if set(old['host']['srs']) != set(new['host']['srs']):
        raise Failed('the set of SRs changed')
    for key, e in olde.items():
        n = newe.get(key)
        mine = [p for p in planned if (p[0], p[1]) == key]
        if not mine:
            if n is None or canon(n) != canon(e):
                raise Failed('VDI %s changed although nothing was planned for it' % key[1])
            continue
        want = json.loads(json.dumps(e))
        for _, _, dp in mine:
            want['dps'].pop(dp, None)
            want.get('dpv', {}).pop(dp, None)
        if not want.get('dps') and not want.get('leaked'):
            if n is not None:
                raise Failed('VDI %s should have been removed whole' % key[1])
        elif n is None or canon(n) != canon(want):
            raise Failed('VDI %s does not hold exactly the planned change' % key[1])
    for key in newe:
        if key not in olde:
            raise Failed('VDI %s appeared in the edited file' % key[1])


def dump_storage_db(obj):
    return json.dumps(obj, ensure_ascii=False, separators=(',', ':')).encode('utf-8')


def image_rows(rows, vdi, target):
    out = []
    for row in rows:
        p = row.get('path') or ''
        if vdi in re.findall(UUID_PAT, p) or (target and p in path_variants(target)):
            out.append(row)
    return out


def post_stop_problems(spec):
    deadline = _now() + QUIET_WAIT
    while True:
        try:
            busy = bounded(local_sm_activity, SCAN_BUDGET)
        except Failed as exc:
            return [_text(exc)]
        if not busy:
            break
        if _now() > deadline:
            return ['SM is not quiet %ds after xapi stopped: %s' % (QUIET_WAIT, '; '.join(busy[:5]))]
        time.sleep(1)
    try:
        rows = f_tapdisks()
        phys = f_phy()
    except Exception as exc:
        return ['the tapdisks and phy links cannot be read again: %s' % _text(exc)]
    targets = set()
    for rec in phys:
        if rec.get('target'):
            targets |= path_variants(rec['target'])
    problems = []
    for row in rows:
        p = row.get('path') or ''
        if not re.findall(UUID_PAT, p) and p not in targets:
            problems.append('tapdisk pid %s minor %s serves an image that maps to no VDI' % (row['pid'], row['minor']))
    for item in spec['items']:
        sr, vdi = item['sr'], item['vdi']
        back = os.path.join(SM_BACKEND, sr, vdi)
        phy = os.path.join(SM_PHY, sr, vdi)
        target = None
        if os.path.lexists(back):
            problems.append('%s exists now' % back)
        if os.path.lexists(phy):
            problems.append('%s exists now' % phy)
            try:
                target = os.readlink(phy)
            except OSError:
                pass
        for row in image_rows(rows, vdi, target):
            problems.append('tapdisk pid %s minor %s serves %s now' % (row['pid'], row['minor'], vdi))
    lvm = [i for i in spec['items'] if i.get('lvm')]
    if lvm:
        try:
            bm = f_blockmap()
            refs = f_smrefs()
        except Exception as exc:
            return problems + ['the LV state cannot be read again: %s' % _text(exc)]
        for item in lvm:
            sr, vdi = item['sr'], item['vdi']
            rc = (refs.get('lvm-' + sr) or {}).get(vdi)
            if rc is not None:
                problems.append('SM counts an activation of %s here now (refcount %s)' % (vdi, rc))
            for n in lv_dm_names(sr, vdi):
                if n in bm['dm']:
                    problems.append('the LV of %s is active here now (%s)' % (vdi, n))
    return problems


LOAD_FAILED = ('Failed to load storage state', 'Failed to unmarshal Everything state', 'No storage state is persisted')


def dp_released(lines, key):
    sr, vdi, dp = key
    tag = ' dp:%s ' % dp
    for l in lines:
        if ('DP.destroy' in l or 'VDI.detach' in l or 'Attempting to destroy datapath' in l) and tag in l + ' ':
            return True
        if 'SR.detach' in l and ('sr:%s' % sr) in l:
            return True
    return False


def verify_loaded(issued, obj, host_uuid, removed=None):
    res = {'failed': False, 'established': False, 'detail': '', 'log': None, 'memory': None}
    covered = None
    try:
        lines, covered = log_lines_covered(XENSOURCE_LOG, issued - 2, must=b'Storage_smapiv1_wrapper')
    except Failed as exc:
        lines = None
        res['log'] = {'error': _text(exc)}
    log_ok = False
    after = []
    if lines is not None:
        loads = [i for i, l in enumerate(lines) if 'Loading storage state from' in l]
        after = lines[loads[-1]:] if loads else lines
        bad = [l for l in after if any(p in l for p in LOAD_FAILED)]
        res['log'] = {'loading': len(loads), 'failed': [b[-300:] for b in bad], 'covered': covered}
        if bad:
            res['failed'] = True
            res['detail'] = 'xapi logged: %s' % bad[-1][-300:]
            return res
        log_ok = bool(loads)
    want = file_dp_set(obj)
    r = xe('host-get-sm-diagnostics', 'uuid=' + host_uuid, timeout=XE_TIMEOUT)
    mem = None
    if not r.ok:
        res['memory'] = {'error': 'xe host-get-sm-diagnostics %s' % r.why()}
    else:
        try:
            mem = parse_sm_diagnostics(r.out)
        except ValueError as exc:
            res['memory'] = {'error': _text(exc)}
    if mem is None:
        res['detail'] = ('the datapaths xapi holds could not be read (%s), so whether it loaded the file is not '
                         'established' % res['memory']['error'])
        return res
    missing = sorted(want - mem)
    released = [x for x in missing if dp_released(after, x)]
    unexplained = [x for x in missing if x not in released]
    back = sorted(set(tuple(x) for x in removed or []) & mem)
    res['memory'] = {'file': len(want), 'memory': len(mem), 'missing': [list(x) for x in unexplained[:20]],
                     'released': [list(x) for x in released[:20]], 'removed_in_memory': [list(x) for x in back[:20]]}
    if back:
        res['wrong'] = True
        res['detail'] = ('xapi still holds %s, which the edit removed: it did not start from the edited file, so the '
                         'edit is not in effect' % ', '.join('%s of %s' % (x[2], x[1]) for x in back[:4]))
        return res
    if want and not (want & mem) and not released and not log_ok:
        res['failed'] = True
        res['detail'] = ('xapi holds none of the %d datapath(s) in the file it was started with, and its log shows '
                         'no load of it: it started with a blank storage state' % len(want))
        return res
    if unexplained:
        res['detail'] = ('xapi does not hold %d of the %d datapath(s) in the file it was started with (%s), and its '
                         'log shows no release of them since, so a whole load of the file is not established'
                         % (len(unexplained), len(want), ', '.join('%s of %s' % (x[2], x[1]) for x in unexplained[:4])))
        return res
    if log_ok:
        res['established'] = True
        return res
    if want and (lines is None or not covered):
        res['established'] = True
        res['detail'] = ('its log could not be read back to the start, but xapi holds every one of the %d datapath(s) '
                         'in the file' % len(want))
        return res
    if lines is None or not covered:
        res['detail'] = ('its log could not be read back to the start, and the file holds no datapath to look for in '
                         'its memory')
    else:
        res['detail'] = ('its log shows no load of the file since xapi was started%s' % (
            '' if not want else ', although it holds every datapath in the file'))
    return res


def guardian_alive(d):
    try:
        rec = read_json(os.path.join(d, 'guardian.json'))
        return pid_alive(rec['pid'], rec['start'], boot_time())
    except (EnvironmentError, ValueError, KeyError):
        return False


def act_main(spec_path):
    socket.setdefaulttimeout(API_TIMEOUT)
    d = os.path.dirname(spec_path)
    spec = read_json(spec_path)
    apply_paths(spec.get('paths'))
    for s in (signal.SIGHUP, signal.SIGINT, signal.SIGTERM):
        signal.signal(s, signal.SIG_IGN)
    protect_self()
    record_self(d, 'action')
    write_status(d, 'starting', detail='action pid %d' % os.getpid())
    act_log(d, 'action %s on %s: removing %d datapath(s) from %s'
            % (spec['run_id'], spec['hostname'], len(spec['items']), STORAGE_DB))
    gpid = spawn_detached([sys.executable, os.path.join(d, 'agent.py'), '--ssf-guard', spec_path],
                          os.path.join(d, 'guardian.out'))
    deadline = _now() + 15
    while not guardian_alive(d):
        if _now() > deadline:
            write_status(d, 'refused', detail='the guardian (pid %d) did not start' % gpid)
            return 1
        time.sleep(0.2)
    lockfd = None
    state = {'stopped': False, 'written': False, 'backup': None, 'old': None, 'error': None, 'issued': None}
    try:
        lockfd, lockpath = toolstack_flock()
        if lockfd is None:
            write_status(d, 'refused', detail='%s is held: xe-toolstack-restart is running' % lockpath)
            return 1
        units = active_units()
        write_json_atomic(os.path.join(d, 'units.json'), {'units': units})
        problems = local_recheck(spec)
        if not guardian_alive(d):
            problems.append('the guardian is not running')
        if problems:
            write_status(d, 'refused', detail='; '.join(problems))
            act_log(d, 'refused: %s' % '; '.join(problems))
            return 1
        write_status(d, 'stopping', detail='stopping xapi')
        act_log(d, 'stopping xapi')
        state['stopped'] = True
        stop_xapi_local(d)
        safe_status(d, 'stopped', detail='xapi is stopped; re-proving every item')
        late = post_stop_problems(spec)
        data = read_file(STORAGE_DB)
        obj = None
        if late:
            why = 'after xapi stopped: %s' % '; '.join(late[:6])
            safe_status(d, 'stopped', detail='nothing written: %s' % why, skipped=why)
            act_log(d, 'nothing written: %s' % why)
        else:
            try:
                obj = json.loads(data.decode('utf-8'))
                plan_from_file(obj, spec)
            except (ValueError, SchemaError, Failed, KeyError) as exc:
                safe_status(d, 'stopped', detail='nothing written: %s' % _text(exc), skipped=_text(exc))
                act_log(d, 'nothing written: %s' % _text(exc))
                obj = None
        if obj is not None:
            st = os.statvfs(d)
            if st.f_bavail * st.f_frsize < 2 * len(data) + (1 << 20):
                raise Failed('%s has no room for the backup' % d)
            backup = os.path.join(d, 'storage.db.%s.bak' % time.strftime('%Y%m%d-%H%M%S'))
            write_new(backup, data)
            state['backup'] = backup
            new, removed, gone = edit_storage_db(obj, spec)
            verify_edit(obj, new, spec)
            payload = dump_storage_db(new)
            if read_file(STORAGE_DB) != data:
                raise Failed('%s changed while xapi was stopped' % STORAGE_DB)
            if not xapi_stopped():
                raise Failed('xapi is running again: nothing written')
            write_status(d, 'writing', detail='writing %s' % STORAGE_DB, backup=backup,
                         written_sha256=sha256_bytes(payload))
            state['old'] = data
            state['new'] = new
            state['written_sha'] = sha256_bytes(payload)
            state['written'] = True
            replace_file(STORAGE_DB, payload)
            back = json.loads(read_text(STORAGE_DB))
            if canon(back) != canon(new):
                raise Failed('%s does not parse back as the edited document' % STORAGE_DB)
            verify_edit(obj, back, spec)
            safe_status(d, 'writing', detail='written and verified', removed=removed, removed_entries=gone)
            act_log(d, 'removed %s' % ', '.join('%s of %s' % (r[2], r[1]) for r in removed))
    except Exception as exc:
        state['error'] = _text(exc)
        act_log(d, 'error: %s' % _text(exc))
        if state['written'] and state['old'] is not None and xapi_stopped():
            try:
                replace_file(STORAGE_DB, state['old'])
                state['written'] = False
                act_log(d, 'the original %s is back' % STORAGE_DB)
            except Exception as exc2:
                act_log(d, 'cannot put the original back: %s' % _text(exc2))
        if not state['stopped']:
            safe_status(d, 'failed', detail='error before xapi was stopped: %s' % _text(exc), error=_text(exc))
    finally:
        if state['stopped']:
            finish_start(d, state, spec)
        if lockfd is not None:
            try:
                os.close(lockfd)
            except OSError:
                pass
    return 0


def _start(d, units):
    try:
        return start_xapi_local(d, units)
    except Exception as exc:
        return {'ready': False, 'answering': False, 'complete': False, 'detail': _text(exc), 'issued': time.time()}


def spec_removed(spec):
    return [[i['sr'], i['vdi'], i['dp']] for i in (spec or {}).get('items') or []]


def roll_back(d, old, units, why, host_uuid, written_sha):
    act_log(d, '%s: rolling back' % why)
    rb = {'ok': False, 'restored': False, 'note': None, 'start': None, 'load': None}
    if not xapi_stopped():
        problems = ha_stop_problems()
        if problems:
            rb['note'] = 'xapi was not stopped for it, because %s' % '; '.join(problems)
            rb['start'] = {'ready': False, 'answering': False, 'complete': False, 'detail': 'xapi was left running'}
            act_log(d, 'no rollback: %s' % rb['note'])
            return rb
        if _ENSURE_END[0] is not None and _ENSURE_END[0] - _now() < STOP_TIMEOUT + GONE_WAIT + START_TIMEOUT + 60:
            rb['deferred'] = True
            rb['note'] = ('xapi was not stopped for it: too little of this call\'s time is left to stop xapi and start '
                          'it again before the call is given up; run recover again to finish it')
            rb['start'] = {'ready': False, 'answering': False, 'complete': False, 'detail': 'xapi was left running'}
            act_log(d, 'no rollback yet: %s' % rb['note'])
            return rb
    try:
        stop_xapi_local(d)
        cur = read_file(STORAGE_DB)
        if cur == old:
            rb['restored'] = True
        elif sha256_bytes(cur) != written_sha:
            rb['note'] = ('%s was written again after the rollback was decided, so it is left as it is (the backup '
                          'stays in the run record)' % STORAGE_DB)
        else:
            replace_file(STORAGE_DB, old)
            rb['restored'] = True
    except Exception as exc:
        rb['note'] = 'the original could not be put back: %s' % _text(exc)
    if rb['note']:
        act_log(d, rb['note'])
    if xapi_stopped():
        rb['start'] = _start(d, units)
    else:
        rb['start'] = {'ready': False, 'answering': False, 'complete': False,
                       'detail': 'xapi did not stop for the rollback, so it was not started again'}
    if rb['restored'] and rb['start'].get('ready'):
        try:
            rb['load'] = verify_loaded(rb['start']['issued'], json.loads(old.decode('utf-8')), host_uuid)
        except Exception as exc:
            rb['load'] = {'failed': False, 'established': False, 'detail': _text(exc)}
    rb['ok'] = bool(rb['restored'] and rb['start'].get('answering') and rb['load'] is not None and
                    not rb['load']['failed'] and rb['load']['established'])
    return rb


def rollback_text(rb):
    if rb['ok']:
        return 'the original is back, and xapi is up and loaded it'
    parts = ['the original was %s' % ('put back' if rb['restored'] else 'NOT put back')]
    if rb['note']:
        parts.append(rb['note'])
    parts.append('after the rollback: %s' % (rb['start'].get('detail') or 'xapi answering'))
    if rb['load'] is not None:
        parts.append('load: %s' % (rb['load'].get('detail') or 'established'))
    return '; '.join(parts)


def rollback_status(d, rb, why, **extra):
    fields = dict(extra, start_after_rollback=rb['start'], load_after_rollback=rb['load'])
    if not rb['ok']:
        fields['error'] = 'rollback incomplete'
    safe_status(d, 'rolled-back' if rb['ok'] else 'failed', detail='%s; %s' % (why, rollback_text(rb)), **fields)


def finish_start(d, state, spec):
    try:
        units = read_json(os.path.join(d, 'units.json')).get('units')
    except (EnvironmentError, ValueError):
        units = None
    res = _start(d, units)
    edited = state['written'] and state['old'] is not None
    why = None
    if edited and not res['ready']:
        why = 'xapi did not come up with the edited file (%s)' % res['detail']
    elif edited:
        try:
            load = verify_loaded(res['issued'], state['new'], spec['host_uuid'], spec_removed(spec))
        except Exception as exc:
            load = {'failed': False, 'established': False, 'detail': 'the load check failed: %s' % _text(exc)}
        res['load'] = load
        if load['failed']:
            why = 'xapi did not load the edited file: %s' % load['detail']
        elif not load['established']:
            state['unverified'] = 'the edited file is written, but %s' % load['detail']
    if why is not None:
        rb = roll_back(d, state['old'], units, why, spec['host_uuid'], state.get('written_sha'))
        rollback_status(d, rb, why, start=res)
        return
    if state.get('error') or not res['answering']:
        final = 'failed'
    elif state.get('unverified'):
        final = 'unverified'
    else:
        final = 'done'
    detail = res['detail'] or 'xapi is up and answering'
    if state.get('error'):
        detail = 'error: %s; then %s' % (state['error'], detail)
    elif state.get('unverified'):
        detail = ('%s, so whether xapi loaded it is checked again by settle or recover; xapi: %s'
                  % (state['unverified'], detail))
    safe_status(d, final, detail=detail, start=res)
    act_log(d, 'finished: %s (%s)' % (final, res['detail'] or 'xapi answering'))


def guard_main(spec_path):
    d = os.path.dirname(spec_path)
    spec = read_json(spec_path)
    apply_paths(spec.get('paths'))
    for s in (signal.SIGHUP, signal.SIGINT, signal.SIGTERM):
        signal.signal(s, signal.SIG_IGN)
    protect_self()
    action = read_json(os.path.join(d, 'action.json'))
    btime = boot_time()
    record_self(d, 'guardian')
    started = _now()
    warned = False
    seen, since, stalled = None, _now(), False
    while True:
        try:
            st = read_status(d)
            if st is not None and st.get('state') in ACT_ENDS:
                return 0
            if not pid_alive(action['pid'], action['start'], btime):
                return guard_takeover(d, spec)
            sig = progress_sig(d, action['pid'])
            if sig != seen:
                seen, since = sig, _now()
                if stalled:
                    stalled = False
                    act_log(d, 'guardian: the action, pid %d, makes progress again' % action['pid'])
                    backstop_note(d, action['pid'], stalled=False)
            elif not stalled and _now() - since > GUARDIAN_STALL:
                stalled = True
                how = proc_note(action['pid'])
                act_log(d, 'guardian: the action, pid %d, has made no progress for %ds (state %s; %s). It is not '
                        'touched: if it is hung, kill -9 %d and this guardian takes over'
                        % (action['pid'], GUARDIAN_STALL, (st or {}).get('state'), how, action['pid']))
                backstop_note(d, action['pid'], stalled=True, since=time.time() - (_now() - since),
                              state=(st or {}).get('state'), proc=how)
            if not warned and _now() - started > GUARDIAN_BACKSTOP:
                warned = True
                act_log(d, 'guardian: the action, pid %d, is still alive after %ds; it is not touched. If it is hung, '
                        'kill -9 %d: this guardian then takes over' % (action['pid'], GUARDIAN_BACKSTOP, action['pid']))
                backstop_note(d, action['pid'], late=True)
        except Exception as exc:
            act_log(d, 'guardian: %s' % _text(exc))
        time.sleep(GUARDIAN_POLL)


def backstop_note(d, pid, **fields):
    path = os.path.join(d, 'backstop.json')
    try:
        cur = read_json(path)
    except (EnvironmentError, ValueError):
        cur = {}
    cur.update(fields)
    cur.update({'time': time.time(), 'action_pid': pid, 'guardian_pid': os.getpid()})
    write_json_atomic(path, cur)


def tree_ticks(root, skip=()):
    kids = collections.defaultdict(list)
    ticks = {}
    for pid in pids():
        if pid in skip:
            continue
        try:
            data = read_text('%s/%d/stat' % (PROC, pid))
            rest = data[data.rindex(')') + 2:].split()
            kids[int(rest[1])].append(pid)
            ticks[pid] = int(rest[11]) + int(rest[12])
        except (EnvironmentError, ValueError, IndexError):
            continue
    total, todo, seen = 0, [root], set()
    while todo:
        p = todo.pop()
        if p in seen:
            continue
        seen.add(p)
        total += ticks.get(p, 0)
        todo.extend(kids.get(p, []))
    return total, len(seen)


def progress_sig(d, pid):
    try:
        st = os.stat(os.path.join(d, 'status.json'))
        out = [[st.st_mtime, st.st_size]]
    except OSError:
        out = [None]
    out.append(list(tree_ticks(pid, skip=(os.getpid(),))))
    out.append(proc_io(pid))
    return canon(out)


def proc_note(pid):
    try:
        st = proc_stat(pid)
    except (EnvironmentError, ValueError, IndexError) as exc:
        return 'its state cannot be read: %s' % _text(exc)
    try:
        wchan = read_text('%s/%d/wchan' % (PROC, pid)).strip()
    except EnvironmentError:
        wchan = ''
    return 'process state %s%s' % (st['state'], (', waiting in %s' % wchan) if wchan and wchan != '0' else '')


def edited_by_action(st, log_dir, who):
    backup = (st or {}).get('backup')
    if not backup:
        return None, None, None
    try:
        old = read_file(backup)
        cur = read_file(STORAGE_DB)
    except EnvironmentError as exc:
        act_log(log_dir, '%s: the backup or the file cannot be compared: %s' % (who, _text(exc)))
        return None, None, None
    if cur == old:
        return None, None, None
    if sha256_bytes(cur) != st.get('written_sha256'):
        note = ('%s is neither the backup nor the file the action wrote: it was written again since, so it is not '
                'rolled back (the backup is %s)' % (STORAGE_DB, backup))
        act_log(log_dir, '%s: %s' % (who, note))
        return None, None, note
    try:
        return old, json.loads(cur.decode('utf-8')), None
    except ValueError as exc:
        act_log(log_dir, '%s: the file the action wrote does not parse: %s' % (who, _text(exc)))
        return None, None, None


def xapi_left_as_is(state):
    deadline = _now() + ANSWER_WAIT
    while True:
        try:
            xp = pids_named(b'xapi')
        except Failed as exc:
            return 'the xapi processes cannot be listed (%s)' % _text(exc)
        if state == 'active' and len(xp) == 1 and xapi_answers():
            return None
        if _now() > deadline:
            break
        time.sleep(POLL)
        state = xapi_unit_state()
    if state == 'active' and len(xp) == 1:
        return 'xapi is running (pid %d) but its CLI did not answer within %ds' % (xp[0], ANSWER_WAIT)
    return 'xapi is %s, with xapi pid(s) %s' % (state, ', '.join(str(p) for p in xp) or 'none')


STORAGE_OK = ('verified', 'restored', 'n/a')
SETTLED_STATES = ('done', 'refused', 'rolled-back')


def storage_verdict(st, spec, start=None):
    st = st or {}
    backup, written = st.get('backup'), st.get('written_sha256')
    if not backup or not written:
        return {'verdict': 'n/a', 'detail': 'the action wrote nothing to %s' % STORAGE_DB, 'load': None}
    try:
        old = read_file(backup)
        cur = read_file(STORAGE_DB)
        old_obj = json.loads(old.decode('utf-8'))
    except (EnvironmentError, ValueError) as exc:
        return {'verdict': 'unverified', 'load': None,
                'detail': 'the backup %s or %s cannot be read (%s), so what xapi holds cannot be checked'
                          % (backup, STORAGE_DB, _text(exc))}
    if start is None:
        try:
            start = f_xapi_state().get('start')
        except Exception:
            start = None
    if start is None:
        return {'verdict': 'unverified', 'load': None,
                'detail': 'the start time of the running xapi cannot be read, so whether it loaded %s is not '
                          'established' % STORAGE_DB}
    original = cur == old
    rewritten = not original and sha256_bytes(cur) != written
    try:
        if original:
            load = verify_loaded(start, old_obj, spec['host_uuid'])
        else:
            load = verify_loaded(start, edit_storage_db(old_obj, spec)[0], spec['host_uuid'], spec_removed(spec))
    except Exception as exc:
        return {'verdict': 'unverified', 'load': None, 'original': original, 'rewritten': rewritten,
                'detail': 'the load check failed: %s' % _text(exc)}
    if load.get('wrong'):
        verdict = 'wrong'
    elif load['failed']:
        verdict = 'failed'
    elif load['established']:
        verdict = 'restored' if original else 'verified'
    else:
        verdict = 'unverified'
    if original:
        what = 'the original %s is back in place' % STORAGE_DB
    elif rewritten:
        what = '%s was written again by xapi since the action edited it' % STORAGE_DB
    else:
        what = '%s is the file the action wrote' % STORAGE_DB
    if verdict in ('verified', 'restored'):
        detail = '%s, and xapi holds what it says%s' % (what, (': %s' % load['detail']) if load['detail'] else '')
    else:
        detail = '%s, but %s' % (what, load['detail'])
    return {'verdict': verdict, 'detail': detail, 'load': load, 'original': original, 'rewritten': rewritten}


def verdict_state(v, fallback='failed'):
    return {'verified': 'done', 'restored': 'rolled-back', 'failed': 'failed', 'n/a': fallback}.get(v['verdict'],
                                                                                                    'unverified')


def verdict_fields(v, spec, **fields):
    if v['verdict'] == 'verified':
        fields['removed'] = spec_removed(spec)
    return fields


def check_running(d, st, units, spec, who):
    v = storage_verdict(st, spec)
    if v['verdict'] != 'failed' or v.get('original') or v.get('rewritten'):
        return v, None
    try:
        old = read_file(st['backup'])
    except (EnvironmentError, KeyError) as exc:
        v['detail'] += '; the backup cannot be read to roll back (%s)' % _text(exc)
        return v, None
    rb = roll_back(d, old, units, '%s: the running xapi did not load the edited file: %s' % (who, v['detail']),
                   spec['host_uuid'], st.get('written_sha256'))
    return v, rb


def guard_takeover(d, spec):
    st = read_status(d)
    if st is not None and st.get('state') in ACT_ENDS:
        return 0
    was = (st or {}).get('state')
    if was == 'starting':
        safe_status(d, 'failed', detail='the action died before it stopped xapi (guardian)')
        return 0

    def waiting_note(path):
        safe_status(d, 'guardian-waiting', detail='the action died in state %s; the guardian waits for %s, which '
                    'another process holds, before it touches xapi' % (was, path))
        act_log(d, 'guardian: the action died in state %s; waiting for %s' % (was, path))
    lockfd, lockpath = toolstack_flock(GUARD_LOCK_WAIT, waiting_note)
    if lockfd is None:
        safe_status(d, 'unverified', detail='the action died in state %s, and %s stayed held by another process for '
                    '%ds (xe-toolstack-restart or another tool restarting xapi), so the guardian left xapi to it; '
                    'settle or recover checks xapi and the edit once it is free' % (was, lockpath, GUARD_LOCK_WAIT))
        act_log(d, 'guardian: %s stayed held for %ds: xapi left to its holder' % (lockpath, GUARD_LOCK_WAIT))
        return 0
    try:
        return guard_locked(d, spec, st, was)
    finally:
        os.close(lockfd)


def guard_locked(d, spec, st, was):
    state = settle_xapi_jobs(STOP_TIMEOUT + GONE_WAIT)
    try:
        units = read_json(os.path.join(d, 'units.json')).get('units')
    except (EnvironmentError, ValueError):
        units = None
    wrote = bool((st or {}).get('backup') and (st or {}).get('written_sha256'))
    if not xapi_stopped():
        left = xapi_left_as_is(state)
        if left is not None:
            safe_status(d, 'unverified' if wrote else 'failed',
                        detail='the action died in state %s; %s, so the guardian left it as it is%s'
                        % (was, left, ('; whether it loaded the edited file is checked again by settle or recover'
                                       if wrote else '')))
            act_log(d, 'guardian: the action died in state %s; %s: left as it is' % (was, left))
            return 0
        v, rb = check_running(d, st or {}, units, spec, 'guardian')
        if rb is not None:
            rollback_status(d, rb, 'the action died in state %s; xapi was running but did not load the edited file'
                            % was, guardian_storage=v)
            return 0
        safe_status(d, verdict_state(v), **verdict_fields(
            v, spec, guardian_storage=v, detail='the action died in state %s; xapi was running; %s' % (was, v['detail'])))
        return 0
    old, edited, note = edited_by_action(st, d, 'guardian')
    res = _start(d, units)
    if edited is not None and not res['ready']:
        why = 'the action died in state %s; xapi did not come up with the edited file (%s)' % (was, res['detail'])
        rb = roll_back(d, old, units, 'guardian: ' + why, spec['host_uuid'], st.get('written_sha256'))
        rollback_status(d, rb, why, guardian_start=res)
        return 0
    if not res['ready']:
        safe_status(d, 'unverified' if wrote else 'failed', detail='the action died in state %s; the guardian '
                    'started xapi, but %s' % (was, res['detail']), guardian_start=res)
        act_log(d, 'guardian: the action died in state %s; xapi start: %s' % (was, res['detail']))
        return 0
    v = storage_verdict(st, spec, start=res['issued'])
    res['storage'] = v
    if v['verdict'] == 'failed' and edited is not None:
        why = 'the action died in state %s; xapi did not load the edited file (%s)' % (was, v['detail'])
        rb = roll_back(d, old, units, 'guardian: ' + why, spec['host_uuid'], st.get('written_sha256'))
        rollback_status(d, rb, why, guardian_start=res)
        return 0
    safe_status(d, verdict_state(v), **verdict_fields(
        v, spec, guardian_start=res, detail='the action died in state %s; the guardian started xapi (%s); %s%s' % (
            was, res['detail'] or 'xapi answering', v['detail'], ('; ' + note) if note else '')))
    act_log(d, 'guardian: the action died in state %s; started xapi: %s' % (was, res['detail'] or 'answering'))
    return 0


INERT_MARK = b'storage-state-fixer: inert backend node\n'


def phy_record(sr, vdi):
    for rec in f_phy():
        if rec['sr'] == sr and rec['vdi'] == vdi:
            return rec
    return None


def sm_vdi_lock(vdi):
    import fcntl
    d = os.path.join(SM_LOCK_DIR, vdi)
    try:
        os.makedirs(d)
    except OSError as exc:
        if exc.errno != errno.EEXIST:
            raise
    fd = os.open(os.path.join(d, 'vdi'), os.O_RDWR | os.O_CREAT, 0o666)
    try:
        fcntl.lockf(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except (IOError, OSError):
        os.close(fd)
        return None
    return fd


def agent_inert_node(args, source):
    sr, vdi = args['sr'], args['vdi']
    if not UUID_RE.match(sr) or not UUID_RE.match(vdi):
        raise Failed('bad SR or VDI uuid')
    lockfd = sm_vdi_lock(vdi)
    if lockfd is None:
        return {'done': False, 'problems': ['SM holds the lock of VDI %s: an SM operation on it is running' % vdi]}
    try:
        return inert_locked(args, sr, vdi)
    finally:
        os.close(lockfd)


def inert_locked(args, sr, vdi):
    exp = args['expect']
    path = os.path.join(SM_BACKEND, sr, vdi)
    try:
        st = os.lstat(path)
    except OSError as exc:
        if exc.errno == errno.ENOENT:
            return {'done': False, 'already': True, 'gone': True, 'problems': [], 'detail': '%s is gone' % path}
        raise
    if stat.S_ISREG(st.st_mode) and read_file(path).startswith(INERT_MARK):
        return {'done': False, 'already': True, 'problems': [], 'detail': '%s is already inert' % path}
    if not stat.S_ISBLK(st.st_mode):
        return {'done': False, 'problems': ['%s is no longer a block node' % path]}
    rdev = [os.major(st.st_rdev), os.minor(st.st_rdev)]
    problems = []
    if rdev != exp['rdev'] or st.st_ino != exp['ino']:
        problems.append('%s is %d:%d inode %d now, not the %d:%d inode %d audited'
                        % (path, rdev[0], rdev[1], st.st_ino, exp['rdev'][0], exp['rdev'][1], exp['ino']))
    tapmaj = proc_devices().get(('b', 'tapdev'))
    if tapmaj is None or rdev[0] != tapmaj:
        problems.append('its major %d is not the tapdev major %s' % (rdev[0], tapmaj))
    phy = phy_record(sr, vdi)
    target = (phy or {}).get('target')
    try:
        rows = f_tapdisks()
    except Exception as exc:
        return {'done': False, 'problems': ['tap-ctl list: %s' % _text(exc)]}
    for row in image_rows(rows, vdi, target):
        problems.append('tapdisk pid %s minor %s serves this VDI' % (row['pid'], row['minor']))
    for row in rows:
        if row.get('pid') is not None and (row.get('minor') is None or not row.get('path')):
            problems.append('tapdisk pid %s %s, so whether it serves this VDI is not established'
                            % (row['pid'], unmapped_why(row)))
    at = [r for r in rows if r['minor'] == rdev[1] and r['pid'] is not None]
    if at and not target and not args.get('path_sr'):
        problems.append('it has no phy link, so whose image tapdisk pid %s minor %s serves is not established'
                        % (at[0]['pid'], rdev[1]))
    for r in at:
        if r['state'] is None or r['state'] & ~LOG_DROPPED:
            problems.append('tapdisk pid %s, which now holds tap minor %d, is in state %s, not running: if it was '
                            'paused through this stale node, its unpause needs the node, so the node is left as it is'
                            % (r['pid'], rdev[1], tap_state_text(r['state'])))
    rx = run([XENSTORE_LS, '-f', '/local/domain/0/backend'], 20)
    if not rx.ok:
        problems.append('xenstore-ls %s' % rx.why())
    else:
        for k, v in parse_xenstore(rx.out).items():
            if k.endswith('/params') and v in (path, (phy or {}).get('target')):
                problems.append('xenstore %s = %s' % (k, v))
    node_rec = {'sr': sr, 'vdi': vdi, 'kind': 'block', 'rdev': rdev}
    blk = {'blktap': {}, 'tapdev': {}}
    try:
        holders = bounded(f_openers, SCAN_BUDGET + 5, [node_rec], [phy] if phy else [], blk)
        for h in holders:
            if h.get('unread'):
                problems.append('the open files of pid %d (%s) could not all be read (%s), so whether it holds this '
                                'node is not established' % (h['pid'], h.get('comm') or '?', h['unread']))
            for x in h['hits']:
                if x['target'] == path or x['target'] == os.path.join(SM_PHY, sr, vdi) or \
                        (target and x['target'] in path_variants(target)) or \
                        (not at and x.get('rdev') == ['b'] + rdev) or \
                        (phy and phy.get('kind') == 'block' and x.get('rdev') == ['b'] + phy['rdev']):
                    problems.append('pid %d (%s) holds %s' % (h['pid'], h['comm'], x['target']))
    except Exception as exc:
        problems.append('the fd scan: %s' % _text(exc))
    try:
        kh = bounded(f_kholders, SCAN_BUDGET, [node_rec] if not at else [], [phy] if phy else [], {})
        for key, rec in kh['devs'].items():
            problems.extend(rec['users'])
        for l in kh['loops']:
            if l['file'] in (path, target):
                problems.append('loop device %s is backed by %s' % (l['loop'], l['file']))
    except Exception as exc:
        problems.append('the kernel holder scan: %s' % _text(exc))
    if problems:
        return {'done': False, 'problems': problems}
    served = None
    if at:
        served = {'pid': at[0]['pid'], 'minor': at[0]['minor'], 'type': at[0].get('type'), 'path': at[0].get('path')}
    note = {'run': args.get('run_id'), 'sr': sr, 'vdi': vdi, 'was': {'rdev': rdev, 'ino': st.st_ino,
            'mode': st.st_mode, 'mtime': st.st_mtime, 'uid': st.st_uid, 'gid': st.st_gid},
            'minor_serves': served, 'time': time.time()}
    tmp = os.path.join(SM_BACKEND, '.ssf-inert-%d-%s' % (os.getpid(), vdi[:8]))
    _unlink_quietly(tmp)
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        data = INERT_MARK + json.dumps(note, sort_keys=True).encode('utf-8') + b'\n'
        append_all(fd, data)
    finally:
        os.close(fd)
    try:
        st2 = os.lstat(path)
        if not stat.S_ISBLK(st2.st_mode) or st2.st_rdev != st.st_rdev or st2.st_ino != st.st_ino:
            _unlink_quietly(tmp)
            return {'done': False, 'problems': ['%s changed while it was being checked' % path]}
        os.rename(tmp, path)
    except OSError:
        _unlink_quietly(tmp)
        raise
    st3 = os.lstat(path)
    done = stat.S_ISREG(st3.st_mode) and read_file(path).startswith(INERT_MARK)
    return {'done': done, 'problems': [] if done else ['%s does not read back as the inert file' % path],
            'was': note['was'], 'minor_serves': served}


FENCE_TAG_RE = re.compile(r'^[a-z0-9-]{1,40}$')
FENCE_ENDS = ('released', 'refused', 'acted', 'failed', 'lost')


def fence_dir(run_id, host_uuid, tag):
    if not RUN_ID_RE.match(run_id or '') or not UUID_RE.match(host_uuid or '') or not FENCE_TAG_RE.match(tag or ''):
        raise Failed('bad run id, host uuid or fence tag')
    return os.path.join(RUN_ROOT, 'runs', run_id, 'fence-%s-%s' % (host_uuid[:8], tag))


def lock_holder(fd):
    import fcntl
    import struct
    try:
        got = fcntl.fcntl(fd, fcntl.F_GETLK, struct.pack('hhqql', fcntl.F_WRLCK, 0, 0, 0, 0))
        fields = struct.unpack('hhqql', got)
    except (IOError, OSError, struct.error):
        return None
    return None if fields[0] == fcntl.F_UNLCK else fields[4]


def try_sm_lock(ns, name, until):
    import fcntl
    if not UUID_RE.match(ns or '') or name not in ('vdi', 'sr', 'gc_active'):
        raise Failed('not an SM lock: %s/%s' % (ns, name))
    d = os.path.join(SM_LOCK_DIR, ns)
    try:
        os.makedirs(d)
    except OSError as exc:
        if exc.errno != errno.EEXIST:
            raise
    path = os.path.join(d, name)
    fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o644)
    while True:
        try:
            fcntl.lockf(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return fd, None
        except (IOError, OSError) as exc:
            if exc.errno not in (errno.EACCES, errno.EAGAIN):
                os.close(fd)
                raise
        if _now() >= until:
            holder = lock_holder(fd)
            os.close(fd)
            return None, 'pid %s' % holder if holder else 'another process'
        time.sleep(FENCE_POLL)


def fence_locks(locks):
    out = []
    for lk in locks or []:
        if not (isinstance(lk, list) and len(lk) == 2 and lk[0] in ('vdi', 'gc') and UUID_RE.match(lk[1] or '')):
            raise Failed('not a lock this tool takes: %s' % canon(lk))
        out.append((lk[0], lk[1]))
    if not out:
        raise Failed('no lock to take')
    return out


def take_fence(locks, until):
    import fcntl
    held = []
    try:
        for kind, uuid in locks:
            if kind == 'vdi':
                fd, who = try_sm_lock(uuid, 'vdi', until)
                if fd is None:
                    return held, 'SM holds the lock of VDI %s (%s): an SM operation on it runs' % (uuid, who)
                held.append(fd)
                continue
            while True:
                srfd, who = try_sm_lock(uuid, 'sr', until)
                if srfd is None:
                    return held, 'SM holds the lock of SR %s (%s): an SM operation on the SR runs' % (uuid, who)
                try:
                    fd, who = try_sm_lock(uuid, 'gc_active', 0)
                finally:
                    try:
                        fcntl.lockf(srfd, fcntl.LOCK_UN)
                    finally:
                        os.close(srfd)
                if fd is not None:
                    break
                if _now() >= until:
                    return held, 'the GC of SR %s holds gc_active (%s): it runs' % (uuid, who)
                time.sleep(FENCE_POLL)
            held.append(fd)
        return held, None
    except Exception:
        for fd in held:
            os.close(fd)
        raise


def fence_paths(locks):
    return [os.path.join(SM_LOCK_DIR, uuid, 'vdi' if kind == 'vdi' else 'gc_active') for kind, uuid in locks]


def fence_unlinked(held, paths):
    for fd, path in zip(held, paths):
        try:
            a = os.fstat(fd)
            b = os.stat(path)
        except OSError as exc:
            if not gone(exc) and exc.errno != errno.ENOTDIR:
                raise
            return 'the lock file %s was removed' % path
        if a.st_nlink == 0 or (a.st_dev, a.st_ino) != (b.st_dev, b.st_ino):
            return 'the lock file %s was removed or replaced' % path
    return None


def agent_fence_start(args, source):
    spec = args['spec']
    fence_locks(spec['locks'])
    d = fence_dir(spec['run_id'], spec['host_uuid'], spec['tag'])
    if not os.path.isdir(d):
        os.makedirs(d, 0o700)
    spec_path = os.path.join(d, 'spec.json')
    fd = os.open(spec_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        append_all(fd, json.dumps(spec, sort_keys=True).encode('utf-8'))
        os.fsync(fd)
    finally:
        os.close(fd)
    agent_path = os.path.join(d, 'agent.py')
    write_new(agent_path, source, 0o700)
    pid = spawn_detached([sys.executable, agent_path, '--ssf-fence', spec_path], os.path.join(d, 'fence.out'))
    deadline = _now() + FENCE_ACQUIRE + 10
    while _now() < deadline:
        st = read_status(d)
        if st is not None and st.get('state') not in ('starting', 'acquiring'):
            break
        time.sleep(0.1)
    return fence_report(d, pid)


def fence_report(d, pid=None):
    st = read_status(d)
    try:
        rec = read_json(os.path.join(d, 'fence.json'))
    except (EnvironmentError, ValueError):
        rec = None
    alive = None
    if rec is not None:
        alive = pid_alive(rec['pid'], rec['start'], boot_time())
        pid = rec['pid']
    elif pid is not None:
        alive = pid_alive(pid)
    left = None
    if st is not None and st.get('until') is not None:
        left = st['until'] - time.time()
    return {'status': st, 'alive': alive, 'pid': pid, 'left': left, 'dir': d}


def agent_fence_status(args, source):
    return fence_report(fence_dir(args['run_id'], args['host_uuid'], args['tag']))


def agent_fence_release(args, source):
    d = fence_dir(args['run_id'], args['host_uuid'], args['tag'])
    if os.path.isdir(d):
        with open(os.path.join(d, 'release'), 'w'):
            pass
    deadline = _now() + 10
    while True:
        rep = fence_report(d)
        if not rep['alive'] or (rep['status'] or {}).get('state') in FENCE_ENDS or _now() > deadline:
            return rep
        time.sleep(0.1)


def fence_main(spec_path):
    d = os.path.dirname(spec_path)
    spec = read_json(spec_path)
    apply_paths(spec.get('paths'))
    signal.signal(signal.SIGHUP, signal.SIG_IGN)
    signal.signal(signal.SIGINT, signal.SIG_IGN)
    hold = min(float(spec.get('hold') or FENCE_HOLD), 300.0)
    action = spec.get('action')
    if not action and hasattr(signal, 'alarm'):
        signal.alarm(int(FENCE_ACQUIRE + hold + 60))
    record_self(d, 'fence')
    write_status(d, 'acquiring', detail='taking %s' % canon(spec['locks']))
    held = []
    final = None
    try:
        locks = fence_locks(spec['locks'])
        held, why = take_fence(locks, _now() + FENCE_ACQUIRE)
        if why:
            final = ('refused', {'detail': why})
            return 0
        paths = fence_paths(locks)
        lost = fence_unlinked(held, paths)
        if lost:
            final = ('refused', {'detail': '%s while it was taken, so holding it keeps nobody out' % lost})
            return 0
        if action:
            write_status(d, 'acting', detail='%s under %s' % (action.get('kind'), canon(spec['locks'])))
            res = fence_action(action)
            final = ('acted', {'detail': res.get('detail') or '', 'result': res})
            return 0
        write_status(d, 'held', detail='holding %s' % canon(spec['locks']), until=time.time() + hold)
        end = _now() + hold
        release = os.path.join(d, 'release')
        while _now() < end and not os.path.exists(release):
            lost = fence_unlinked(held, paths)
            if lost:
                final = ('lost', {'detail': '%s (SM does that when the VDI or the SR is deleted, or an LVM SR is '
                                            'detached from a pool member), so holding it keeps nobody out' % lost,
                                  'until': None})
                return 0
            time.sleep(FENCE_POLL)
        final = ('released', {'detail': 'released on request' if os.path.exists(release) else
                              'released at the end of its %ds hold' % hold, 'until': None})
        return 0
    except Exception as exc:
        final = ('failed', {'detail': '%s: %s' % (exc.__class__.__name__, _text(exc)), 'until': None})
        return 1
    finally:
        for fd in held:
            try:
                os.close(fd)
            except OSError:
                pass
        if final is not None:
            safe_status(d, final[0], **final[1])


def fence_action(action):
    if action.get('kind') != 'unpause':
        raise Failed('unknown fence action %s' % canon(action.get('kind')))
    return unpause_locked(action)


def plugin_handler(src, fn):
    for node in ast.walk(ast.parse(src)):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == 'dispatch' \
                and node.args and isinstance(node.args[0], ast.Dict):
            for k, v in zip(node.args[0].keys, node.args[0].values):
                if _ast_str(k) == fn and isinstance(v, ast.Name):
                    return v.id
    return None


def load_plugin(path):
    import importlib.machinery
    import importlib.util
    loader = importlib.machinery.SourceFileLoader('ssf_plugin_' + re.sub(r'\W', '_', os.path.basename(path)), path)
    spec = importlib.util.spec_from_loader(loader.name, loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


def unpause_locked(a):
    sr, vdi = a['sr'], a['vdi']
    if not UUID_RE.match(sr or '') or not UUID_RE.match(vdi or ''):
        raise Failed('bad SR or VDI uuid')
    problems = []
    path = os.path.join(SM_BACKEND, sr, vdi)
    try:
        st = os.lstat(path)
    except OSError as exc:
        if exc.errno != errno.ENOENT:
            raise
        return {'done': False, 'problems': ['%s is gone' % path]}
    rdev = [os.major(st.st_rdev), os.minor(st.st_rdev)] if stat.S_ISBLK(st.st_mode) else None
    if rdev != a['node']['rdev'] or st.st_ino != a['node']['ino']:
        problems.append('%s is %s inode %d now, not the block node %s inode %d audited'
                        % (path, canon(rdev), st.st_ino, canon(a['node']['rdev']), a['node']['ino']))
    tapmaj = proc_devices().get(('b', 'tapdev'))
    if rdev is not None and rdev[0] != tapmaj:
        problems.append('its major %d is not the tapdev major %s' % (rdev[0], tapmaj))
    rows = f_tapdisks()
    at = [r for r in rows if r['minor'] == a['minor'] and r['pid'] is not None]
    if len(at) != 1 or at[0]['pid'] != a['pid']:
        problems.append('tap minor %d is held by %s now, not by tapdisk pid %d'
                        % (a['minor'], ', '.join('pid %s' % r['pid'] for r in at) or 'no tapdisk', a['pid']))
    elif at[0]['state'] is None or not at[0]['state'] & PAUSED:
        return {'done': False, 'already': True, 'problems': [],
                'detail': 'tapdisk pid %d is no longer paused (state %s)' % (a['pid'], tap_state_text(at[0]['state']))}
    elif (at[0].get('path') or '') != a['path']:
        problems.append('tapdisk pid %d serves %s now, not %s' % (a['pid'], at[0].get('path'), a['path']))
    target = (phy_record(sr, vdi) or {}).get('target')
    if target != a.get('phy'):
        problems.append('its phy link points at %s now, not %s' % (target, a.get('phy')))
    if problems:
        return {'done': False, 'problems': problems}
    session = local_session()
    try:
        smc = session.xenapi.VDI.get_sm_config(session.xenapi.VDI.get_by_uuid(vdi))
        keys = [k for k in ('paused', 'relinking', 'activating') if k in smc]
        if keys:
            return {'done': False, 'problems': ['the VDI carries %s now' % ', '.join(keys)]}
        src = read_file(os.path.join(PLUGIN_DIR, 'tapdisk-pause'))
        fn = plugin_handler(src.decode('utf-8', 'replace'), 'unpause')
        if fn is None:
            return {'done': False, 'problems': ['the tapdisk-pause plugin has no unpause entry point']}
        mod = load_plugin(os.path.join(PLUGIN_DIR, 'tapdisk-pause'))
        ret = getattr(mod, fn)(session, {'sr_uuid': sr, 'vdi_uuid': vdi, 'failfast': 'True'})
    finally:
        try:
            session.xenapi.session.logout()
        except Exception:
            pass
    after = [r for r in f_tapdisks() if r['minor'] == a['minor'] and r['pid'] == a['pid']]
    state = after[0]['state'] if after else None
    done = _text(ret) == 'True' and bool(after) and state is not None and not state & PAUSED
    return {'done': done, 'problems': [] if done else ['the plugin answered %s and tapdisk pid %d reads %s'
                                                        % (canon(_text(ret)), a['pid'], 'gone' if not after else
                                                           tap_state_text(state))],
            'plugin': _text(ret), 'state_after': state,
            'detail': 'SM\'s tapdisk-pause unpause ran under the VDI lock; the tapdisk reads %s'
                      % ('gone' if not after else tap_state_text(state))}


NETFS = ('nfs', 'nfs4', 'cifs', 'smb3', 'smbfs', 'glusterfs', 'ceph', '9p', 'lustre', 'ocfs2', 'gfs2', 'moosefs',
         'davfs', 'afs')


def mountinfo_all(text):
    out, seen = [], set()
    for line in text.splitlines():
        head, sep, tail = line.partition(' - ')
        parts = head.split()
        rest = tail.split()
        if not sep or len(parts) < 5 or not rest:
            continue
        mp = re.sub(r'\\([0-7]{3})', lambda m: chr(int(m.group(1), 8)), parts[4])
        if mp not in seen:
            seen.add(mp)
            out.append((mp, rest[0]))
    return sorted(out, key=lambda x: (not (x[1] in NETFS or x[1].startswith('fuse')), x[0]))


PF_KTHREAD = 0x00200000


def stuck_d(wait):
    first = {}
    out = []
    for pid in pids():
        if pid == os.getpid():
            continue
        try:
            st = proc_stat(pid)
        except EnvironmentError as exc:
            if not gone(exc):
                out.append({'pid': pid, 'comm': comm_of(pid) or '?', 'unread': _text(exc)})
            continue
        except (ValueError, IndexError) as exc:
            out.append({'pid': pid, 'comm': comm_of(pid) or '?', 'unread': _text(exc)})
            continue
        if st['state'] == 'D' and not st['flags'] & PF_KTHREAD:
            first[pid] = (st['ticks'], proc_io(pid))
    if not first:
        return out
    time.sleep(wait)
    for pid, (ticks, io) in sorted(first.items()):
        try:
            st = proc_stat(pid)
        except EnvironmentError as exc:
            if not gone(exc):
                out.append({'pid': pid, 'comm': comm_of(pid) or '?', 'unread': _text(exc)})
            continue
        except (ValueError, IndexError) as exc:
            out.append({'pid': pid, 'comm': comm_of(pid) or '?', 'unread': _text(exc)})
            continue
        if st['state'] != 'D' or st['ticks'] != ticks:
            continue
        io2 = proc_io(pid)
        if io is not None and io2 is not None and io2 != io:
            continue
        out.append({'pid': pid, 'comm': st['comm']})
    return out


def agent_mount_probe(args, source):
    timeout = int(args.get('timeout') or 10)
    deadline = _now() + float(args.get('budget') or 120)
    problems, probed, left = [], [], []
    targets = []
    own = set()
    for pid, text in mount_namespaces():
        for mp, fstype in mountinfo_all(text):
            if pid is None:
                own.add(mp)
                targets.append((mp, fstype, mp, None))
            elif (fstype in NETFS or fstype.startswith('fuse')) and mp not in own:
                targets.append(('%s (mount namespace of pid %d)' % (mp, pid), fstype, '%s/%d/root%s' % (PROC, pid, mp),
                                pid))
    for mp, fstype, path, pid in targets:
        if _now() + timeout > deadline:
            left.append(mp)
            continue
        r = run(['stat', '--format=ssf-mount-probe %i', '--', path], timeout)
        probed.append(mp)
        if r.timed_out:
            problems.append('the %s mount %s does not answer a stat within %ss (a stuck probe may be left behind)'
                            % (fstype, mp, timeout))
        elif r.rc != 0 and (pid is None or pid_alive(pid)):
            problems.append('the %s mount %s: stat %s' % (fstype, mp, r.why()))
    if left:
        problems.append('%d mount(s) were not probed within the budget: %s' % (len(left), ', '.join(left[:4])))
    try:
        stuck = bounded(stuck_d, SCAN_BUDGET + 10, float(args.get('dwait') or 5))
    except Failed as exc:
        stuck = None
        problems.append('the D-state scan: %s' % _text(exc))
    for p in stuck or []:
        if p.get('unread'):
            problems.append('pid %d (%s) cannot be read, so whether it is stuck in D state is not established (%s)'
                            % (p['pid'], p['comm'], p['unread']))
            continue
        problems.append('pid %d (%s) stays in D state with no progress, and lsof can hang reading it%s'
                        % (p['pid'], p['comm'], ' (a stat left by an earlier mount probe: one of the mounts is '
                                                'dead)' if p['comm'] == 'stat' else ''))
    return {'probed': probed, 'problems': problems, 'stuck': stuck}


def agent_smlog_tail(args, source):
    vdi = args.get('vdi') or ''
    if not UUID_RE.match(vdi):
        raise Failed('bad VDI uuid')
    since = float(args['since'])
    now = time.time()
    with open(SMLOG, 'rb') as h:
        h.seek(0, 2)
        size = h.tell()
        start = max(0, size - (4 << 20))
        h.seek(start)
        data = h.read()
    out = []
    after_lsof = set()
    for raw in data.splitlines()[1 if start else 0:]:
        line = raw.decode('utf-8', 'replace')
        ev = parse_smlog_line(line, now)
        if ev is None or ev[0] < since - 2:
            continue
        low = line.lower()
        keep = vdi in line or any(w in low for w in ('exception', 'raise', 'error', 'fail', 'lsof', 'locked', 'paused'))
        mm = SM_PID_RE.search(line)
        if mm and mm.group(1) in after_lsof:
            after_lsof.discard(mm.group(1))
            keep = True
        if mm and "'/usr/sbin/lsof'" in line:
            after_lsof.add(mm.group(1))
        if keep:
            out.append(line[-400:])
    return {'lines': out[-12:]}


def agent_tap_stats(args, source):
    pid, minor = int(args['pid']), int(args['minor'])
    res = f_tap_stats([{'pid': pid, 'minor': minor, 'state': 0}], 30.0)
    return res.get('%d:%d' % (pid, minor)) or {'ok': False, 'error': 'not asked'}


def io_counts(st):
    if not isinstance(st, dict) or not isinstance(st.get('reqs_outstanding'), int):
        return None, None, None
    def pair(v):
        return v if isinstance(v, list) and len(v) == 2 and all(isinstance(x, int) for x in v) else [0, 0]
    tap = pair((st.get('tap') or {}).get('reqs') if isinstance(st.get('tap'), dict) else None)
    ring = pair((st.get('xenbus') or {}).get('reqs') if isinstance(st.get('xenbus'), dict) else None)
    failed = 0
    for img in st.get('images') if isinstance(st.get('images'), list) else []:
        f = pair(img.get('fail') if isinstance(img, dict) else None)
        failed += f[0] + f[1]
    return st['reqs_outstanding'], tap[1] + ring[1], failed


def agent_xlog_grep(args, source):
    needle = _text(args.get('needle') or '')
    if not needle:
        raise Failed('nothing to look for')
    lines, covered = log_lines_covered(XENSOURCE_LOG, float(args['since']) - 2, must=needle.encode('utf-8'))
    also = _text(args.get('also') or '')
    return {'lines': [l[-400:] for l in lines if not also or also in l][-12:], 'covered': covered}


BACKUP_RE = re.compile(r'^storage\.db\.[0-9]{8}-[0-9]{6}\.bak$')


def agent_fetch_backup(args, source):
    d = act_dir(args['run_id'], args['host_uuid'], args['attempt'])
    name = os.path.basename(args['name'])
    if not BACKUP_RE.match(name):
        raise Failed('not a backup name: %s' % name)
    data = read_file(os.path.join(d, name))
    return {'name': name, 'size': len(data), 'sha256': sha256_bytes(data),
            'data': base64.b64encode(data).decode('ascii')}


def agent_unlink_abort(args, source):
    sr = args['sr']
    if not UUID_RE.match(sr):
        raise Failed('bad SR uuid')
    path = os.path.join(IPC_DIR, sr, 'abort')
    exp = args['expect']

    def same():
        st_ = os.lstat(path)
        return read_text(path) == exp['content'] and abs(st_.st_mtime - exp['mtime']) <= 0.001 and \
            st_.st_ino == exp['ino'], st_
    try:
        ok, st = same()
        content = read_text(path)
    except OSError as exc:
        if exc.errno == errno.ENOENT:
            return {'done': False, 'already': True, 'problems': []}
        raise
    problems = []
    if not ok:
        problems.append('the flag file changed since the audit')
    m = re.match(r'^\s*(\d+)\s*$', content)
    if not m:
        problems.append('the flag holds %s, not a pid' % canon(content[:40]))
    else:
        pid = int(m.group(1))
        btime = boot_time()
        if pid_alive(pid):
            try:
                start = proc_start(pid, btime)
                argv = bounded(proc_cmdline, 10, pid)
            except (EnvironmentError, ValueError, IndexError, Failed):
                start, argv = None, []
            if start is None or start <= st.st_mtime + 1:
                problems.append('its writer, pid %d, is alive and older than the flag' % pid)
            elif is_sm_argv(argv) or any('cleanup.py' in a for a in argv):
                problems.append('pid %d is now an SM process (%s)' % (pid, ' '.join(argv[:3])))
    if time.time() - st.st_mtime < ABORT_MIN_AGE:
        problems.append('the flag is younger than %ds' % ABORT_MIN_AGE)

    def gc_procs():
        found = []
        for pid in pids():
            try:
                argv = proc_cmdline(pid)
            except EnvironmentError as exc:
                if not gone(exc):
                    found.append((pid, _text(exc)))
                continue
            if any(a.endswith('cleanup.py') for a in argv) and sr in argv:
                found.append((pid, None))
        return found
    try:
        for pid, why in bounded(gc_procs, SCAN_BUDGET):
            problems.append('a GC (pid %d) runs on the SR' % pid if why is None else
                            'pid %d cannot be read, so whether it is a GC is not established (%s)' % (pid, why))
    except Failed as exc:
        problems.append(_text(exc))
    try:
        for l in f_locks():
            if l['path'] in (os.path.join(SM_LOCK_DIR, sr, 'gc_active'), os.path.join(SM_LOCK_DIR, sr, 'running')):
                problems.append('%s is held by pid %d' % (l['path'], l['pid']))
    except Exception as exc:
        problems.append('lock holders: %s' % _text(exc))
    u = run([SYSTEMCTL, 'is-active', unit_name(sr)], SYSTEMCTL_TIMEOUT)
    if u.timed_out or u.out.strip() not in ('inactive', 'failed', 'unknown'):
        problems.append('%s is %s' % (unit_name(sr), u.out.strip() or u.why()))
    if problems:
        return {'done': False, 'problems': problems}
    aside = os.path.join(IPC_DIR, '.ssf-abort-%s-%d' % (sr, os.getpid()))
    _unlink_quietly(aside)
    try:
        ok, _ = same()
    except OSError:
        ok = False
    if not ok:
        return {'done': False, 'problems': ['the flag file changed while it was being checked']}
    try:
        os.rename(path, aside)
    except OSError as exc:
        if exc.errno == errno.ENOENT:
            return {'done': False, 'already': True, 'problems': []}
        raise
    try:
        st2 = os.lstat(aside)
        moved = read_text(aside)
    except EnvironmentError as exc:
        if exc.errno == errno.ENOENT:
            return {'done': not os.path.lexists(path), 'problems': []}
        raise
    if moved != exp['content'] or abs(st2.st_mtime - exp['mtime']) > 0.001 or st2.st_ino != exp['ino']:
        if os.path.lexists(path):
            _unlink_quietly(aside)
        else:
            os.rename(aside, path)
        return {'done': False, 'problems': ['the flag was rewritten while it was being removed: it is left in place']}
    os.unlink(aside)
    return {'done': not os.path.lexists(path), 'problems': []}


def ssf_processes(flags=('--ssf-act', '--ssf-guard')):
    found = []
    for pid in pids():
        if pid == os.getpid():
            continue
        try:
            if not (comm_strict(pid) or '').startswith('python'):
                continue
            argv = proc_cmdline(pid)
        except EnvironmentError as exc:
            if not gone(exc):
                found.append(pid)
            continue
        if any(f in argv for f in flags):
            found.append(pid)
    return found


def agent_xapi_ensure(args, source):
    _ENSURE_END[0] = _now() + ENSURE_TIMEOUT - ENSURE_MARGIN
    try:
        return xapi_ensure(args)
    finally:
        _ENSURE_END[0] = None


def xapi_ensure(args):
    d = act_dir(args['run_id'], args['host_uuid'], args['attempt']) if args.get('run_id') else None
    btime = boot_time()
    if d is not None:
        for who in ('action', 'guardian'):
            try:
                rec = read_json(os.path.join(d, who + '.json'))
            except (EnvironmentError, ValueError):
                continue
            if pid_alive(rec['pid'], rec['start'], btime):
                return {'started': False, 'busy': who, 'pid': rec['pid'], 'ready': False,
                        'detail': 'the %s (pid %d) is still alive' % (who, rec['pid'])}
    try:
        others = bounded(ssf_processes, SCAN_BUDGET)
    except Failed as exc:
        return {'started': False, 'busy': 'scan', 'ready': False, 'detail': _text(exc)}
    if others:
        return {'started': False, 'busy': 'action', 'ready': False,
                'detail': 'another storage-state-fixer action runs here (pid %s)' % ', '.join(str(p) for p in others)}
    lockfd, lockpath = toolstack_flock()
    if lockfd is None:
        return {'started': False, 'busy': 'toolstack', 'ready': False,
                'detail': '%s is held: an action or xe-toolstack-restart runs here' % lockpath}
    try:
        state = settle_xapi_jobs(STOP_TIMEOUT + GONE_WAIT)
        log_dir = d if d is not None and os.path.isdir(d) else RUN_ROOT
        if not os.path.isdir(log_dir):
            os.makedirs(log_dir, 0o700)
        st, spec, units = {}, {'host_uuid': args.get('host_uuid'), 'items': []}, None
        if d is not None:
            st = read_status(d) or {}
            try:
                units = read_json(os.path.join(d, 'units.json')).get('units')
            except (EnvironmentError, ValueError):
                units = None
            try:
                spec = read_json(os.path.join(d, 'spec.json'))
            except (EnvironmentError, ValueError):
                pass
        recheck = d is not None and st.get('state') not in SETTLED_STATES
        wrote = recheck and bool(st.get('backup') and st.get('written_sha256'))
        keep = st.get('state') if st.get('state') in ACT_ENDS else 'failed'
        none = {'verdict': 'n/a', 'detail': 'nothing of this run is left to check here'}
        if not xapi_stopped():
            left = xapi_left_as_is(state)
            if left is not None:
                detail = ('%s: it is left as it is (not started again, nothing rolled back); run recover again once '
                          'it answers' % left)
                act_log(log_dir, 'recover: %s' % detail)
                return {'started': False, 'busy': None, 'ready': False, 'running': True, 'detail': detail,
                        'storage': 'unverified' if wrote else 'n/a', 'storage_detail': detail}
            v = none
            if recheck:
                v, rb = check_running(log_dir, st, units, spec, 'recover')
                if rb is not None and rb.get('deferred'):
                    return {'started': False, 'busy': None, 'ready': False, 'running': True,
                            'storage': 'failed', 'storage_detail': v['detail'],
                            'detail': 'xapi is running but did not load the edited file (%s); %s'
                                      % (v['detail'], rb['note'])}
                if rb is not None:
                    why = 'recover: xapi was running but did not load the edited file (%s)' % v['detail']
                    rollback_status(d, rb, why, recover_storage=v)
                    return {'started': False, 'busy': None, 'result': rb['start'], 'rolled_back': rb['ok'],
                            'ready': bool(rb['ok'] and rb['start'].get('complete')),
                            'storage': 'restored' if rb['ok'] else 'failed', 'storage_detail': rollback_text(rb),
                            'detail': 'xapi was running but did not load the edited file; %s' % rollback_text(rb)}
                safe_status(d, verdict_state(v, keep), **verdict_fields(
                    v, spec, recover_storage=v, detail='%s; recover found xapi running: %s' % (
                        'its load was not established' if st.get('state') == 'unverified' else
                        'the action did not finish', v['detail'])))
            deadline = _now() + INIT_WAIT
            while True:
                ready = xapi_ready(f_xapi_state(), f_cookies())
                if ready or _now() > deadline:
                    break
                time.sleep(POLL)
            return {'started': False, 'busy': None, 'ready': ready, 'storage': v['verdict'],
                    'storage_detail': v['detail'],
                    'detail': 'xapi is running and answering%s' % (
                        '' if ready else ', but has not finished initialising after %ds' % INIT_WAIT)}
        old = edited = note = None
        if recheck:
            old, edited, note = edited_by_action(st, log_dir, 'recover')
        act_log(log_dir, 'recover: starting xapi (it was %s)' % state)
        res = start_xapi_local(log_dir, units)
        why = None
        v = none
        if edited is not None and not res.get('ready'):
            why = 'xapi did not come up with the edited file (%s)' % res['detail']
        elif recheck and res.get('ready'):
            v = storage_verdict(st, spec, start=res['issued'])
            res['storage'] = v
            if v['verdict'] == 'failed' and edited is not None:
                why = 'xapi did not load the edited file: %s' % v['detail']
        elif wrote:
            v = {'verdict': 'unverified', 'detail': 'xapi is not up, so what it holds cannot be checked (%s)'
                                                    % res['detail']}
        if why is not None:
            rb = roll_back(log_dir, old, units, 'recover: ' + why, args['host_uuid'], st.get('written_sha256'))
            if rb.get('deferred'):
                return {'started': True, 'busy': None, 'ready': False, 'result': res, 'storage': 'failed',
                        'storage_detail': why, 'detail': '%s; %s' % (why, rb['note'])}
            rollback_status(d, rb, 'recover: ' + why, recover_start=res)
            return {'started': True, 'busy': None, 'result': rb['start'], 'rolled_back': rb['ok'],
                    'ready': bool(rb['ok'] and rb['start'].get('complete')),
                    'storage': 'restored' if rb['ok'] else 'failed', 'storage_detail': rollback_text(rb),
                    'detail': '%s; %s' % (why, rollback_text(rb))}
        if recheck:
            safe_status(d, verdict_state(v, keep), **verdict_fields(
                v, spec, recover_start=res, detail='recover started xapi (%s); %s%s' % (
                    res['detail'] or 'answering', v['detail'], ('; ' + note) if note else '')))
        return {'started': True, 'busy': None, 'result': res, 'ready': bool(res['answering'] and res['complete']),
                'storage': v['verdict'], 'storage_detail': v['detail'],
                'detail': (res['detail'] or 'xapi is up and answering') + (('; ' + note) if note else '')}
    finally:
        os.close(lockfd)


VERBS = {'facts': lambda a, s: agent_facts(a), 'act-start': agent_act_start, 'act-status': agent_act_status,
         'act-list': agent_act_list, 'inert-node': agent_inert_node, 'mount-probe': agent_mount_probe,
         'fetch-backup': agent_fetch_backup, 'unlink-abort': agent_unlink_abort, 'xapi-ensure': agent_xapi_ensure,
         'smlog-tail': agent_smlog_tail, 'xlog-grep': agent_xlog_grep, 'tap-stats': agent_tap_stats,
         'fence-start': agent_fence_start, 'fence-status': agent_fence_status, 'fence-release': agent_fence_release}


def agent_entry(request, source):
    try:
        req = json.loads(base64.b64decode(request).decode('utf-8'))
        apply_paths(req.get('paths'))
        if req.get('host'):
            me = parse_inventory(read_text(INVENTORY)).get('INSTALLATION_UUID')
            if me != req['host']:
                raise Failed('this is host %s, not %s: the address reached another machine, so nothing was asked or '
                             'done here' % (me, req['host']))
        result = {'ok': True, 'value': VERBS[req['verb']](req.get('args') or {}, source)}
    except Exception as exc:
        import traceback
        result = {'ok': False, 'error': u'%s: %s' % (exc.__class__.__name__, _text(exc)),
                  'trace': _text(traceback.format_exc())[-3000:]}
    out = json.dumps(result)
    _write(sys.stdout, MARK_BEGIN + out + MARK_END)
    return 0

ASKPASS_ENV = 'SSF_SSH_PASSWORD'


class CallError(Exception):
    pass


class Host(object):
    def __init__(self, ref, rec, local, live):
        self.ref = ref
        self.uuid = rec['uuid']
        self.name = rec['name_label'] or rec['hostname'] or rec['uuid']
        self.hostname = rec['hostname']
        self.address = rec['address']
        self.enabled = rec['enabled']
        self.local = local
        self.live = live
        self.is_master = False


def known_hosts_file():
    return os.path.join(RUN_ROOT, 'known_hosts')


def user_known_hosts():
    return [known_hosts_file(), os.path.join(os.path.expanduser('~'), '.ssh', 'known_hosts')]


GLOBAL_KNOWN_HOSTS = '/etc/ssh/ssh_known_hosts'


def key_known(address):
    for f in user_known_hosts() + [GLOBAL_KNOWN_HOSTS]:
        if not os.path.exists(f):
            continue
        r = run(['ssh-keygen', '-F', address, '-f', f], 20)
        if r.rc == 0 and r.out.strip():
            return True
    return False


def scan_keys(address, workdir):
    r = run(['ssh-keyscan', '-T', '10', address], 40)
    lines = [l for l in r.out.splitlines() if l.strip() and not l.startswith('#')]
    if not lines:
        raise CallError('ssh-keyscan found no host key for %s (%s)' % (address, r.why()))
    tmp = os.path.join(workdir, 'scan-%s' % re.sub(r'[^0-9A-Za-z.]', '_', address))
    with open(tmp, 'w') as h:
        h.write('\n'.join(lines) + '\n')
    f = run(['ssh-keygen', '-l', '-f', tmp], 20)
    fps = [l.strip() for l in f.out.splitlines() if l.strip()]
    if not f.ok or not fps:
        raise CallError('the fingerprints of the keys of %s cannot be computed (%s)' % (address, f.why()))
    return lines, fps


def trust_hosts(transport, hosts, assume):
    new = [h for h in hosts if h.live and not h.local and not key_known(h.address)]
    if not new:
        return []
    say(u'')
    say(u'This host has no recorded ssh host key for %s. Their keys, as they answer now:'
        % ', '.join('%s (%s)' % (h.name, h.address) for h in new))
    found = []
    for h in new:
        try:
            lines, fps = scan_keys(h.address, transport.workdir)
        except CallError as exc:
            warn('%s: %s' % (h.name, _text(exc)))
            continue
        found.append((h, lines))
        say(u'  %s (%s):' % (h.name, h.address))
        for fp in fps:
            say(u'    %s' % fp)
    if not found:
        return new
    say(u'Compare them with what each host prints on its own console for: '
        u'for f in /etc/ssh/ssh_host_*_key.pub; do ssh-keygen -lf $f; done')
    if assume:
        say(u'They are recorded without asking (--trust-host-keys).')
    elif not sys.stdin.isatty():
        warn('there is no terminal to confirm them on, so those hosts are not reached (pass --trust-host-keys to '
             'record them without asking)')
        return new
    elif not ask(u'Do the fingerprints match, and are these keys to be trusted? [y/N] '):
        warn('the keys were not trusted, so those hosts are not reached')
        return new
    ensure_run_root()
    fd = os.open(known_hosts_file(), os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    try:
        append_all(fd, ('\n'.join(l for h, lines in found for l in lines) + '\n').encode('utf-8'))
        os.fsync(fd)
    finally:
        os.close(fd)
    return [h for h in new if h not in [x[0] for x in found]]


def ensure_run_root():
    if not os.path.isdir(RUN_ROOT):
        os.makedirs(RUN_ROOT, 0o700)


def make_workdir():
    d = tempfile.mkdtemp(prefix='ssf-')
    atexit.register(shutil.rmtree, d, True)
    return d


class Transport(object):
    def __init__(self, source, workdir):
        self.source = source
        self.workdir = workdir
        self.password = None
        self.askpass = None
        self.paths = None
        self.calls = 0

    def set_password(self, password):
        self.password = password or None
        if self.password is None:
            return
        path = os.path.join(self.workdir, 'askpass')
        with open(path, 'w') as h:
            h.write('#!/bin/sh\nprintf \'%s\\n\' "$' + ASKPASS_ENV + '"\n')
        os.chmod(path, 0o700)
        env = dict(os.environ)
        env[ASKPASS_ENV] = 'ssf-askpass-probe'
        r = run([path], 10, env=env)
        if r.rc != 0 or r.out.strip() != 'ssf-askpass-probe':
            raise Refused('the ssh password helper cannot run from %s (%s): is it mounted noexec?'
                          % (self.workdir, r.why()))
        self.askpass = path

    def ssh_argv(self, host):
        argv = ['ssh', '-o', 'StrictHostKeyChecking=yes', '-o', 'UserKnownHostsFile=' + ' '.join(user_known_hosts()),
                '-o', 'LogLevel=ERROR',
                '-o', 'ConnectTimeout=%d' % SSH_CONNECT, '-o', 'ServerAliveInterval=15',
                '-o', 'ServerAliveCountMax=4', '-o', 'NumberOfPasswordPrompts=1',
                '-o', 'ControlMaster=no', '-o', 'ControlPath=none',
                '-o', 'BatchMode=%s' % ('no' if self.password else 'yes'),
                'root@' + host.address, "exec %s -c '%s'" % (REMOTE_PYTHON, BOOT)]
        env = dict(os.environ)
        if self.password:
            env[ASKPASS_ENV] = self.password
            env['SSH_ASKPASS'] = self.askpass
            env['SSH_ASKPASS_REQUIRE'] = 'force'
            if not env.get('DISPLAY'):
                env['DISPLAY'] = ':0'
        return argv, env

    def call(self, host, verb, args=None, timeout=AGENT_TIMEOUT):
        req = {'verb': verb, 'args': args or {}, 'host': host.uuid}
        if self.paths:
            req['paths'] = self.paths
        payload = base64.b64encode(json.dumps(req).encode('utf-8')) + b'\n' + self.source
        self.calls += 1
        if host.local:
            argv, env = [sys.executable, '-c', BOOT], None
        else:
            argv, env = self.ssh_argv(host)
        r = run(argv, timeout, data=payload, env=env, raw=True)
        out = r.out.decode('utf-8', 'replace') if isinstance(r.out, bytes) else r.out
        if r.timed_out:
            raise CallError('no answer from %s within %ds' % (host.name, timeout))
        start = out.find(MARK_BEGIN)
        end = out.rfind(MARK_END)
        if start < 0 or end < start:
            detail = (r.err.strip().splitlines() or [''])[-1][:300]
            if 'IDENTIFICATION HAS CHANGED' in r.err:
                raise CallError('ssh to %s (%s) was stopped: its host key is not the one recorded for it (in %s), so '
                                'the password was not sent. If the host was reinstalled, delete its line there and run '
                                'again' % (host.name, host.address, ' or '.join(user_known_hosts())))
            if 'Host key verification failed' in r.err:
                raise CallError('ssh to %s (%s) was stopped: its host key is not known to this host and was not '
                                'confirmed, so the password was not sent' % (host.name, host.address))
            if r.rc == 255 and ('denied' in r.err or 'Authentication' in r.err):
                raise CallError('ssh to %s (%s) was refused: %s' % (host.name, host.address, detail))
            raise CallError('%s to %s failed (exit %d)%s' % ('local agent' if host.local else 'ssh', host.name,
                                                             r.rc, ': ' + detail if detail else ''))
        try:
            doc = json.loads(out[start + len(MARK_BEGIN):end])
        except ValueError as exc:
            raise CallError('the agent on %s answered something unreadable: %s' % (host.name, _text(exc)))
        if not doc.get('ok'):
            raise CallError('the agent on %s failed: %s' % (host.name, doc.get('error')))
        return doc['value']


def sanitize(obj):
    if isinstance(obj, dict):
        return dict((_text(k), sanitize(v)) for k, v in obj.items())
    if isinstance(obj, (list, tuple)):
        return [sanitize(v) for v in obj]
    if isinstance(obj, (bool, int, float)) or obj is None:
        return obj
    if isinstance(obj, (_TEXT, bytes)):
        return _text(obj)
    return _text(obj)


class Api(object):
    def __init__(self):
        self.session = None
        self.epoch = 0

    def login(self):
        import XenAPI
        socket.setdefaulttimeout(API_TIMEOUT)
        s = XenAPI.xapi_local()
        s.xenapi.login_with_password('root', '', '', PROG)
        self.session = s
        self.epoch += 1

    def logout(self):
        if self.session is not None:
            try:
                self.session.xenapi.session.logout()
            except Exception:
                pass
            self.session = None

    @property
    def x(self):
        if self.session is None:
            self.login()
        return self.session.xenapi

    def relogin(self, wait=ANSWER_WAIT):
        self.session = None
        deadline = _now() + wait
        while True:
            try:
                self.login()
                self.session.xenapi.pool.get_all()
                self.epoch += 1
                return
            except Exception as exc:
                self.session = None
                if _now() > deadline:
                    raise Failed('xapi on this host does not answer the API: %s' % _text(exc))
                pause(2, False)


SNAP_CLASSES = ('pool', 'host', 'host_metrics', 'SR', 'PBD', 'VM', 'VBD', 'VDI', 'task', 'PIF')
EVENT_CLASSES = ['vbd', 'vm', 'vdi', 'task', 'pbd', 'sr', 'pool']


def pool_snapshot(api):
    snap = {}
    for cls in SNAP_CLASSES:
        snap[cls] = sanitize(getattr(api.x, cls).get_all_records())
    snap['time'] = time.time()
    return snap


class Model(object):
    def __init__(self, snap):
        self.snap = snap
        pools = list(snap['pool'].values())
        if len(pools) != 1:
            raise Failed('the API lists %d pools' % len(pools))
        self.pool = pools[0]
        self.hosts = snap['host']
        self.vms = snap['VM']
        self.vbds = snap['VBD']
        self.vdis = snap['VDI']
        self.srs = snap['SR']
        self.pbds = snap['PBD']
        self.tasks = snap['task']
        self.pifs = snap.get('PIF') or {}
        self.host_by_uuid = dict((r['uuid'], ref) for ref, r in self.hosts.items())
        self.vdi_by_uuid = dict((r['uuid'], ref) for ref, r in self.vdis.items())
        self.vbd_by_uuid = dict((r['uuid'], ref) for ref, r in self.vbds.items())
        self.sr_by_uuid = dict((r['uuid'], ref) for ref, r in self.srs.items())
        self.dom0 = {}
        self.domids = collections.defaultdict(list)
        for ref, vm in self.vms.items():
            if vm['is_control_domain']:
                self.dom0.setdefault(vm['resident_on'], []).append(ref)
            elif vm['power_state'] in ('Running', 'Paused'):
                self.domids[(vm['resident_on'], vm['domid'])].append(ref)
        self.children = collections.defaultdict(list)
        self.vdi_uuid8 = collections.Counter()
        self.vdi_by_loc = collections.defaultdict(list)
        for ref, v in self.vdis.items():
            self.vdi_uuid8[v['uuid'][:8]] += 1
            sr = self.srs.get(v['SR'])
            loc = v.get('location', v['uuid'])
            if sr is not None:
                self.vdi_by_loc[(sr['uuid'], loc)].append(v['uuid'])
            parent = v['sm_config'].get('vhd-parent')
            if parent:
                self.children[(v['SR'], parent)].append(ref)

    def host_live(self, href):
        h = self.hosts.get(href)
        if h is None:
            return False
        m = self.snap['host_metrics'].get(h['metrics'])
        return bool(m and m.get('live') is True)

    def dom0_of(self, href):
        refs = self.dom0.get(href) or []
        return refs[0] if len(refs) == 1 else None

    def plugged_hosts(self, sr_ref):
        out = []
        for p in self.srs[sr_ref]['PBDs']:
            pb = self.pbds.get(p)
            if pb and pb['currently_attached']:
                out.append(pb['host'])
        return out

    def sr_master(self, sr_ref):
        sr = self.srs.get(sr_ref)
        if sr is None:
            return None
        if sr['shared']:
            return self.pool['master']
        hs = set(self.pbds[p]['host'] for p in sr['PBDs'] if p in self.pbds)
        return list(hs)[0] if len(hs) == 1 else None

    def is_leaf(self, vdi_ref):
        v = self.vdis[vdi_ref]
        return not self.children.get((v['SR'], v['uuid']))

    def vdi_uuid(self, ref):
        v = self.vdis.get(ref)
        return v['uuid'] if v else None

    def name_vdi(self, ref):
        v = self.vdis.get(ref)
        if v is None:
            return u'(gone)'
        return u'%s "%s"' % (v['uuid'], v['name_label'])

    def name_host(self, href):
        h = self.hosts.get(href)
        return h['name_label'] if h else _text(href)

    def name_sr(self, sref):
        s = self.srs.get(sref)
        return u'%s "%s" (%s)' % (s['uuid'], s['name_label'], s['type']) if s else _text(sref)

    def pending_tasks(self, href=None, work=False):
        out = []
        for ref, t in self.tasks.items():
            if t['status'] != 'pending' or (work and t['name_label'] in HOUSEKEEPING_TASKS):
                continue
            if href is None or t['resident_on'] == href:
                out.append(t)
        return out

    def is_gc_task(self, t, sr_uuid=None):
        if t['name_label'] != 'Garbage Collection':
            return False
        if sr_uuid is None:
            return True
        return t['name_description'].endswith(sr_uuid)


class Audit(object):
    def __init__(self, n):
        self.n = n
        self.t = None
        self.t0 = None
        self.snap = None
        self.model = None
        self.facts = {}
        self.errors = {}
        self.smlog = {}
        self.drbd = {}
        self.probes = {}
        self.caps = {}
        self.rpm = {}
        self.xapi_pkg = {}
        self.vbd2 = None
        self.pidinfo = {}
        self.lvnames = {}
        self.statfiles = {}
        self.srdirs = {}
        self.xsread = {}
        self.vhdchecks = {}
        self.dmchecks = {}
        self._views = {}

    def view(self, href):
        hv = self._views.get(href)
        if hv is None:
            hv = HostView(self, href)
            self._views[href] = hv
        return hv

    def fact(self, host_uuid, key):
        doc = self.facts.get(host_uuid)
        if doc is None:
            return None
        f = doc.get(key)
        if not f or not f.get('ok'):
            return None
        return f['value']

    def fact_error(self, host_uuid, key):
        doc = self.facts.get(host_uuid)
        if doc is None:
            return self.errors.get(host_uuid) or 'the host was not audited'
        f = doc.get(key)
        if f is None:
            return '%s was not collected' % key
        if not f.get('ok'):
            return f.get('error')
        return None


def parallel(fn, items, limit=16):
    results = {}
    lock = threading.Lock()
    todo = list(items)

    def worker():
        while True:
            with lock:
                if not todo:
                    return
                item = todo.pop(0)
            try:
                res = ('ok', fn(item))
            except Exception as exc:
                res = ('err', exc)
            with lock:
                results[id(item)] = (item, res)
    threads = [threading.Thread(target=worker) for _ in range(min(limit, max(1, len(todo))))]
    for t in threads:
        t.daemon = True
        t.start()
    for t in threads:
        while t.is_alive():
            t.join(0.5)
    return [results[id(i)] for i in items]

PATH_SR_TYPES = ('ext', 'nfs', 'file', 'lvm', 'lvmoiscsi', 'lvmohba', 'lvmofcoe', 'smb', 'cifs', 'xfs',
                 'zfs', 'btrfs', 'ext4', 'largeblock', 'moosefs', 'cephfs', 'glusterfs')
JUDGED_SR_TYPES = PATH_SR_TYPES + ('linstor',)
ATOMIC_PAUSE_SR_TYPES = ('ext', 'nfs', 'file', 'lvm', 'lvmoiscsi', 'lvmohba', 'lvmofcoe', 'smb', 'xfs', 'zfs',
                         'largeblock', 'moosefs', 'cephfs', 'glusterfs', 'linstor')
LVM_SR_TYPES = ('lvm', 'lvmoiscsi', 'lvmohba', 'lvmofcoe')
FILE_SR_TYPES = ('ext', 'nfs', 'file', 'smb', 'cifs')
SPECIAL_VDI_TYPES = ('ha_statefile', 'redo_log', 'metadata', 'pvs_cache', 'cbt_metadata', 'crashdump',
                     'suspend', 'rrd')
FIX, WAIT, REPORT, UNKNOWN, INFO = 'FIX', 'WAIT', 'REPORT', 'UNKNOWN', 'INFO'


def identity_problem(doc, uuid):
    i = doc.get('identity') or {}
    if not i.get('ok'):
        return 'its identity could not be read: %s' % (i.get('error') or 'not collected')
    if i['value'].get('uuid') != uuid:
        return 'the agent that answered for it is host %s, not %s' % (i['value'].get('uuid'), uuid)
    j = doc.get('identity_after')
    if j is not None:
        if not j.get('ok') or (j.get('value') or {}).get('uuid') != uuid:
            return 'its identity could not be read again after its facts: %s' % (j.get('error') or j.get('value'))
        if j['value'].get('boot_id') != i['value'].get('boot_id'):
            return 'it rebooted while its facts were read'
    return None


class HostView(object):
    def __init__(self, audit, href):
        self.audit = audit
        self.href = href
        m = audit.model
        self.uuid = m.hosts[href]['uuid']
        self.name = m.hosts[href]['name_label']
        self.live = m.host_live(href)
        self.doc = audit.facts.get(self.uuid)
        self.err = audit.errors.get(self.uuid)
        if self.doc is not None:
            why = identity_problem(self.doc, self.uuid)
            if why:
                self.doc, self.err = None, why
        f = (lambda k: audit.fact(self.uuid, k)) if self.doc is not None else (lambda k: None)
        self.taps = f('tapdisks')
        self.backend = f('backend')
        self.phy_list = f('phy')
        self.blktap = f('blktap')
        self.sys_minors = f('sys_minors')
        self.xenstore = f('xenstore')
        self.procs = f('procs')
        self.locks = f('locks')
        self.ipc = f('ipc')
        self.nbd = f('nbd')
        self.ha = f('ha')
        self.xapi = f('xapi')
        self.cookies = f('cookies')
        self.static_vdis = f('static_vdis')
        self.units = f('units')
        self.openers = f('openers')
        self.kholders = f('kholders')
        self.tap_stats = f('tap_stats')
        self.ctl_backlog = f('ctl_backlog')
        self.nbd_vbds = f('nbd_vbds')
        self.smrefs = f('smrefs')
        self.domains = f('domains')
        self.room = f('room')
        self.blockmap = f('blockmap')
        self.sdb = f('storage_db')
        self.identity = f('identity')
        self.caps = audit.caps.get(self.uuid) if self.doc is not None else None
        self.smlog = audit.smlog.get(self.uuid) if self.doc is not None else None
        self.dps_files = f('storage_dps')
        self.tap_major = None
        if self.blktap is not None:
            self.tap_major = (self.blktap.get('majors') or {}).get('tapdev')
        self.back_node = {}
        self.back_minor = {}
        self.attach_info = {}
        for r in self.backend or []:
            if r['kind'] == 'attach_info':
                self.attach_info[(r['sr'], r['vdi'])] = r
                continue
            self.back_node[(r['sr'], r['vdi'])] = r
            if r['kind'] == 'block' and self.tap_major is not None and r['rdev'][0] == self.tap_major:
                self.back_minor.setdefault(r['rdev'][1], []).append(r)
        self.phy = dict(((r['sr'], r['vdi']), r) for r in self.phy_list or [])
        self.phy_owner = collections.defaultdict(set)
        for (s, v), r in self.phy.items():
            if r.get('target'):
                for t in path_variants(r['target']):
                    self.phy_owner[t].add(v)
        known = m.vdi_by_uuid
        self.tap_vdis = collections.defaultdict(list)
        self.row_ident = {}
        self.unmapped = []
        self.unnamed = []
        self.empty_minors = []
        for row in self.taps or []:
            if row['pid'] is None:
                self.empty_minors.append(row)
                continue
            path = row.get('path') or ''
            raw = set(re.findall(UUID_PAT, path))
            ident = set(u for u in raw if u in known) | set(self.phy_owner.get(path) or ())
            self.row_ident[(row['pid'], row['minor'])] = ident
            claimed = set(r['vdi'] for r in self.back_minor.get(row['minor'], []) if row['minor'] is not None)
            for u in sorted(raw | ident | claimed):
                self.tap_vdis[u].append(row)
            if not raw and not self.phy_owner.get(path):
                self.unmapped.append(row)
            elif not ident:
                self.unnamed.append(row)
        self.entries = None
        self.claim = None
        self.keys = {}
        self.sdb_error = None
        if self.sdb is None:
            self.sdb_error = audit.fact_error(self.uuid, 'storage_db')
        elif self.sdb.get('schema_error'):
            self.sdb_error = 'storage.db has an unexpected shape: %s' % self.sdb['schema_error']
        else:
            self.entries = check_storage_db(self.sdb['obj'])
            for sr, key, e in self.entries:
                self.keys[(sr, key)] = entry_vdi(m, sr, key)
            self.claim = collections.defaultdict(list)
            for dp, cl in dp_claimants(self.entries).items():
                for sr, key, st in cl:
                    self.claim[dp].append((sr, self.keys[(sr, key)][0] or key, st, key))
            self.claim = dict(self.claim)

    def live_taps(self):
        return [r for r in self.taps or [] if r['pid'] is not None]

    def ok(self, *keys):
        return self.doc is not None and all(self.audit.fact(self.uuid, k) is not None for k in keys)

    def why(self, *keys):
        if self.doc is None:
            return self.err or 'the host was not audited'
        for k in keys:
            e = self.audit.fact_error(self.uuid, k)
            if e:
                return '%s: %s' % (k, e)
        return None

    def serving(self, sr_type, vdi_uuid):
        if self.taps is None:
            return None, 'tap-ctl list did not answer'
        rows = list(self.tap_vdis.get(vdi_uuid, []))
        if rows:
            return rows, None
        if self.unmapped:
            return None, ('tapdisk pid %s here %s%s, so it is not established that none serves this one'
                          % (self.unmapped[0]['pid'], unmapped_why(self.unmapped[0]),
                             ' (and %d more)' % (len(self.unmapped) - 1) if len(self.unmapped) > 1 else ''))
        m = self.audit.model
        vref = m.vdi_by_uuid.get(vdi_uuid)
        sr = m.srs.get(m.vdis[vref]['SR']) if vref else None
        if sr_type in PATH_SR_TYPES:
            odd = [r for r in self.unnamed if sr is None or sr['uuid'] in (r.get('path') or '')]
        else:
            vols = self.linstor_vols(sr['uuid'], vdi_uuid) if sr is not None and sr_type == 'linstor' else []
            mine = [r for r in self.unnamed if any(v in (r.get('path') or '') for v in vols)]
            if mine:
                return mine, None
            odd = list(self.unnamed)
        if odd:
            return None, ('tapdisk pid %s here serves %s, a name xapi does not know (an image renamed or deleted '
                          'since it was opened, or a volume with no phy link), so it is not established that none '
                          'serves this one' % (odd[0]['pid'], odd[0].get('path')))
        return [], None

    def ident_rows(self, vdi):
        m = self.audit.model
        vref = m.vdi_by_uuid.get(vdi)
        sr = m.srs.get(m.vdis[vref]['SR']) if vref else None
        vols = self.linstor_vols(sr['uuid'], vdi) if sr is not None and sr['type'] == 'linstor' else []
        out = []
        for row in self.live_taps():
            path = row.get('path') or ''
            if vdi in self.row_ident.get((row['pid'], row['minor']), ()) or vdi in re.findall(UUID_PAT, path) or \
                    any(v in path for v in vols):
                out.append(row)
        return out

    def node_state(self, sr, vdi):
        node = self.back_node.get((sr, vdi))
        if node is None:
            return 'none', None, None
        if node['kind'] != 'block':
            return node['kind'], node, None
        if self.tap_major is None or self.taps is None:
            return 'unknown', node, None
        if node['rdev'][0] != self.tap_major:
            return 'nontap', node, None
        at = [r for r in self.live_taps() if r['minor'] == node['rdev'][1]]
        if not at:
            return 'free', node, None
        if any(r in self.ident_rows(vdi) for r in at):
            return 'own', node, at[0]
        return 'other', node, at[0]

    def row_label(self, row):
        m = self.audit.model
        ident = sorted(self.row_ident.get((row['pid'], row['minor'])) or ())
        what = ', '.join(m.name_vdi(m.vdi_by_uuid[u]) for u in ident if u in m.vdi_by_uuid) or \
            '%s:%s' % (row.get('type'), row.get('path'))
        return 'tapdisk pid %s, serving %s' % (row['pid'], what)

    def own_devices(self, sr, vdi):
        paths = set(['%s/%s/%s' % (SM_BACKEND, sr, vdi), '%s/%s/%s' % (SM_PHY, sr, vdi)])
        rdevs = set()
        phy = self.phy.get((sr, vdi))
        if phy:
            if phy.get('target'):
                paths |= path_variants(phy['target'])
            if phy.get('kind') == 'block' and phy.get('rdev'):
                rdevs.add(('b', phy['rdev'][0], phy['rdev'][1]))
        bmaj = ((self.blktap or {}).get('majors') or {}).get('blktap')
        for row in self.ident_rows(vdi):
            if self.tap_major is not None:
                rdevs.add(('b', self.tap_major, row['minor']))
            if bmaj is not None:
                rdevs.add(('c', bmaj, row['minor']))
        state, node, row = self.node_state(sr, vdi)
        if node is not None and node['kind'] == 'block' and state in ('free', 'nontap', 'own', 'unknown'):
            rdevs.add(('b', node['rdev'][0], node['rdev'][1]))
            if state in ('free', 'unknown') and bmaj is not None:
                rdevs.add(('c', bmaj, node['rdev'][1]))
        sr_type = self.sr_type(sr)
        bm = self.blockmap or {}
        devs = []
        if sr_type in LVM_SR_TYPES:
            devs = [(bm.get('dm') or {}).get(n) for n in lv_dm_names(sr, vdi)]
        elif sr_type in PATH_SR_TYPES:
            paths |= image_paths(sr, vdi)
        elif sr_type == 'iso':
            m = self.audit.model
            vref = m.vdi_by_uuid.get(vdi)
            loc = m.vdis[vref].get('location') if vref else None
            if loc:
                paths |= path_variants('%s/%s/%s' % (SR_MOUNT, sr, loc))
        else:
            devs = [(bm.get('drbd') or {}).get(v) for v in self.volumes(vdi)]
        for d in devs:
            if d:
                ma, mi = d.split(':')
                rdevs.add(('b', int(ma), int(mi)))
        return paths, rdevs

    def sr_type(self, sr):
        m = self.audit.model
        sref = m.sr_by_uuid.get(sr)
        return m.srs[sref]['type'] if sref else None

    def volumes(self, vdi):
        evs = ((self.smlog or {}).get('events') or {}).get('phy:' + vdi) or []
        return sorted(set(e[1] for e in evs))

    def linstor_vols(self, sr, vdi):
        out = set(self.volumes(vdi))
        mm = re.search(r'(xcp-volume-' + UUID_PAT + ')', (self.phy.get((sr, vdi)) or {}).get('target') or '')
        if mm:
            out.add(mm.group(1))
        return sorted(out)

    def drbd_unknown(self, sr, vdi):
        if self.sr_type(sr) != 'linstor':
            return None
        if (self.phy.get((sr, vdi)) or {}).get('target'):
            return None
        if self.smlog is None:
            return 'it has no phy link on %s and SMlog there was not read, so its DRBD device is not watched' % self.name
        if not self.volumes(vdi):
            return ('it has no phy link on %s and SMlog there names no LINSTOR volume for it, so its DRBD device is '
                    'not watched' % self.name)
        if self.smlog.get('complete') is not True:
            return ('it has no phy link on %s and not every rotated SMlog there was read, so its DRBD devices are '
                    'not all known' % self.name)
        return None

    def devices_known(self, sr):
        t = self.sr_type(sr)
        if t in PATH_SR_TYPES and t not in LVM_SR_TYPES:
            return True
        if t in LVM_SR_TYPES:
            return self.blockmap is not None
        return self.blockmap is not None and self.smlog is not None

    def holders(self, sr, vdi):
        if self.openers is None or not self.devices_known(sr):
            return None
        paths, rdevs = self.own_devices(sr, vdi)
        out = []
        for h in self.openers:
            hits = [x for x in h['hits'] if x.get('target') in paths or tuple(x.get('rdev') or ()) in rdevs]
            if hits:
                out.append((h, hits))
        return out

    def unreadable(self):
        return [h for h in self.openers or [] if h.get('unread')]

    def kernel_users(self, sr, vdi):
        if self.kholders is None or not self.devices_known(sr):
            return None
        paths, rdevs = self.own_devices(sr, vdi)
        out = []
        for kind, ma, mi in sorted(rdevs):
            if kind != 'b':
                continue
            rec = (self.kholders.get('devs') or {}).get('%d:%d' % (ma, mi))
            if rec is None:
                return None
            out.extend(rec.get('users') or [])
        for l in self.kholders.get('loops') or []:
            if l.get('file') in paths:
                out.append('loop device %s is backed by %s' % (l['loop'], l['file']))
        for s in self.kholders.get('swap_files') or []:
            if s in paths:
                out.append('%s is a swap file' % s)
        return out

    def deaf(self):
        out = []
        for key, st in sorted((self.tap_stats or {}).items()):
            if not st.get('ok') and not st.get('gone') and 'deaf' in (st.get('error') or ''):
                out.append(key)
        return out

    def stats_unknown(self):
        out = []
        for key, st in sorted((self.tap_stats or {}).items()):
            if not st.get('ok') and not st.get('gone') and 'deaf' not in (st.get('error') or ''):
                out.append((key, st.get('error')))
        for row in self.live_taps():
            if row['minor'] is None and row.get('path'):
                out.append(('pid %d' % row['pid'], 'tap-ctl list shows it serving %s:%s with no tap minor, so tap-ctl '
                            'stats cannot be asked' % (row.get('type'), row['path'])))
            elif row['minor'] is None:
                out.append(('pid %d' % row['pid'], 'tap-ctl list shows it with no disk: it serves nothing, or it did '
                            'not answer tap-ctl within 10s, and tap-ctl prints both alike'))
            elif self.tap_stats is not None and '%d:%d' % (row['pid'], row['minor']) not in self.tap_stats:
                out.append(('%d:%d' % (row['pid'], row['minor']), 'not asked'))
        return out

    def proc_alive(self, pid):
        for p in self.procs or []:
            if p['pid'] == pid:
                return p
        return None

    def sm_busy(self):
        out = []
        if self.procs is None:
            return None
        for p in self.procs:
            if p.get('sm'):
                out.append(p)
        return out

    def held_locks(self):
        return self.locks


def gc_state(audit, sr_ref):
    m = audit.model
    sr = m.srs.get(sr_ref)
    if sr is None:
        return 'unknown', ['the SR is gone']
    sr_uuid = sr['uuid']
    reasons = []
    unknown = []
    quiet = []
    for t in m.pending_tasks():
        if m.is_gc_task(t, sr_uuid):
            reasons.append('GC task %s is pending' % t['uuid'])
    if not reasons:
        quiet.append('no GC task is pending')
    mref = m.sr_master(sr_ref)
    if mref is None:
        unknown.append('the SR master is not known')
        return ('running' if reasons else 'unknown'), reasons + unknown
    hv = audit.view(mref)
    caps = hv.caps or {}
    if not (caps.get('cleanup') or {}).get('gc_task'):
        unknown.append('the GC task name could not be confirmed in the installed SM on %s' % hv.name)
    n = len(reasons)
    if hv.procs is None:
        unknown.append('the processes on %s were not read' % hv.name)
    else:
        for p in hv.procs:
            argv = p.get('argv') or []
            if any(a.endswith('cleanup.py') for a in argv) and sr_uuid in argv:
                reasons.append('GC process %d on %s' % (p['pid'], hv.name))
        if len(reasons) == n:
            quiet.append('no GC process on %s' % hv.name)
    n = len(reasons)
    others = [r for r in m.plugged_hosts(sr_ref) if r != mref] if sr['type'] == 'linstor' else []
    for href in [mref] + others:
        hv2 = audit.view(href)
        if hv2.procs is None:
            if href != mref:
                unknown.append('the processes on %s were not read' % hv2.name)
            continue
        for p in hv2.procs:
            argv = p.get('argv') or []
            if p.get('comm') == 'vhd-util' and (any(sr_uuid in a for a in argv) or
                                                sr['type'] == 'linstor' and any('/dev/drbd/' in a for a in argv)):
                reasons.append('vhd-util pid %d on %s works on the SR (%s)' % (p['pid'], hv2.name,
                                                                               ' '.join(argv[:4])[:120]))
            elif sr['type'] == 'linstor' and any(a == PLUGIN_DIR + '/linstor-manager' for a in argv):
                reasons.append('the linstor-manager plugin runs on %s (pid %d), and it coalesces for the GC'
                               % (hv2.name, p['pid']))
    if len(reasons) == n:
        quiet.append('no vhd-util works on the SR')
    lockcap = (caps.get('lock') or {}).get('running') and (caps.get('cleanup') or {}).get('gc_active')
    n = len(reasons)
    if hv.locks is None:
        unknown.append('the lock holders on %s were not read' % hv.name)
    elif not lockcap:
        unknown.append('the GC lock names could not be confirmed in the installed SM on %s' % hv.name)
    else:
        for l in hv.locks:
            if l['path'] in ('%s/%s/gc_active' % (SM_LOCK_DIR, sr_uuid), '%s/%s/running' % (SM_LOCK_DIR, sr_uuid)):
                reasons.append('%s is held by pid %d on %s' % (l['path'], l['pid'], hv.name))
        if len(reasons) == n:
            quiet.append('no GC lock is held on %s' % hv.name)
    if hv.units is None:
        unknown.append('the state of %s on %s was not read' % (unit_name(sr_uuid), hv.name))
    elif hv.units.get(sr_uuid) in ('activating', 'active', 'deactivating', 'reloading'):
        reasons.append('%s is %s on %s' % (unit_name(sr_uuid), hv.units.get(sr_uuid), hv.name))
    else:
        quiet.append('%s is %s on %s' % (unit_name(sr_uuid), hv.units.get(sr_uuid) or 'unknown', hv.name))
    if reasons:
        return 'running', reasons + (['but %s' % '; '.join(quiet + unknown)] if quiet or unknown else [])
    if unknown:
        return 'unknown', unknown
    return 'idle', []


def host_gate(audit, href, opts):
    m = audit.model
    hv = audit.view(href)
    block, unknown = [], []
    for t in m.pending_tasks(href, work=True):
        if m.is_gc_task(t):
            continue
        block.append('task "%s" (%s) is pending on this host' % (t['name_label'], t['uuid']))
    for ref, vm in m.vms.items():
        if vm.get('is_control_domain'):
            continue
        ops = vm.get('current_operations') or {}
        if ops and (vm.get('resident_on') == href or vm.get('scheduled_to_be_resident_on') == href):
            block.append('VM "%s" has %s in progress' % (vm['name_label'], ', '.join(sorted(set(ops.values())))))
        elif vm.get('scheduled_to_be_resident_on') == href:
            block.append('VM "%s" is scheduled to arrive on this host (a start or an incoming migration)'
                         % vm['name_label'])
    if hv.taps is None:
        unknown.append('the tapdisks on this host were not listed: %s' % hv.why('tapdisks'))
    elif hv.tap_stats is None:
        unknown.append('the tapdisks on this host were not asked for their stats: %s' % hv.why('tap_stats'))
    else:
        for key in hv.deaf():
            block.append('tapdisk %s does not answer (C15): nothing that touches tapdisks runs on this host' % key)
        for key, why in hv.stats_unknown():
            unknown.append('tapdisk %s gave no tap-ctl stats (%s), so whether it answers is not established'
                           % (key, why))
    if hv.ctl_backlog is None:
        unknown.append('the tapdisk control sockets were not read: %s' % hv.why('ctl_backlog'))
    else:
        for pid, q in sorted(hv.ctl_backlog.items()):
            if q > 0:
                block.append('tapdisk pid %s has %d connection(s) waiting on its control socket (C15)' % (pid, q))
    if hv.procs is None:
        unknown.append('the processes on this host were not read: %s' % hv.why('procs'))
    if hv.nbd is None:
        unknown.append('NBD connections not established: %s' % hv.why('nbd'))
    elif hv.nbd:
        block.append('%d NBD connection(s) are open on port %d (a backup is reading disks)' % (len(hv.nbd), NBD_PORT))
    if hv.openers is None:
        unknown.append('the openers of disk devices were not established: %s' % hv.why('openers'))
    else:
        for h in hv.openers:
            if h.get('unread'):
                unknown.append('the open files of pid %d (%s) were not read: %s' % (h['pid'], h['comm'], h['unread']))
                continue
            hits = [x for x in h['hits'] if not x.get('generic')]
            if h['comm'] == 'tapdisk' or not hits:
                continue
            block.append('%s (pid %d, %s) holds %s' % (
                h['comm'], h['pid'], 'started %s ago' % format_age(audit.t - h['start']) if h.get('start')
                else 'age unknown', ', '.join(x['what'] for x in hits)))
    for p in stuck_sm(audit, href):
        block.append('SM process %d has run for %s: %s' % (p['pid'], format_age(audit.t - p['start']),
                                                           ' '.join((p.get('argv') or [])[:3])[:160]))
    return block, unknown


def stuck_sm(audit, href):
    hv = audit.view(href)
    out = []
    now = hv.identity['time'] if hv.identity and hv.identity.get('time') else audit.t
    alive = dict((p['pid'], p) for p in hv.procs or [])
    for p in hv.procs or []:
        if not p.get('sm'):
            continue
        argv = p.get('argv') or []
        if any(a.endswith('cleanup.py') for a in argv):
            continue
        if now - p['start'] > STUCK_SM_AGE:
            out.append(p)
    seen = set(p['pid'] for p in out)
    for t, pid, path, blocker in (hv.smlog or {}).get('lockwaits') or []:
        if now - t < STUCK_SM_AGE or pid in seen:
            continue
        w, b = alive.get(pid), alive.get(blocker)
        if w and b and w.get('sm') and w['start'] <= t + 1 and b['start'] <= t + 1:
            out.append(dict(w, blocked_on=path, blocker=blocker))
            seen.add(pid)
    return out


def is_vhd(vdi, sr_type):
    smc = vdi['sm_config']
    return (smc.get('image-format') or smc.get('vdi_type')) == 'vhd'


def vdi_vbds(model, vdi_ref):
    return [(r, model.vbds[r]) for r in model.vdis[vdi_ref]['VBDs'] if r in model.vbds]


def descendants(model, vref):
    out, todo, seen = [], [vref], set([vref])
    while todo:
        v = model.vdis.get(todo.pop())
        if v is None:
            continue
        for c in model.children.get((v['SR'], v['uuid'])) or []:
            if c not in seen and c in model.vdis:
                seen.add(c)
                out.append(model.vdis[c]['uuid'])
                todo.append(c)
    return sorted(out)


PHASES = (('S', 'storage.db (xapi restarted on the host)'), ('V', 'dom0 VBD releases'),
          ('L', 'leaked guest datapaths'), ('F', 'sm-config flags'), ('P', 'paused tapdisks'),
          ('G', 'garbage collector'))
CLASS_TITLES = {
    'C01': 'dead dom0 datapath that duplicates another', 'C02': 'dead dom0 datapath',
    'C03': 'leaked guest datapath', 'C04': 'stale dom0 VBD (snapshot / template / unused disk)',
    'C05': 'stale dom0 VBD on a VM\'s live disk', 'C06': 'dom0 VBD in use', 'C08': 'stale GC abort flag',
    'C09': 'stale relinking key', 'C10': 'stale activating key', 'C11': 'paused key',
    'C12': 'paused tapdisk', 'C13': 'stale host_ attach marker', 'C14': 'orphan tapdisk',
    'C15': 'tapdisk not answering', 'C16': 'leftover', 'C17': 'backup / export activity',
    'C18': 'environment', 'C19': 'garbage collector health',
    'C20': 'backend node pointing at another disk\'s tapdisk', 'C21': 'tapdisk in an abnormal state',
    'C00': 'not audited'}


def ev(key, cls, verdict, host, title, reason, evidence=None, sig=None, item=None):
    if item is not None:
        item = dict(item, sig=sig)
    return {'key': list(key), 'cls': cls, 'verdict': verdict, 'host': host, 'title': title, 'reason': reason,
            'evidence': list(evidence or []), 'sig': sig, 'item': item}


def verdict_of(problems, unknowns, waits):
    if problems:
        return REPORT, '; '.join(problems)
    if unknowns:
        return UNKNOWN, '; '.join(unknowns)
    if waits:
        return WAIT, '; '.join(waits)
    return FIX, ''


def host_time(hv, audit):
    if hv.identity and hv.identity.get('time'):
        return hv.identity['time']
    return audit.t


def major_minor(version):
    parts = _text(version or '').split('.')
    return '.'.join(parts[:2]) if len(parts) >= 2 else None


def xapi_move(a, href):
    m = a.model
    h = m.hosts[href]
    hv = a.view(href)
    sw = h.get('software_version') or {}
    pkg = a.xapi_pkg.get(hv.uuid)
    if pkg is None or hv.xapi is None:
        return None, ('whether a restart would move xapi on %s to another version is not established (the installed '
                      'xapi-core or the running xapi was not read)' % hv.name), []
    exe = hv.xapi.get('exe') or ''
    run_build, inst = sw.get('xapi_build'), pkg.get('version')
    notes, keys = [], []
    if run_build and inst and run_build != inst:
        notes.append('it runs xapi %s, and xapi-core %s-%s is installed' % (run_build, inst, pkg.get('release')))
    elif exe.endswith(' (deleted)'):
        notes.append('its running xapi binary was replaced on disk (xapi-core %s-%s is installed)'
                     % (inst, pkg.get('release')))
    if sw.get('xapi') and major_minor(inst) and sw['xapi'] != major_minor(inst):
        keys.append('xapi %s would become %s' % (sw['xapi'], major_minor(inst)))
    if not run_build and exe.endswith(' (deleted)'):
        return None, ('the running xapi on %s was replaced on disk and its version is not recorded, so what a restart '
                      'would start is not established' % hv.name), notes
    plat, inv_plat = sw.get('platform_version'), pkg.get('platform_version')
    if plat and inv_plat and plat != inv_plat:
        keys.append('platform %s would become %s' % (plat, inv_plat))
        notes.append('its inventory says platform %s, while it runs %s' % (inv_plat, plat))
    return keys, None, notes


def version_split(model):
    master = model.hosts.get(model.pool['master'])
    if master is None:
        return ['the pool master is not in the host list']
    want = master.get('software_version') or {}
    out = []
    for href, h in sorted(model.hosts.items(), key=lambda kv: kv[1]['name_label']):
        sw = h.get('software_version') or {}
        for k in ('platform_version', 'xapi'):
            if sw.get(k) != want.get(k):
                out.append('%s runs %s %s where the master runs %s' % (h['name_label'], k, sw.get(k), want.get(k)))
    return out


UPGRADE_REMEDY = ('finish the update first: restart the toolstack (xe-toolstack-restart) on the pool master, then on '
                  'every other host, or reboot them in that order')


def upgrade_refused(text):
    text = _text(text)
    return 'NOT_SUPPORTED_DURING_UPGRADE' in text or 'not supported during an upgrade' in text.lower()


def eval_hosts(a, opts):
    out = []
    m = a.model
    for href, h in sorted(m.hosts.items(), key=lambda kv: kv[1]['name_label']):
        hv = a.view(href)
        if not hv.live:
            out.append(ev(('ENV', 'live', h['uuid']), 'C18', UNKNOWN, h['uuid'], 'host %s is not live' % h['name_label'],
                          'xapi does not report it live: nothing on it is checked or changed, and xapi is not '
                          'restarted anywhere in this run'))
            continue
        if hv.doc is None:
            out.append(ev(('ENV', 'agent', h['uuid']), 'C18', UNKNOWN, h['uuid'],
                          'host %s could not be audited' % h['name_label'], hv.err or 'no answer',))
            continue
        ident = hv.identity
        if a.t0 is not None and (ident['time'] < a.t0 - 60 or ident['time'] > (a.t or time.time()) + 60):
            out.append(ev(('ENV', 'clock', h['uuid']), 'C18', REPORT, h['uuid'],
                          'the clock on %s is off' % h['name_label'],
                          'it differs from this host\'s by more than a minute: SMlog times are only ever compared '
                          'on the host that wrote them, but check NTP'))
        for key in ('tapdisks', 'openers', 'kholders', 'tap_stats', 'storage_db', 'procs', 'locks', 'nbd', 'ha',
                    'xenstore', 'backend', 'phy', 'ipc', 'blktap', 'sys_minors'):
            err = hv.why(key)
            if err:
                cls = 'C15' if key == 'tapdisks' and 'timed out' in err else 'C18'
                out.append(ev(('ENV', key, h['uuid']), cls, UNKNOWN if cls == 'C18' else REPORT, h['uuid'],
                              '%s on %s not established' % (key, h['name_label']), err))
        rpm = a.rpm.get(h['uuid'])
        if rpm and ident.get('btime'):
            late = sorted(k for k, v in rpm.items() if v > ident['btime'])
            if late:
                out.append(ev(('ENV', 'rpm', h['uuid']), 'C18', REPORT, h['uuid'],
                              'host %s was updated and not rebooted' % h['name_label'],
                              'installed after the last boot: %s. New SM code runs against old daemons until '
                              'it reboots' % ', '.join(late)))
        keys, why, notes = xapi_move(a, href)
        if keys:
            out.append(ev(('ENV', 'xapi-update', h['uuid']), 'C18', REPORT, h['uuid'],
                          'a xapi restart on %s would change its version' % h['name_label'],
                          '%s. storage.db is not edited there, since that restarts xapi: %s, then run this again'
                          % ('; '.join(keys), UPGRADE_REMEDY), notes))
        for p in stuck_sm(a, href):
            out.append(ev(('ENV', 'stuck', h['uuid'], p['pid']), 'C18', REPORT, h['uuid'],
                          'stuck SM operation on %s' % h['name_label'],
                          'pid %d has run for %s: %s' % (p['pid'], format_age(host_time(hv, a) - p['start']),
                                                         ' '.join((p.get('argv') or [])[:4])[:200]),
                          ['no fix on this host, and no xapi stop on it, while it runs']))
        if hv.smlog and hv.smlog.get('refusal_count'):
            last = hv.smlog['refusals'][-1]
            out.append(ev(('ENV', 'gen', h['uuid']), 'C17', REPORT, h['uuid'],
                          'refused disk activations on %s in the last 24h' % h['name_label'],
                          '%d SMlog line(s) "not detached cleanly" / "is still open on host": something (most '
                          'likely a backup job) keeps asking for disks that are in use elsewhere, and dead '
                          'dom0 datapaths will come back. Pause that job before fixing, and run this again '
                          'after its next window' % hv.smlog['refusal_count'],
                          [u'last: %s' % last[2]]))
    return out


def eval_ha(a, opts):
    out = []
    m = a.model
    p = m.pool
    on = p.get('ha_enabled')
    if on not in (True, False):
        out.append(ev(('HA', 'flag'), 'C18', UNKNOWN, None, 'HA state unreadable',
                      'pool.ha_enabled is %s, not true or false' % canon(on)))
        return out
    for href, h in m.hosts.items():
        hv = a.view(href)
        if hv.ha is None:
            continue
        armed, xh = hv.ha['armed'], hv.ha['xhad']
        if not on and (armed == 'true' or xh):
            out.append(ev(('HA', 'incons', h['uuid']), 'C18', REPORT, h['uuid'], 'HA is half on',
                          'pool HA is off, but %s has ha.armed=%s and xhad pid(s) %s' % (h['name_label'], armed, xh)))
        if on and armed not in ('true',):
            out.append(ev(('HA', 'unarmed', h['uuid']), 'C18', REPORT, h['uuid'], 'HA not armed on a host',
                          'pool HA is on, but %s has ha.armed=%s' % (h['name_label'], armed)))
    if on:
        srs = []
        for sf in p.get('ha_statefiles') or []:
            vref = sf if sf.startswith('OpaqueRef:') else m.vdi_by_uuid.get(sf)
            v = m.vdis.get(vref)
            if v is None or v['type'] != 'ha_statefile':
                out.append(ev(('HA', 'statefile'), 'C18', UNKNOWN, None, 'HA statefile not resolvable',
                              'pool.ha_statefiles names %s, which is not an HA statefile VDI' % sf))
                continue
            srs.append(v['SR'])
        if not srs:
            out.append(ev(('HA', 'nostatefile'), 'C18', UNKNOWN, None, 'HA statefile not found',
                          'HA is on but no statefile is listed, so it could not be enabled again'))
        split = version_split(m)
        if split:
            out.append(ev(('HA', 'split'), 'C18', REPORT, None, 'the hosts run different xapi or platform versions',
                          'xapi refuses to enable HA while they differ (NOT_SUPPORTED_DURING_UPGRADE), so HA is not '
                          'turned off by this tool and storage.db is not edited: %s' % UPGRADE_REMEDY, split))
    return out


def entry_vdi(model, sr_uuid, key):
    sref = model.sr_by_uuid.get(sr_uuid)
    sr_type = model.srs[sref]['type'] if sref else None
    found = model.vdi_by_loc.get((sr_uuid, key)) or []
    if len(found) > 1:
        return None, False, '%d VDIs of the SR have the location %s' % (len(found), key)
    mapped = found[0] if found else None
    if UUID_RE.match(key):
        if mapped is not None and mapped != key:
            return mapped, False, 'its storage.db key %s is the location of VDI %s' % (key, mapped)
        vref = model.vdi_by_uuid.get(key)
        if vref is not None and model.vdis[vref]['SR'] != sref:
            return key, False, 'VDI %s is in another SR' % key
    elif mapped is None:
        return None, False, 'its storage.db key %s names no VDI location in the SR' % key
    vdi = mapped or key
    if sr_type is not None and sr_type not in JUDGED_SR_TYPES:
        return vdi, False, 'datapaths on %s SRs are not judged' % sr_type
    if not UUID_RE.match(key):
        return vdi, False, 'its storage.db key is the location %s, not a uuid' % key
    return vdi, True, None


def dom0_backed(a, href):
    m = a.model
    backed = set()
    problem = None
    dom0 = m.dom0_of(href)
    if dom0 is None:
        return None, 'this host has %d control domains in the API' % len(m.dom0.get(href) or [])
    for vbds in (m.vbds, a.vbd2 or {}):
        for vref, vbd in vbds.items():
            if vbd['VM'] != dom0 or not vbd['currently_attached']:
                continue
            vdi = m.vdis.get(vbd['VDI'])
            if vdi is None:
                continue
            try:
                backed.add((vdi['uuid'], 'vbd/0/' + devname(vbd['userdevice'])))
            except ValueError as exc:
                problem = 'dom0 VBD %s: %s' % (vbd['uuid'], _text(exc))
    return backed, problem


def eval_dps(a, opts):
    out = []
    m = a.model
    for href, h in m.hosts.items():
        hv = a.view(href)
        if not hv.live or hv.doc is None:
            continue
        if hv.sdb_error:
            out.append(ev(('SDB', h['uuid']), 'C18', UNKNOWN, h['uuid'], 'storage.db on %s not usable' % h['name_label'],
                          '%s: datapaths on this host are not judged, and its file is never edited' % hv.sdb_error))
            continue
        backed, naming = dom0_backed(a, href)
        if backed is None:
            out.append(ev(('SDB', 'dom0', h['uuid']), 'C18', UNKNOWN, h['uuid'], 'dom0 of %s' % h['name_label'], naming))
            continue
        selfcheck = []
        for vdi, dp in sorted(backed):
            cl = hv.claim.get(dp) or []
            if not any(c[1] == vdi for c in cl):
                selfcheck.append('attached dom0 VBD of VDI %s has no %s in storage.db' % (vdi, dp))
        gate = None
        for dp, cl in sorted(hv.claim.items()):
            g = GUEST_DP_RE.match(dp)
            if not g:
                continue
            for sr, vdi, st, key in cl:
                judged, why = hv.keys[(sr, key)][1:]
                if g.group(1) == '0':
                    if (vdi, dp) in backed:
                        continue
                    if not judged:
                        out.append(not_judged(a, hv, dp, sr, key, vdi, st, why))
                        continue
                    if gate is None:
                        gate = host_gate(a, href, opts)
                    out.append(eval_dom0_dp(a, opts, hv, dp, cl, sr, vdi, st, naming, selfcheck, gate))
                else:
                    e = eval_guest_dp(a, opts, hv, dp, cl, sr, vdi, st)
                    if e is not None and not judged:
                        e = not_judged(a, hv, dp, sr, key, vdi, st, why)
                    if e is not None:
                        if e['verdict'] == FIX:
                            if gate is None:
                                gate = host_gate(a, href, opts)
                            if gate[1] or gate[0]:
                                e['verdict'] = UNKNOWN if gate[1] else WAIT
                                e['reason'] = '; '.join(gate[1] or gate[0])
                                e['item'] = None
                        out.append(e)
        for sr, key, e in hv.entries:
            for dp in sorted(set(e.get('leaked') or []) - set(e.get('dps') or {})):
                out.append(ev(('DPL', h['uuid'], sr, key, dp), 'C16', INFO, h['uuid'],
                              'C16 %s on %s, storage.db key %s' % (dp, h['name_label'], key),
                              'listed in leaked only: xapi holds no datapath by that name for it any more; left '
                              'alone'))
    return out


def not_judged(a, hv, dp, sr, key, vdi, st, why):
    m = a.model
    vref = m.vdi_by_uuid.get(vdi) if vdi else None
    return ev(('DPX', hv.uuid, sr, key, dp), 'C16', REPORT, hv.uuid,
              'C16 %s on %s, %s' % (dp, hv.name, ('VDI ' + m.name_vdi(vref)) if vref else 'storage.db key %s' % key),
              'not judged: %s. Only datapaths of VHD/QCOW2 disks keyed by their uuid are ever changed' % why,
              ['state %s' % canon(st)])


def eval_dom0_dp(a, opts, hv, dp, cl, sr, vdi, st, naming, selfcheck, gate):
    m = a.model
    dup = len(cl) >= 2
    cls = 'C01' if dup else 'C02'
    key = ('DP0', hv.uuid, sr, vdi, dp)
    vref = m.vdi_by_uuid.get(vdi)
    sref = m.sr_by_uuid.get(sr)
    sr_type = m.srs[sref]['type'] if sref else None
    title = '%s %s on %s, VDI %s' % (cls, dp, hv.name, m.name_vdi(vref) if vref else vdi + ' (not in xapi)')
    others = ['%s %s' % (c[1], canon(c[2])) for c in cl if c[1] != vdi]
    evidence = ['state %s; %s' % (canon(st), ('other claimant(s): ' + ', '.join(others)) if others
                                  else 'no other claimant yet: the next export on this name would fail')]
    if st != ['Attached', 'RO']:
        return ev(key, cls, REPORT, hv.uuid, title,
                  'it is %s with no attached dom0 VBD behind it; only Attached/RO datapaths (refused export '
                  'activations) are removed' % canon(st), evidence)
    problems, unknowns, waits = [], [], []
    if sr_type is None:
        unknowns.append('SR %s is not known to xapi, so how this datapath was attached is not established' % sr)
    if naming:
        unknowns.append(naming)
    unknowns.extend(selfcheck)
    if vref and m.vdis[vref].get('current_operations'):
        waits.append('the VDI has %s in progress' % ', '.join(sorted(set(m.vdis[vref]['current_operations'].values()))))
    rows, why = hv.serving(sr_type, vdi)
    if rows is None:
        unknowns.append(why)
    elif rows:
        problems.append('tapdisk pid %s minor %s serves it on this host' % (rows[0]['pid'], rows[0]['minor']))
    if hv.backend is None:
        unknowns.append('backend nodes not read')
    elif (sr, vdi) in hv.back_node:
        problems.append('a backend node exists for it on this host')
    if hv.phy_list is None:
        unknowns.append('phy links not read')
    elif (sr, vdi) in hv.phy:
        problems.append('a phy link exists for it on this host')
    if vref:
        for r, vbd in vdi_vbds(m, vref):
            vm = m.vms.get(vbd['VM'])
            if vm and not vm['is_control_domain'] and vm['resident_on'] == hv.href:
                problems.append('VM "%s", resident on this host, has a VBD on it' % vm['name_label'])
        if m.vdis[vref]['type'] in SPECIAL_VDI_TYPES:
            problems.append('it is an %s VDI' % m.vdis[vref]['type'])
    if hv.static_vdis is None:
        unknowns.append('static VDIs not read')
    elif vdi in hv.static_vdis:
        problems.append('it is a static VDI (HA) on this host')
    entry = None
    for s2, v2, e in hv.entries:
        if (s2, v2) == (sr, vdi):
            entry = e
    if entry is not None and dp in (entry.get('leaked') or []):
        problems.append('it is listed in leaked')
    if sr_type in LVM_SR_TYPES:
        if hv.smrefs is None:
            unknowns.append('the SM refcounts on this host were not read: %s' % hv.why('smrefs'))
        else:
            rc = (hv.smrefs.get('lvm-' + sr) or {}).get(vdi)
            if rc is not None:
                problems.append('SM still counts an activation of its LV on this host (refcount %s): its attach '
                                'is in place, and nothing would ever detach it once the datapath is gone' % rc)
        if hv.blockmap is None:
            unknowns.append('the device-mapper devices on this host were not read: %s' % hv.why('blockmap'))
        else:
            for n in lv_dm_names(sr, vdi):
                if n in (hv.blockmap.get('dm') or {}):
                    problems.append('its LV is active on this host (%s)' % n)
    if sr_type is None or sr_type not in PATH_SR_TYPES:
        if vref is None:
            evidence.append('the VDI no longer exists in xapi')
        else:
            evs = (hv.smlog or {}).get('events', {}).get('phy:' + vdi) or []
            vols = sorted(set(e[1] for e in evs))
            if not vols:
                unknowns.append('its LINSTOR volume could not be named from SMlog, so its DRBD state is not '
                                'established')
            for vol in vols:
                d = (a.drbd.get(hv.uuid) or {}).get(vol)
                if not d or not d.get('ok'):
                    unknowns.append('DRBD state of %s not established: %s' % (vol, (d or {}).get('error')))
                elif d['value'].get('exists') is False:
                    evidence.append('%s: No such resource here' % vol)
                elif d['value'].get('open') == 'no':
                    evidence.append('%s: open:no here' % vol)
                else:
                    problems.append('%s is open here (%s)' % (vol, canon(d['value'].get('open'))))
    keys, why, notes = xapi_move(a, hv.href)
    if why:
        unknowns.append(why)
    elif keys:
        waits.append('a xapi restart on %s would change its version (%s): %s' % (hv.name, '; '.join(keys),
                                                                                UPGRADE_REMEDY))
    for row in hv.live_taps() if hv.taps is not None else []:
        if row['state'] is not None and row['state'] & PAUSED:
            waits.append('tapdisk pid %s minor %s on %s is paused (see C12), and xapi is not restarted next to a '
                         'paused tapdisk' % (row['pid'], row['minor'], hv.name))
        elif row['state'] is not None and row['state'] & ~LOG_DROPPED:
            waits.append('tapdisk pid %s minor %s on %s is in state %s, and xapi is not restarted next to it'
                         % (row['pid'], row['minor'], hv.name, tap_state_text(row['state'])))
    waits.extend(gate[0])
    unknowns.extend(gate[1])
    verdict, reason = verdict_of(problems, unknowns, waits)
    if verdict == FIX:
        reason = 'nothing on %s serves or holds it, and no attached dom0 VBD names it' % hv.name
    item = {'cls': cls, 'phase': 'S', 'action': 'storage-db', 'host': hv.uuid, 'sr': sr, 'vdi': vdi, 'dp': dp,
            'state': st}
    return ev(key, cls, verdict, hv.uuid, title, reason, evidence,
              sig=[dp, st, sorted([c[0], c[1], c[2]] for c in cl)], item=item if verdict == FIX else None)


def eval_guest_dp(a, opts, hv, dp, cl, sr, vdi, st):
    m = a.model
    domid = GUEST_DP_RE.match(dp).group(1)
    vref = m.vdi_by_uuid.get(vdi)
    running = m.domids.get((hv.href, domid)) or []
    for vmref in running:
        for vb in m.vms[vmref]['VBDs']:
            vbd = m.vbds.get(vb)
            if vbd and vbd['currently_attached'] and vref and vbd['VDI'] == vref:
                return None
    key = ('C03', hv.uuid, sr, vdi, dp)
    title = 'C03 %s on %s, VDI %s' % (dp, hv.name, m.name_vdi(vref) if vref else vdi + ' (not in xapi)')
    problems, unknowns, waits = [], [], []
    evidence = ['state %s%s' % (canon(st), ', listed in leaked' if any(
        dp in (e.get('leaked') or []) for s2, v2, e in hv.entries if (s2, v2) == (sr, vdi)) else '')]
    if running:
        problems.append('domid %s now belongs to running VM "%s", which does not have this disk attached' % (
            domid, m.vms[running[0]]['name_label']))
    if hv.domains is None:
        unknowns.append('the domains running on this host were not listed: %s' % hv.why('domains'))
    elif domid in hv.domains and not running:
        problems.append('domain %s runs on this host, but no VM in xapi runs here with that domid' % domid)
    if len(cl) > 1:
        problems.append('%d VDIs claim %s, and host-sm-dp-destroy cannot remove a duplicate' % (len(cl), dp))
    side = dp.replace('/', '-')
    route = None
    if hv.dps_files is None:
        unknowns.append('xapi\'s storage-dps records on this host were not read: %s' % hv.why('storage_dps'))
    elif side not in hv.dps_files:
        problems.append('xapi has no storage-dps/%s record, so xe host-sm-dp-destroy would do nothing' % side)
    else:
        route, why = route_of(hv.dps_files[side], sr, [c[3] for c in cl if c[0] == sr and c[1] == vdi] or [vdi],
                              domid, st)
        if why:
            unknowns.append('xapi routes host-sm-dp-destroy %s by its storage-dps/%s record, and %s, so what the '
                            'destroy would reach is not established' % (dp, side, why))
    if vref is None:
        evidence.append('the VDI is not in xapi any more')
    elif m.vdis[vref]['type'] in SPECIAL_VDI_TYPES:
        problems.append('it is an %s VDI' % m.vdis[vref]['type'])
    if vref is not None and 'paused' in m.vdis[vref]['sm_config']:
        problems.append('the VDI carries sm-config paused: SM refuses to deactivate it, and xapi, told to allow a '
                        'leak, would forget the datapath without tearing it down (see C11)')
    if hv.static_vdis is None:
        unknowns.append('static VDIs not read')
    elif vdi in hv.static_vdis:
        problems.append('it is a static VDI (HA) on this host')
    needs = []
    if vref:
        if m.vdis[vref].get('current_operations'):
            waits.append('the VDI has %s in progress'
                         % ', '.join(sorted(set(m.vdis[vref]['current_operations'].values()))))
        for r, vbd in vdi_vbds(m, vref):
            vm = m.vms.get(vbd['VM'])
            if vm is None or vm['is_control_domain']:
                continue
            if vm['power_state'] in ('Running', 'Paused') and vm['resident_on'] == hv.href:
                problems.append('its VM "%s" runs on this host' % vm['name_label'])
            evidence.append('VM "%s" is %s%s' % (vm['name_label'], vm['power_state'],
                                                 ' on %s' % m.name_host(vm['resident_on'])
                                                 if vm['power_state'] in ('Running', 'Paused') else ''))
    sref = m.sr_by_uuid.get(sr)
    sr_type = m.srs[sref]['type'] if sref else None
    if sr_type is None:
        unknowns.append('SR %s is not known to xapi, so how this datapath was attached is not established' % sr)
    dku = hv.drbd_unknown(sr, vdi)
    if dku:
        unknowns.append(dku)
    ob = orphan_block(a, sr)
    if ob:
        problems.append(ob)
    ou = orphan_unknown(a, sr)
    if ou:
        unknowns.append(ou)
    inert = None
    state, node, at = hv.node_state(sr, vdi)
    if state == 'unknown':
        unknowns.append('the tapdev block major on %s is not established' % hv.name)
    elif state == 'other':
        problems.append('its backend node points at tap minor %d, which now belongs to %s (C20)'
                        % (node['rdev'][1], hv.row_label(at)))
    elif state == 'free':
        inert, why_inert = plan_inert(hv, sr, vdi, sr_type, node)
        if inert is None:
            unknowns.append(why_inert)
        else:
            evidence.append('its backend node points at tap minor %d, on which no tapdisk runs: it is made inert '
                            'first, so SM\'s deactivate cannot reach whatever tapdisk takes that minor next'
                            % node['rdev'][1])
    ku = hv.kernel_users(sr, vdi)
    if ku is None:
        unknowns.append('the kernel users of its devices were not established')
    elif ku:
        problems.append('the kernel uses it: %s' % '; '.join(ku[:4]))
    rows, why = hv.serving(sr_type, vdi)
    if rows is not None and state == 'other':
        rows = [r for r in rows if r is not at]
    if rows is None:
        unknowns.append(why)
    elif rows:
        dom0 = m.dom0_of(hv.href)
        mine = []
        if vref and dom0:
            for r, vbd in vdi_vbds(m, vref):
                if vbd['VM'] == dom0 and vbd['currently_attached']:
                    mine.append(vbd['uuid'])
        if mine:
            needs = mine
            evidence.append('a tapdisk serves it for dom0 VBD(s) %s: they must be released first' % ', '.join(mine))
        else:
            problems.append('tapdisk pid %s serves it, and nothing on this host accounts for that'
                            % rows[0]['pid'])
    if sr_type == 'linstor':
        for vol in hv.linstor_vols(sr, vdi):
            d = (a.drbd.get(hv.uuid) or {}).get(vol)
            if not d or not d.get('ok'):
                unknowns.append('the DRBD state of %s on %s is not established: %s'
                                % (vol, hv.name, (d or {}).get('error') or 'not read'))
            elif d['value'].get('exists') is False:
                evidence.append('%s: No such resource on %s' % (vol, hv.name))
            elif d['value'].get('open') == 'no':
                evidence.append('%s: open:no on %s' % (vol, hv.name))
            elif needs:
                evidence.append('%s is open on %s (%s), as the tapdisk of dom0 VBD(s) %s keeps it'
                                % (vol, hv.name, canon(d['value'].get('open')), ', '.join(needs)))
            else:
                problems.append('%s is open on %s (%s), and nothing in xapi accounts for that'
                                % (vol, hv.name, canon(d['value'].get('open'))))
    verdict, reason = verdict_of(problems, unknowns, waits)
    if verdict == FIX:
        reason = 'no running VM on %s with domid %s has it attached' % (hv.name, domid)
    item = {'cls': 'C03', 'phase': 'L', 'action': 'dp-destroy', 'host': hv.uuid, 'sr': sr, 'vdi': vdi, 'dp': dp,
            'needs': needs, 'inert': inert}
    return ev(key, 'C03', verdict, hv.uuid, title, reason, evidence, sig=[dp, st, len(cl), needs, inert, route],
              item=item if verdict == FIX else None)


def route_of(rec, sr, keys, domid, st):
    c = (rec or {}).get('content')
    if not isinstance(c, dict):
        return None, 'it cannot be read as a JSON object (%s)' % canon(((rec or {}).get('raw') or '')[:120])
    if not set(['sr', 'vdi', 'vm']) <= set(c) <= set(['sr', 'vdi', 'vm', 'read_write']):
        return None, 'it has the fields %s, where xapi writes sr, vdi, vm and read_write' % ', '.join(sorted(c))
    rw = c.get('read_write', True)
    if c['sr'] != sr:
        return None, 'it names SR %s, not %s' % (canon(c['sr']), sr)
    if c['vdi'] not in keys:
        return None, 'it names VDI %s, not %s' % (canon(c['vdi']), ' or '.join(keys))
    if c['vm'] != domid:
        return None, 'it names domain %s, not %s' % (canon(c['vm']), domid)
    if rw is not (st[1] == 'RW'):
        return None, 'it says read_write=%s for a datapath that is %s' % (canon(rw), st[1])
    return [c['sr'], c['vdi'], c['vm'], rw], None


def plan_inert(hv, sr, vdi, sr_type, node):
    if node.get('ino') is None:
        return None, 'the inode of its backend node was not read'
    if sr_type not in ATOMIC_PAUSE_SR_TYPES:
        return None, ('SM does not hold the VDI lock across attach and detach on %s SRs, so its stale backend node '
                      'cannot be made inert safely' % sr_type)
    if hv.unmapped:
        return None, ('tapdisk pid %s here %s, so it is not established that no tapdisk serves this one or holds '
                      'its tap minor' % (hv.unmapped[0]['pid'], unmapped_why(hv.unmapped[0])))
    if sr_type not in PATH_SR_TYPES:
        if (sr, vdi) not in hv.phy:
            return None, 'it has no phy link here, so whether a tapdisk still serves its image is not established'
        rows, why = hv.serving(sr_type, vdi)
        if rows is None:
            return None, why
        rows = [r for r in rows if r['minor'] != node['rdev'][1]]
        if rows:
            return None, 'tapdisk pid %s serves it under another minor' % rows[0]['pid']
    if hv.ident_rows(vdi):
        return None, 'a tapdisk serves it under another minor'
    return {'rdev': list(node['rdev']), 'ino': node['ino'], 'path_sr': sr_type in PATH_SR_TYPES}, None


def eval_vbds(a, opts):
    out = []
    m = a.model
    for vbref, vbd in sorted(m.vbds.items(), key=lambda kv: kv[1]['uuid']):
        vm = m.vms.get(vbd['VM'])
        if not vm or not vm['is_control_domain']:
            continue
        vdi = m.vdis.get(vbd['VDI'])
        if vdi is None:
            continue
        e = eval_vbd(a, opts, vbd, vm, vdi)
        if e is not None:
            out.append(e)
    return out


def eval_vbd(a, opts, vbd, vm, vdi):
    m = a.model
    href = vm['resident_on']
    hname = m.name_host(href)
    key = ('VBD', vbd['uuid'])
    sref = vdi['SR']
    sr = m.srs.get(sref)
    sr_uuid = sr['uuid'] if sr else None
    sr_type = sr['type'] if sr else None
    title = 'dom0 VBD %s on %s, VDI %s' % (vbd['uuid'], hname, m.name_vdi(vbd['VDI']))
    owners = []
    for r, v2 in vdi_vbds(m, vbd['VDI']):
        o = m.vms.get(v2['VM'])
        if o is not None and not o['is_control_domain']:
            owners.append((o, v2))
    regular = [(o, v2) for o, v2 in owners if not o['is_a_template'] and not o['is_a_snapshot']]
    cls = 'C04' if not regular else 'C05'
    evidence = ['attached: %s; VDI %s%s' % ('yes' if vbd['currently_attached'] else 'no',
                                            'is a snapshot' if vdi['is_a_snapshot'] else 'type %s' % vdi['type'],
                                            '; owner(s): ' + ', '.join('"%s" %s' % (o['name_label'], o['power_state'])
                                                                       for o, _ in regular) if regular else '')]
    if href not in m.hosts:
        return ev(key, cls, UNKNOWN, None, title, 'its control domain is not resident on a known host', evidence)
    hv = a.view(href)
    if not hv.live or hv.doc is None:
        return ev(key, cls, UNKNOWN, hv.uuid, title, 'host %s was not audited' % hname, evidence)
    problems, unknowns, waits = [], [], []
    if vdi['type'] in SPECIAL_VDI_TYPES:
        return ev(key, cls, REPORT, hv.uuid, title, 'the VDI is an %s VDI: never touched' % vdi['type'], evidence)
    if sr is None:
        return ev(key, cls, UNKNOWN, hv.uuid, title, 'the SR of its VDI is not known to xapi', evidence)
    if sr_type not in JUDGED_SR_TYPES + ('iso',):
        return ev(key, cls, REPORT, hv.uuid, title, 'dom0 VBDs on %s SRs are not released by this tool' % sr_type,
                  evidence)
    if 'force_loopback_vbd' in (m.pool.get('other_config') or {}):
        return ev(key, cls, REPORT, hv.uuid, title, 'the pool sets other-config:force_loopback_vbd, so dom0 disks are '
                  'xvd devices whose users this tool cannot see; dom0 VBDs are not released', evidence)
    want_dev = 'sm/backend/%s/%s' % (sr_uuid, vdi['uuid'])
    if vbd['currently_attached'] and vbd.get('device') != want_dev:
        return ev(key, cls, REPORT, hv.uuid, title, 'it is plugged as %s, not %s: whoever reads it opens a device '
                  'this tool does not watch, so it is not released' % (canon(vbd.get('device')), want_dev), evidence)
    if vbd.get('current_operations'):
        waits.append('the VBD has %s in progress' % ', '.join(sorted(set(vbd['current_operations'].values()))))
    if vdi.get('current_operations'):
        waits.append('the VDI has %s in progress' % ', '.join(sorted(set(vdi['current_operations'].values()))))
    oc = vbd.get('other_config') or {}
    if oc.get('task_id'):
        t = m.tasks.get(oc['task_id'])
        if t is not None and t['status'] in ('pending', 'cancelling'):
            waits.append('task "%s" (%s), which created the VBD, is %s' % (t['name_label'], t['uuid'], t['status']))
    if oc.get('related_to'):
        rv = m.vbds.get(oc['related_to'])
        if rv is not None and rv['currently_attached']:
            waits.append('it is related to VBD %s, which is attached' % rv['uuid'])
    if hv.nbd_vbds is None:
        unknowns.append('the VBDs xapi-nbd serves on %s were not read: %s' % (hname, hv.why('nbd_vbds')))
    elif vbd['uuid'] in hv.nbd_vbds:
        waits.append('xapi-nbd lists it as its own (an NBD export of this disk); it unplugs it itself when the '
                     'export ends')
    elif not oc.get('task_id'):
        problems.append('it was not made by xapi\'s own disk helpers (it has no other-config:task_id) and xapi-nbd '
                        'does not list it: it may be someone\'s recovery or maintenance attach, so it is left alone. '
                        'Once nobody uses it: %sxe vbd-destroy uuid=%s'
                        % ('xe vbd-unplug uuid=%s, then ' % vbd['uuid'] if vbd['currently_attached'] else '',
                           vbd['uuid']))
    smc = vdi['sm_config']
    if vbd['currently_attached'] and 'paused' in smc:
        problems.append('the VDI carries sm-config paused, so SM would refuse to deactivate it (see C11)')
    if vbd['currently_attached'] and 'relinking' in smc:
        problems.append('the VDI carries sm-config relinking (see C09): the GC pauses and refreshes its tapdisk to '
                        'relink it, and a deactivate would race that')
    if 'activating' in smc:
        waits.append('the VDI carries sm-config activating: an activation of it is in progress (or see C10)')
    state, node_, at = (hv.node_state(sr_uuid, vdi['uuid']) if hv.backend is not None
                        else ('unread', None, None))
    if cls == 'C05':
        running = [(o, v2) for o, v2 in regular if o['power_state'] in ('Running', 'Paused')]
        if any(o['resident_on'] == href for o, _ in running):
            return ev(key, 'C05', REPORT, hv.uuid, title,
                      'the disk belongs to a VM running on this same host; not handled', evidence)
        susp = [o for o, _ in regular if o['power_state'] not in ('Running', 'Paused', 'Halted')]
        if susp:
            return ev(key, 'C05', REPORT, hv.uuid, title, 'the disk belongs to VM "%s", which is %s, not halted; not '
                      'handled' % (susp[0]['name_label'], susp[0]['power_state']), evidence)
        if 'c05' not in opts.include:
            return ev(key, 'C05', REPORT, hv.uuid, title,
                      'the disk is a live disk of a VM; releasing it is opt-in (--include c05)', evidence)
        if not running:
            if any(v2['currently_attached'] for o, v2 in owners):
                problems.append('a VM VBD on the disk is attached')
        else:
            if any(v2['currently_attached'] and o['resident_on'] == href for o, v2 in owners):
                problems.append('a VM on this host has the disk attached')
            rows, why = hv.serving(sr_type, vdi['uuid'])
            if rows is not None and state == 'other':
                rows = [r for r in rows if r is not at]
            if rows is None:
                unknowns.append(why)
            elif rows:
                problems.append('a tapdisk still serves it on this host (pid %s)' % rows[0]['pid'])
    hold = hv.holders(sr_uuid, vdi['uuid'])
    if hold is None:
        unknowns.append('the openers of its devices were not established')
    else:
        exp = [(h, hits) for h, hits in hold if h['comm'] != 'tapdisk']
        if exp:
            h = exp[0][0]
            age = host_time(hv, a) - h['start'] if h.get('start') is not None else None
            txt = '%s (pid %d, %s) holds %s' % (h['comm'], h['pid'], 'running %s' % format_age(age) if age is not None
                                                else 'age unknown', ', '.join(x['target'] for x in exp[0][1]))
            if age is not None and age > opts.stuck_export_age:
                return ev(key, 'C06', REPORT, hv.uuid, title, 'stuck export: ' + txt +
                          '. Ending it is your call; this tool never kills processes', evidence)
            return ev(key, 'C06', WAIT, hv.uuid, title, 'an export is reading it: ' + txt, evidence)
    if vbd['currently_attached']:
        ku = hv.kernel_users(sr_uuid, vdi['uuid'])
        if ku is None:
            unknowns.append('the kernel users of its devices were not established')
        elif ku:
            return ev(key, 'C06', REPORT, hv.uuid, title, 'the kernel uses it: %s. Unmount or remove that first; '
                      'this tool never does' % '; '.join(ku[:4]), evidence)
        dku = hv.drbd_unknown(sr_uuid, vdi['uuid'])
        if dku:
            unknowns.append(dku)
        if sr_type == 'linstor':
            for vol in hv.linstor_vols(sr_uuid, vdi['uuid']):
                st, why = drbd_health((a.drbd.get(hv.uuid) or {}).get(vol))
                if st == 'unknown':
                    unknowns.append('the DRBD state of %s on %s is not established: %s' % (vol, hname, why))
                elif st == 'bad':
                    problems.append('DRBD resource %s on %s is not healthy (%s): fix the DRBD state first, then '
                                    'xe sr-scan the SR, then release it (xostor KB, VBD stuck on control domain)'
                                    % (vol, hname, why))
                else:
                    evidence.append('DRBD %s on %s: %s' % (vol, hname, why))
    node = hv.back_node.get((sr_uuid, vdi['uuid'])) if hv.backend is not None else None
    local = bool(node) or bool(hv.tap_vdis.get(vdi['uuid'])) or any(
        c[1] == vdi['uuid'] for dp, cl in (hv.claim or {}).items() for c in cl)
    mydp = None
    try:
        mydp = 'vbd/0/' + devname(vbd['userdevice'])
    except ValueError as exc:
        if vbd['currently_attached']:
            unknowns.append('its datapath name is not established: %s' % _text(exc))
    side = None
    if mydp and hv.dps_files is not None:
        f = hv.dps_files.get(mydp.replace('/', '-'))
        named = ((f or {}).get('content') or {}).get('vdi')
        if f is not None and f.get('mtime') is not None and named and named in (vdi['uuid'], vdi.get('location')):
            side = f
    if hv.backend is None or hv.taps is None:
        unknowns.append('the backend nodes and tapdisks on %s were not established' % hname)
    elif local:
        ages = []
        if node is not None:
            ages.append(host_time(hv, a) - node['mtime'])
            evidence.append('backend node created %s ago' % format_age(ages[-1]))
        if side is not None:
            ages.append(host_time(hv, a) - side['mtime'])
            evidence.append('xapi recorded the attach of %s %s ago' % (mydp, format_age(ages[-1])))
        if not ages:
            evs = (hv.smlog or {}).get('events', {}).get('activate:' + vdi['uuid']) or []
            if evs:
                ages.append(host_time(hv, a) - evs[-1][0])
                evidence.append('last vdi_activate %s ago' % format_age(ages[-1]))
            else:
                unknowns.append('its age is not established (no backend node, no attach record, no vdi_activate '
                                'in SMlog)')
        if ages and min(ages) < opts.min_vbd_age:
            waits.append('it is only %s old (--min-vbd-age %s)' % (format_age(min(ages)),
                                                                     format_age(opts.min_vbd_age)))
    if hv.claim is None and not local:
        unknowns.append('storage.db on %s is not usable, so whether an attach is in progress is not established'
                        % hname)
    if vbd['currently_attached'] and mydp and hv.claim is not None:
        per_sr = collections.Counter(c[0] for c in hv.claim.get(mydp, []))
        if any(n > 1 for n in per_sr.values()):
            evidence.append('%s has a dead duplicate in storage.db (C01): the unplug can only work once that is '
                            'removed' % mydp)
    gate, gate_unknown = host_gate(a, href, opts)
    waits.extend(gate)
    unknowns.extend(gate_unknown)
    ob = orphan_block(a, sr_uuid)
    if ob:
        problems.append(ob)
    ou = orphan_unknown(a, sr_uuid)
    if ou:
        unknowns.append(ou)
    inert = None
    if vbd['currently_attached'] and hv.backend is not None and hv.taps is not None:
        mine = hv.ident_rows(vdi['uuid'])
        for row in mine:
            if row['state'] is None:
                unknowns.append('the state of its tapdisk pid %s is not known' % row['pid'])
            elif row['state'] & ~LOG_DROPPED:
                problems.append('its tapdisk pid %s is in state %s, not running%s' % (
                    row['pid'], tap_state_text(row['state']),
                    ': it is paused, and SM would deactivate it in the middle of whatever paused it (see C12)'
                    if row['state'] & PAUSED else ''))
        if state == 'unknown':
            unknowns.append('the tapdev block major on %s is not established' % hname)
        elif len(mine) > 1:
            problems.append('%d tapdisks serve it on this host' % len(mine))
        elif state in ('other', 'free'):
            n = node_['rdev'][1]
            if mine:
                problems.append('its tapdisk pid %s runs on minor %s, but its backend node points at minor %d'
                                % (mine[0]['pid'], mine[0]['minor'], n))
            else:
                inert, why = plan_inert(hv, sr_uuid, vdi['uuid'], sr_type, node_)
                if inert is None:
                    unknowns.append(why)
                elif state == 'other':
                    evidence.append('its tapdisk is gone and tap minor %d now belongs to %s: SM\'s own deactivate '
                                    'would shut that tapdisk down, so the backend node is made inert first'
                                    % (n, hv.row_label(at)))
                else:
                    ring = ((hv.blktap or {}).get('blktap') or {}).get(str(n))
                    evidence.append('its tapdisk is gone and no tapdisk runs on tap minor %d%s: the backend node is '
                                    'made inert first, so SM\'s deactivate cannot reach whatever tapdisk takes that '
                                    'minor next' % (n, ' (blktap%d is a leftover file)' % n if ring else ''))
        elif state != 'own' and mine:
            problems.append('tapdisk pid %s serves it, but its backend node is %s, so SM would not close it'
                            % (mine[0]['pid'], 'missing' if state == 'none' else state))
    verdict, reason = verdict_of(problems, unknowns, waits)
    if verdict == FIX:
        reason = ('nothing reads it, it is %s' % ('a snapshot' if vdi['is_a_snapshot'] else
                                                  'not a disk of any running or halted VM' if cls == 'C04'
                                                  else 'the disk of a VM that is halted or runs elsewhere'))
    item = {'cls': cls, 'phase': 'V', 'action': 'release-vbd', 'host': hv.uuid, 'vbd': vbd['uuid'],
            'vdi': vdi['uuid'], 'sr': sr_uuid, 'attached': vbd['currently_attached'], 'inert': inert,
            'victim': [at['pid'], at['minor'], at.get('path')] if inert and state == 'other' else None}
    return ev(key, cls, verdict, hv.uuid, title, reason, evidence,
              sig=[vbd['currently_attached'], vdi['uuid'], state, inert], item=item if verdict == FIX else None)


def eval_vdis(a, opts):
    out = []
    m = a.model
    abort_srs = set()
    ipc_unknown = set()
    for href in m.hosts:
        hv = a.view(href)
        if hv.ipc is None:
            ipc_unknown.add(href)
        for f in hv.ipc or []:
            if f['name'] == 'abort':
                abort_srs.add(f['sr'])
    a.ipc_unknown = ipc_unknown
    activating_srs = set(v['SR'] for v in m.vdis.values() if 'activating' in v['sm_config'])
    for vref, v in sorted(m.vdis.items(), key=lambda kv: kv[1]['uuid']):
        smc = v['sm_config']
        if 'activating' in smc:
            out.append(eval_flag(a, opts, vref, v, 'activating', abort_srs, activating_srs))
        if 'relinking' in smc:
            out.append(eval_flag(a, opts, vref, v, 'relinking', abort_srs, activating_srs))
        if 'paused' in smc:
            out.append(eval_paused_key(a, opts, vref, v))
        for k in smc:
            if k.startswith('host_'):
                e = eval_marker(a, opts, vref, v, k)
                if e is not None:
                    out.append(e)
    return out


def flag_common(a, vref, v, key):
    m = a.model
    sref = v['SR']
    sr = m.srs.get(sref)
    problems, unknowns = [], []
    smc = v['sm_config']
    hosts_ = [k for k in smc if k.startswith('host_')]
    if hosts_:
        problems.append('it also carries %s: attach state is never removed by hand' % ', '.join(hosts_))
    others = [k for k in ('paused', 'relinking', 'activating') if k != key and k in smc]
    if others:
        problems.append('it also carries %s' % ', '.join(others))
    for r, vbd in vdi_vbds(m, vref):
        if vbd['currently_attached']:
            problems.append('VBD %s is attached' % vbd['uuid'])
    if sr is None or not is_vhd(v, sr['type']):
        problems.append('its image format is not established as vhd (%s)'
                        % (v['sm_config'].get('image-format') or v['sm_config'].get('vdi_type') or 'no format key'))
    plugged = m.plugged_hosts(sref) if sr else []
    if not plugged:
        unknowns.append('no host has the SR plugged, so no host can be asked whether it is open')
    for href in plugged:
        hu = m.hosts[href]['uuid']
        ans = a.probes.get((v['uuid'], hu))
        if ans == 'False':
            continue
        if ans == 'True':
            problems.append('on-slave is_open says a tapdisk on %s has it open' % m.name_host(href))
        else:
            unknowns.append('is_open on %s: %s' % (m.name_host(href), ans or 'not asked'))
    desc = descendants(m, vref)
    for href in plugged:
        hv = a.view(href)
        rows, why = hv.serving(sr['type'] if sr else None, v['uuid'])
        if rows is None:
            unknowns.append('the tapdisks on %s: %s' % (hv.name, why))
        elif rows:
            problems.append('tapdisk pid %s on %s serves it, whatever is_open answers' % (rows[0]['pid'], hv.name))
        for du in desc:
            r2 = hv.ident_rows(du)
            if r2:
                problems.append('tapdisk pid %s on %s serves VDI %s, which sits on it in its chain'
                                % (r2[0]['pid'], hv.name, du))
                break
        if hv.procs is None:
            unknowns.append('the processes on %s were not read' % hv.name)
        if hv.locks is None:
            unknowns.append('the SM locks on %s were not read' % hv.name)
            continue
        for l in hv.locks:
            if l['path'] == '%s/%s/vdi' % (SM_LOCK_DIR, v['uuid']):
                problems.append('its SM lock is held by pid %d on %s' % (l['pid'], hv.name))
        for p in stuck_sm(a, href):
            problems.append('a stuck SM operation on %s (pid %d) may own it' % (hv.name, p['pid']))
    return problems, unknowns


def eval_flag(a, opts, vref, v, key, abort_srs, activating_srs):
    m = a.model
    cls = 'C10' if key == 'activating' else 'C09'
    sr = m.srs.get(v['SR'])
    sr_uuid = sr['uuid'] if sr else None
    title = '%s %s on VDI %s' % (cls, key, m.name_vdi(vref))
    k = (cls, v['uuid'])
    evidence = ['SR %s' % m.name_sr(v['SR'])]
    if key == 'relinking' and not m.is_leaf(vref):
        return ev(k, cls, INFO, None, title, 'not a leaf: nothing activates a base copy, so the key is inert there; '
                  'left alone', evidence)
    problems, unknowns = flag_common(a, vref, v, key)
    waits = []
    ob = orphan_block(a, sr_uuid) if sr_uuid else None
    if ob:
        problems.append(ob)
    ou = orphan_unknown(a, sr_uuid) if sr_uuid else None
    if ou:
        unknowns.append(ou)
    gstate, greasons = gc_state(a, v['SR'])
    sig = [key]
    for href in (m.plugged_hosts(v['SR']) if sr else []):
        tag = (((a.caps.get(m.hosts[href]['uuid']) or {}).get('blktap2') or {}).get('add_tag'))
        if tag is None:
            unknowns.append('how SM on %s checks sm-config when it activates was not read' % m.name_host(href))
        elif not (tag.get('relinking') and tag.get('paused') and tag.get('activating')):
            problems.append('SM on %s does not check relinking, paused and activating when it activates the way '
                            'this tool knows, so what the key does there is not established' % m.name_host(href))
    item_extra = {}
    if key == 'activating':
        smref = m.sr_master(v['SR']) if sr else None
        near = set(m.plugged_hosts(v['SR']) if sr else []) | set([smref] if smref else [])
        near |= set(r for r in m.hosts if a.view(r).tap_vdis.get(v['uuid']))
        for href in sorted(m.hosts):
            hv = a.view(href)
            if href not in near and (not hv.live or hv.smlog is None):
                continue
            if not hv.live:
                unknowns.append('%s is not live, so whether it activated the disk recently is not established'
                                % hv.name)
                continue
            if hv.smlog is None:
                unknowns.append('SMlog on %s was not read' % hv.name)
                continue
            evs = hv.smlog.get('events', {}).get('activate:' + v['uuid']) or []
            if evs and host_time(hv, a) - evs[-1][0] < ACTIVATE_QUIET:
                waits.append('vdi_activate for it %s ago on %s' % (format_age(host_time(hv, a) - evs[-1][0]), hv.name))
        if gstate == 'running':
            evidence.append('GC running on the SR: %s' % '; '.join(greasons))
        smref = m.sr_master(v['SR']) if sr else None
        tags = (a.view(smref).smlog or {}).get('failed_tag') or [] if smref else []
        item_extra['kick'] = any(e[2] == v['uuid'][:8] for e in tags)
        if item_extra['kick']:
            evidence.append('the GC failed to tag it for relink: the SR\'s GC is started again once it is removed')
    else:
        smref = m.sr_master(v['SR']) if sr else None
        if smref is None or smref in getattr(a, 'ipc_unknown', set()):
            unknowns.append('the GC abort flags on the SR master were not read')
        if smref is not None and not (((a.caps.get(m.hosts[smref]['uuid']) or {}).get('cleanup') or {})
                                      .get('relinking_key')):
            unknowns.append('the installed GC on %s does not name the relinking key the way this tool knows'
                            % m.name_host(smref))
        if sr and sr_uuid in abort_srs:
            waits.append('the SR has a GC abort flag (C08): fixed first, and the GC then clears this itself')
        if sr and v['SR'] in activating_srs:
            waits.append('the SR has a VDI with activating (C10): fixed first, and the GC then clears this itself')
        if smref is not None and sr:
            jr, jwhy = relink_journals(a, m.hosts[smref]['uuid'], sr)
            if jr is None:
                unknowns.append(jwhy)
            else:
                live = [j for j in jr if j in m.vdi_by_uuid]
                if live:
                    waits.append('a GC relink journal exists for %s: the GC finishes that relink first and removes '
                                 'the key itself' % ', '.join(live))
                elif jr:
                    evidence.append('relink journal(s) name VDI(s) that are gone: %s' % ', '.join(jr))
        if smref is not None:
            sets = [e for e in ((a.view(smref).smlog or {}).get('events', {}).get('relink:' + v['uuid'][:8]) or [])
                    if e[1] == 'set']
            if sets:
                sig.append([sets[-1][0], sets[-1][2]])
        if gstate != 'idle':
            proof, why = relink_override(a, opts, v, sr)
            if proof is None:
                if gstate == 'running':
                    waits.append('GC is running on the SR (%s) and SMlog does not prove the key stale: %s'
                                 % ('; '.join(greasons), why))
                else:
                    unknowns.append('whether a GC runs on the SR is not established (%s), and SMlog does not '
                                    'prove the key stale: %s' % ('; '.join(greasons), why))
            else:
                evidence.append(proof['text'])
        else:
            proof, why = relink_override(a, opts, v, sr)
            if proof is not None:
                evidence.append(proof['text'])
    verdict, reason = verdict_of(problems, unknowns, waits)
    if verdict == FIX:
        reason = 'no host has it open, no VBD is attached, and %s' % (
            'no GC runs on its SR' if gstate == 'idle' else 'SMlog proves the GC that set it is gone')
    item = {'cls': cls, 'phase': 'F', 'action': 'remove-key', 'vdi': v['uuid'], 'key': key, 'sr': sr_uuid,
            'host': None}
    item.update(item_extra)
    return ev(k, cls, verdict, None, title, reason, evidence, sig=sig, item=item if verdict == FIX else None)


def relink_journals(a, master_uuid, sr):
    if sr['type'] in LVM_SR_TYPES:
        names = a.lvnames.get((master_uuid, 'VG_XenStorage-' + sr['uuid']))
        if names is None:
            return None, 'the LVs of the SR were not listed on its master, so its GC relink journals are not known'
        names = [n for n, attr in names]
        pat = re.compile(r'^relink_(' + UUID_PAT + r')_')
    elif sr['type'] in PATH_SR_TYPES:
        names = a.srdirs.get((master_uuid, sr['uuid']))
        if names is None:
            return None, 'the SR directory was not listed on its master, so its GC relink journals are not known'
        pat = re.compile(r'^relink_(' + UUID_PAT + r')$')
    else:
        return None, 'the GC relink journals of a %s SR cannot be listed by this tool' % sr['type']
    return sorted(set(m_.group(1) for m_ in (pat.match(n) for n in names) if m_)), None


def relink_override(a, opts, v, sr):
    m = a.model
    if sr is None:
        return None, 'the SR is gone'
    u8 = v['uuid'][:8]
    if m.vdi_uuid8[u8] != 1:
        return None, '%s is not unique among the pool\'s VDIs' % u8
    mref = m.sr_master(v['SR'])
    if mref is None:
        return None, 'the SR master is not known'
    hv = a.view(mref)
    if hv.smlog is None:
        return None, 'SMlog on %s was not read' % hv.name
    caps = (hv.caps or {}).get('cleanup') or {}
    if not (caps.get('set_fmt') and caps.get('del_fmt')):
        return None, 'the installed GC on %s does not log relinking in the known format' % hv.name
    evs = hv.smlog.get('events', {}).get('relink:' + u8) or []
    sets = [e for e in evs if e[1] == 'set']
    if not sets:
        return None, 'no "Set relinking" line for %s in %s\'s SMlog%s' % (
            u8, hv.name, '' if hv.smlog.get('complete') is True else ' (not every rotated log was read)')
    last = sets[-1]
    if any(e[1] == 'removed' and e[0] >= last[0] for e in evs):
        return None, 'SMlog shows it removed after it was last set'
    age = host_time(hv, a) - last[0]
    if age < opts.relink_min_age:
        return None, 'it was set %s ago, less than --relink-min-age %s' % (format_age(age), format_age(opts.relink_min_age))
    pinfo = a.pidinfo.get((hv.uuid, last[2]))
    if pinfo is None:
        return None, 'whether its setter, pid %d, is alive was not established' % last[2]
    if pinfo.get('alive') and (pinfo.get('sm') or pinfo.get('start', 0) <= last[0] + 1):
        return None, 'its setter, pid %d, is still alive' % last[2]
    return {'set': [last[0], last[2]],
            'text': 'set %s ago by GC pid %d, which is gone, and never removed' % (format_age(age), last[2])}, None


def eval_paused_key(a, opts, vref, v):
    m = a.model
    k = ('C11', v['uuid'])
    title = 'C11 paused key on VDI %s' % m.name_vdi(vref)
    paused_taps = []
    unknown = []
    for href in m.hosts:
        hv = a.view(href)
        if not hv.live:
            continue
        if hv.taps is None:
            unknown.append(hv.name)
            continue
        for row in hv.tap_vdis.get(v['uuid'], []):
            if row['state'] is not None and row['state'] & PAUSED:
                paused_taps.append((hv.name, row))
    gstate, greasons = gc_state(a, v['SR'])
    evidence = ['GC on its SR: %s' % gstate]
    mref = m.sr_master(v['SR'])
    hosts = ([mref] if mref is not None else []) + sorted(
        r for r in m.hosts if r != mref and a.view(r).tap_vdis.get(v['uuid']))
    for href in hosts:
        h2 = a.view(href)
        if h2.smlog is None:
            evidence.append('SMlog on %s was not read' % h2.name)
            continue
        evs = sorted(((h2.smlog.get('events') or {}).get('preq:' + v['uuid']) or []) +
                     [[e[0], 'plugin ' + e[1], e[2]] for e in (h2.smlog.get('events') or {}).get('pause:' + v['uuid'])
                      or []])
        if evs:
            evidence.append('pause history on %s: %s' % (h2.name, '; '.join(
                '%s %s ago by pid %d' % (e[1], format_age(host_time(h2, a) - e[0]), e[2]) for e in evs[-3:])))
        else:
            evidence.append('no pause request for it in the SMlog of %s' % h2.name)
    busy = m.pending_tasks()
    evidence.append('pending task(s) in the pool: %s' % (', '.join('"%s" (%s)' % (t['name_label'], t['uuid'])
                                                                  for t in busy[:4]) if busy else 'none'))
    if paused_taps:
        evidence.append('paused tapdisk(s): %s' % ', '.join('%s pid %s' % (n, r['pid']) for n, r in paused_taps))
        return ev(k, 'C11', REPORT, None, title, 'a snapshot, coalesce or relink holds it paused (see C12)', evidence)
    if unknown:
        return ev(k, 'C11', UNKNOWN, None, title, 'tapdisks on %s not read' % ', '.join(unknown), evidence)
    return ev(k, 'C11', REPORT, None, title, 'the key is set but no tapdisk is paused for it; never seen stale on '
              'its own, so it is only reported (SM removes it when the pause it belongs to finishes)', evidence)


def eval_marker(a, opts, vref, v, key):
    m = a.model
    href = key[len('host_'):]
    title = 'C13 %s on VDI %s' % (key, m.name_vdi(vref))
    k = ('C13', v['uuid'], key)
    if href not in m.hosts:
        return ev(k, 'C13', REPORT, None, title, 'the marker names a host that is not in the pool any more')
    hv = a.view(href)
    if not hv.live or hv.doc is None or hv.taps is None or hv.backend is None:
        return None
    sr = m.srs.get(v['SR'])
    if hv.tap_vdis.get(v['uuid']) or (sr and (sr['uuid'], v['uuid']) in hv.back_node):
        return None
    vbds = []
    for r, vbd in vdi_vbds(m, vref):
        vm = m.vms.get(vbd['VM'])
        if vm and vbd['currently_attached'] and vm['resident_on'] == href:
            return None
        if vm:
            vbds.append('VBD %s of %s (%s, %s)' % (vbd['uuid'], 'dom0' if vm['is_control_domain'] else
                                                    'VM "%s"' % vm['name_label'], vm['power_state'],
                                                    'attached' if vbd['currently_attached'] else 'not attached'))
    return ev(k, 'C13', REPORT, None, title,
              'nothing on %s has it attached: a proper deactivate (releasing its dom0 VBD) or SM\'s own reset '
              'removes it; it is never removed by hand' % hv.name, vbds or ['it has no VBDs'])


def eval_aborts(a, opts):
    out = []
    m = a.model
    for href in m.hosts:
        hv = a.view(href)
        for f in hv.ipc or []:
            if f['name'] != 'abort':
                continue
            out.append(eval_abort(a, opts, hv, f))
    return out


def eval_abort(a, opts, hv, f):
    m = a.model
    sr_uuid = f['sr']
    sref = m.sr_by_uuid.get(sr_uuid)
    k = ('C08', hv.uuid, sr_uuid)
    title = 'C08 GC abort flag on %s for SR %s' % (hv.name, m.name_sr(sref) if sref else sr_uuid)
    now = host_time(hv, a)
    age = now - f['mtime']
    evidence = ['written %s ago, content %s' % (format_age(age), canon(f['content'].strip()))]
    problems, unknowns, waits = [], [], []
    if sref is None:
        return ev(k, 'C08', REPORT, hv.uuid, title, 'the SR is not in xapi', evidence)
    if m.sr_master(sref) != hv.href:
        return ev(k, 'C08', REPORT, hv.uuid, title, 'this host is not the SR\'s master, where its GC runs', evidence)
    ob = orphan_block(a, sr_uuid)
    if ob:
        problems.append(ob)
    ou = orphan_unknown(a, sr_uuid)
    if ou:
        unknowns.append(ou)
    w = f.get('writer')
    if w is None:
        problems.append('the flag does not hold a pid')
    elif w.get('alive'):
        if w.get('start', 0) <= f['mtime'] + 1:
            waits.append('its writer, pid %d, is alive: an abort in progress' % w['pid'])
        elif w.get('sm'):
            unknowns.append('pid %d is now an SM process' % w['pid'])
        else:
            evidence.append('pid %d was reused by an unrelated process' % w['pid'])
    else:
        evidence.append('its writer, pid %d, is gone' % w['pid'])
    if age < ABORT_MIN_AGE:
        waits.append('it is only %s old' % format_age(age))
    caps = (hv.caps or {}).get('ipc') or {}
    if not (caps.get('set_log') and caps.get('clear_log') and caps.get('base') and caps.get('pid')):
        unknowns.append('the installed SM on %s does not keep and log IPC flags the way this tool knows' % hv.name)
    if m.srs[sref]['type'] == 'linstor' and ((hv.caps or {}).get('cleanup') or {}).get('abort_from_openers'):
        evidence.append('this SM aborts the GC on LINSTOR SRs when a volume open is held up by a coalesce on '
                        'another host (abortGc), so a new flag can appear after this one is removed')
    if hv.smlog is None:
        unknowns.append('SMlog not read')
    else:
        evs = hv.smlog.get('events', {}).get('abort:' + sr_uuid) or []
        sets = [e for e in evs if e[1] == 'set']
        if not sets:
            unknowns.append('no "IPCFlag: set %s:abort" line in SMlog' % sr_uuid)
        else:
            last = sets[-1]
            if abs(last[0] - f['mtime']) > 5:
                unknowns.append('the last "IPCFlag: set" line (%s) does not match the file time' % format_age(now - last[0]))
            if any(e[1] == 'clear' and e[0] >= last[0] for e in evs):
                problems.append('SMlog shows the flag cleared after it was set: the file is a newer one')
            if any(e[1] == 'cleanup-abort' and now - e[0] < 60 for e in evs):
                waits.append('a GC abort (=== SR: abort ===) ran in the last minute')
            runs = [r for r in hv.smlog.get('gc') or [] if r.get('sr') == sr_uuid and r['first'] >= last[0]]
            aborted = [r for r in runs if r.get('aborted')]
            if not aborted:
                waits.append('no GC run since the flag was set has ended "Aborted" yet: the next run may clear it')
            else:
                evidence.append('%d GC run(s) since it was set, %d ended Aborted' % (len(runs), len(aborted)))
    gstate, greasons = gc_state(a, sref)
    if gstate == 'running':
        waits.append('a GC runs on the SR now (%s)' % '; '.join(greasons))
    elif gstate == 'unknown':
        unknowns.append('whether a GC runs on the SR is not established (%s)' % '; '.join(greasons))
    verdict, reason = verdict_of(problems, unknowns, waits)
    if verdict == FIX:
        reason = ('its writer is gone, it outlived the GC run(s) that ended Aborted on it, and no GC runs on the SR '
                  'now')
    item = {'cls': 'C08', 'phase': 'G', 'action': 'unlink-abort', 'host': hv.uuid, 'sr': sr_uuid,
            'expect': {'content': f['content'], 'mtime': f['mtime'], 'ino': f['ino']}}
    return ev(k, 'C08', verdict, hv.uuid, title, reason, evidence,
              sig=[f['content'], f['mtime'], f['ino']], item=item if verdict == FIX else None)


def orphan_rows(hv):
    if not hv.live or hv.taps is None or hv.backend is None or hv.tap_major is None:
        return []
    out = []
    for row in hv.live_taps():
        if row['minor'] is None or row['minor'] in hv.back_minor:
            continue
        vdis = set(re.findall(UUID_PAT, row.get('path') or '')) | set(hv.row_ident.get((row['pid'], row['minor'])) or ())
        if not any(c[1] in vdis for dp, cl in (hv.claim or {}).items() for c in cl):
            out.append(row)
    return out


def row_srs(a, hv, row):
    m = a.model
    p = row.get('path') or ''
    mm = re.search(r'VG_XenStorage-(' + UUID_PAT + ')', p) or re.search(r'sr-mount/(' + UUID_PAT + ')/', p)
    if mm:
        return set([mm.group(1)])
    out = set()
    for u in set(re.findall(UUID_PAT, p)) | set(hv.row_ident.get((row['pid'], row['minor'])) or ()):
        vref = m.vdi_by_uuid.get(u)
        sr = m.srs.get(m.vdis[vref]['SR']) if vref else None
        if sr:
            out.add(sr['uuid'])
    return out


def orphan_gap(hv):
    if not hv.live:
        return 'xapi does not report it live'
    if hv.doc is None:
        return 'it was not read (%s)' % (hv.err or 'not asked in this read')
    if hv.taps is None:
        return 'its tapdisks were not listed (%s)' % (hv.why('tapdisks') or 'no answer')
    if hv.backend is None:
        return 'its SM backend nodes were not listed (%s)' % (hv.why('backend') or 'no answer')
    if hv.tap_major is None:
        return 'its blktap major is not known (%s)' % (hv.why('blktap') or 'no tapdev major in /proc/devices')
    return None


def orphan_srs(a):
    if getattr(a, '_orphans', None) is None:
        m = a.model
        out = collections.defaultdict(list)
        blind = collections.defaultdict(list)
        for href in m.hosts:
            hv = a.view(href)
            plugged = set(m.srs[pb['SR']]['uuid'] for pb in m.pbds.values()
                          if pb['host'] == href and pb['currently_attached'] and pb['SR'] in m.srs)
            gap = orphan_gap(hv)
            if gap:
                for s in plugged:
                    blind[s].append('%s: %s' % (hv.name, gap))
                continue
            for row in orphan_rows(hv):
                for s in row_srs(a, hv, row) or plugged:
                    out[s].append('tapdisk pid %s minor %s on %s, %s:%s' % (row['pid'], row['minor'], hv.name,
                                                                          row.get('type'), row.get('path')))
        a._orphans = (dict(out), dict(blind))
    return a._orphans


def orphan_block(a, sr_uuid):
    orph = orphan_srs(a)[0].get(sr_uuid)
    if not orph:
        return None
    return ('an orphan tapdisk (one that no SM backend node and no datapath names) has an image of this SR open '
            '(C14: %s): this tool changes nothing on the SR until it is fenced, and the recovery kit says to freeze '
            'snapshots, backups and VDI creation on it too' % '; '.join(orph[:2]))


def orphan_unknown(a, sr_uuid):
    blind = orphan_srs(a)[1].get(sr_uuid)
    if not blind:
        return None
    return ('whether an orphan tapdisk (one that no SM backend node and no datapath names) has an image of this SR '
            'open is not established on every host that has it plugged (%s)' % '; '.join(blind[:3]))


def c14_evidence(a, hv, row):
    out = ['args %s:%s' % (row.get('type'), row.get('path'))]
    dev = '%x:%x' % (hv.tap_major, row['minor'])
    p = row.get('path') or ''
    refs = sorted(k.rsplit('/', 1)[0] for k, v in (hv.xenstore or {}).items()
                  if (k.endswith('/physical-device') and v == dev) or (k.endswith('/params') and v and v == p))
    if hv.xenstore is None:
        out.append('the xenstore backends on %s were not read' % hv.name)
    elif refs:
        out.append('xenstore still connects a guest to it: %s, so it serves a VM without the backend node and the '
                   'datapath SM and xapi keep for a disk (the SR is still held back)' % ', '.join(refs[:3]))
    else:
        out.append('no xenstore backend on %s names it' % hv.name)
    mm = re.match(r'^/dev/(VG_XenStorage-' + UUID_PAT + r')/((?:VHD|LV|QCOW2)-' + UUID_PAT + r')$', p)
    if mm:
        names = a.lvnames.get((hv.uuid, mm.group(1)))
        if names is None:
            out.append('whether its LV %s still exists was not read' % mm.group(2))
        elif mm.group(2) in [n for n, attr in names]:
            out.append('its LV %s exists' % mm.group(2))
        else:
            out.append('its LV %s is gone from the volume group: its extents are free in LVM\'s eyes, which is an '
                       'emergency (xcp-storage-recovery-kit, stale-mapping sweep)' % mm.group(2))
    elif p.startswith('/var/run/sr-mount/') or p.startswith('/run/sr-mount/'):
        st = a.statfiles.get((hv.uuid, p))
        if st is None:
            out.append('whether its image file still exists was not read')
        else:
            out.append('its image file %s' % ('exists' if st.get('exists') else 'is gone'))
    return out


def eval_taps(a, opts):
    out = []
    m = a.model
    for href, h in m.hosts.items():
        hv = a.view(href)
        if not hv.live or hv.taps is None:
            continue
        for row in hv.taps:
            if row['state'] is not None and row['state'] & PAUSED:
                out.append(eval_paused_tap(a, opts, hv, row))
            elif row['state'] is not None and row['state'] & ~LOG_DROPPED:
                out.append(ev(('C21', hv.uuid, row['pid'], row['minor']), 'C21', REPORT, hv.uuid,
                              'C21 tapdisk pid %s minor %s on %s is in state %s (%s)'
                              % (row['pid'], row['minor'], hv.name, tap_state_text(row['state']),
                                 tap_state_names(row['state'])),
                              'nothing that touches its disk is done while it is in that state. A requested pause, '
                              'quiesce or shutdown clears by itself; anything else needs a look (tapdisk-inspect.sh)',
                              ['args %s:%s' % (row.get('type'), row.get('path'))]))
        for row in orphan_rows(hv):
            out.append(ev(('C14', hv.uuid, row['pid'], row['minor']), 'C14', REPORT, hv.uuid,
                          'C14 tapdisk pid %s minor %s on %s' % (row['pid'], row['minor'], hv.name),
                          'no SM backend node and no datapath name it: possibly an orphan. Investigate with '
                          'orphan-tapdisk.py (fence, then teardown). This tool never touches tapdisks, and while it '
                          'is there nothing that reaches its SR is done: no dom0 VBD release, datapath teardown, '
                          'sm-config key removal, unpause, abort flag removal or GC start on that SR (only dead '
                          'records in storage.db, which never reach the SR, are still removed)',
                          c14_evidence(a, hv, row)))
        for key in hv.deaf():
            out.append(ev(('C15', hv.uuid, key), 'C15', REPORT, hv.uuid,
                          'C15 tapdisk %s on %s does not answer' % (key, hv.name), hv.tap_stats[key]['error'],
                          ['see tapdisk-kill-deaf.sh; no fix touching tapdisks on this host while it is deaf']))
        quiet = hv.stats_unknown()
        if quiet:
            out.append(ev(('ENV', 'tapstats', hv.uuid), 'C18', UNKNOWN, hv.uuid,
                          'tap-ctl stats on %s not established' % hv.name,
                          'no tap-ctl stats from %s: nothing that touches tapdisks runs on this host' %
                          ', '.join('%s (%s)' % (k, why) for k, why in quiet[:6])))
        for pid, q in sorted((hv.ctl_backlog or {}).items()):
            if q > 0:
                out.append(ev(('C15', hv.uuid, 'ctl', pid), 'C15', REPORT, hv.uuid,
                              'C15 tapdisk pid %s on %s is not accepting control connections' % (pid, hv.name),
                              '%d connection(s) wait on its control socket' % q,
                              ['see tapdisk-kill-deaf.sh; no fix touching tapdisks on this host while it is deaf']))
        for row in hv.empty_minors:
            out.append(ev(('C16', 'minor', hv.uuid, row['minor']), 'C16', INFO, hv.uuid,
                          'C16 tap minor %s on %s has no tapdisk' % (row['minor'], hv.name),
                          'tap-ctl lists it as allocated with no tapdisk behind it (what a killed tapdisk leaves); '
                          'left alone: tap-ctl free -m %s releases it once nothing names it' % row['minor']))
        if hv.backend is not None:
            for (sr, vdi), node in hv.back_node.items():
                if node['kind'] != 'block' or node['rdev'][0] != hv.tap_major:
                    continue
                if any(r['minor'] == node['rdev'][1] for r in hv.live_taps()):
                    continue
                if any(c[1] == vdi for cl in (hv.claim or {}).values() for c in cl):
                    continue
                out.append(ev(('C16', 'node', hv.uuid, sr, vdi), 'C16', INFO, hv.uuid,
                              'C16 backend node %s/%s on %s' % (sr, vdi, hv.name),
                              'it points at tap minor %d, which has no tapdisk, and no datapath names it'
                              % node['rdev'][1]))
        for name, f in sorted((hv.dps_files or {}).items() if hv.claim is not None else ()):
            c = f.get('content') or {}
            vdi = c.get('vdi')
            dp = name.replace('-', '/', 2) if name.startswith('vbd-') else None
            if vdi and dp and not any(vdi in (cl[1], cl[3]) for cl in hv.claim.get(dp, [])):
                out.append(ev(('C16', 'dpsfile', hv.uuid, name), 'C16', INFO, hv.uuid,
                              'C16 storage-dps/%s on %s' % (name, hv.name),
                              'it names VDI %s, which no longer holds %s; left alone' % (vdi, dp)))
        errs = len(((hv.sdb or {}).get('obj') or {}).get('errors') or [])
        if errs:
            out.append(ev(('C16', 'errors', hv.uuid), 'C16', INFO, hv.uuid, 'C16 storage.db errors on %s' % hv.name,
                          '%d past storage errors are recorded; never edited' % errs))
    return out


def pause_owner(a, hv, vu, sr_ref):
    m = a.model
    hosts = [hv.href]
    mref = m.sr_master(sr_ref) if sr_ref else None
    if mref is not None and mref not in hosts:
        hosts.append(mref)
    unknowns, waits, evidence = [], [], []
    found = []
    for href in hosts:
        h2 = a.view(href)
        if h2.smlog is None:
            unknowns.append('SMlog on %s was not read' % h2.name)
            continue
        evs = (h2.smlog.get('events') or {}).get('preq:' + vu) or []
        if evs:
            found.append((h2, evs[-1]))
    if not found:
        if not unknowns:
            unknowns.append('no "Pause request for" line for it is in the SMlog of %s, so whoever paused it is not '
                            'established' % ', '.join(a.view(r).name for r in hosts))
        return unknowns, waits, evidence
    for h2, (t, kind, pid) in found:
        age = host_time(h2, a) - t
        evidence.append('last %s request for it on %s: %s ago, by pid %d' % (kind, h2.name, format_age(age), pid))
        pi = a.pidinfo.get((h2.uuid, pid))
        if pi is None:
            unknowns.append('whether pid %d on %s is gone was not established' % (pid, h2.name))
        elif pi.get('alive') and (pi.get('sm') or pi.get('start', 0) <= t + 1):
            waits.append('pid %d on %s, which requested the %s, is still alive' % (pid, h2.name, kind))
        elif pi.get('alive'):
            evidence.append('pid %d on %s now belongs to an unrelated process that started after the %s'
                            % (pid, h2.name, kind))
        else:
            evidence.append('pid %d on %s, which requested the %s, is gone' % (pid, h2.name, kind))
        if kind == 'pause' and age < ABORT_MIN_AGE:
            waits.append('the pause was requested only %s ago on %s' % (format_age(age), h2.name))
    return unknowns, waits, evidence


def chain_problems(a, hv, v, sr):
    m = a.model
    problems, unknowns = [], []
    lv = a.lvnames.get((hv.uuid, 'VG_XenStorage-' + sr['uuid'])) if sr['type'] in LVM_SR_TYPES else None
    listing = a.srdirs.get((hv.uuid, sr['uuid'])) if sr['type'] in FILE_SR_TYPES else None
    if sr['type'] in LVM_SR_TYPES and lv is None:
        return problems, ['the SR\'s LV names were not read']
    if sr['type'] in FILE_SR_TYPES and listing is None:
        return problems, ['the SR directory was not listed']
    names = set(n for n, attr in lv) if lv is not None else set(listing)
    cur, seen = v, set()
    while True:
        parent = cur['sm_config'].get('vhd-parent')
        if not parent:
            break
        if parent in seen or len(seen) > 64:
            problems.append('its vhd-parent chain loops at %s' % parent)
            break
        seen.add(parent)
        pref = m.vdi_by_uuid.get(parent)
        if pref is None:
            problems.append('its parent %s is not a VDI in xapi' % parent)
            break
        if sr['type'] in LVM_SR_TYPES:
            if not any(n in names for n in ('VHD-' + parent, 'LV-' + parent)):
                problems.append('the LV of its parent %s is not in the volume group' % parent)
        elif parent + '.vhd' not in names:
            problems.append('the file of its parent %s is not in the SR directory' % parent)
        cur = m.vdis[pref]
    if v.get('cbt_enabled') is True:
        if v['uuid'] + '.cbtlog' not in names:
            problems.append('CBT is enabled but its log %s.cbtlog is not in the SR' % v['uuid'])
    return problems, unknowns


def c12_context(a, hv, v, vu, sr):
    out = []
    u2, w2, e2 = pause_owner(a, hv, vu, v['SR'])
    out.extend(e2 + w2 + u2)
    gstate, greasons = gc_state(a, v['SR'])
    out.append('GC on its SR: %s%s' % (gstate, (' (%s)' % '; '.join(greasons)) if greasons else ''))
    keys = [key for key in ('paused', 'relinking', 'activating') if key in v['sm_config']]
    out.append('sm-config: %s' % (', '.join(keys) if keys else 'no paused, relinking or activating key'))
    phy = hv.phy.get((sr['uuid'], vu)) if sr else None
    if phy is None:
        out.append('no phy link for it on %s' % hv.name)
    elif sr['type'] in LVM_SR_TYPES:
        out.append('its LV is %s on %s' % ('active' if phy.get('kind') == 'block' else 'not active (%s)' % phy.get('kind'),
                                            hv.name))
    else:
        out.append('its phy link points at %s' % phy.get('target'))
    for note in (orphan_block(a, sr['uuid']), orphan_unknown(a, sr['uuid'])) if sr else ():
        if note:
            out.append(note)
    return out


def eval_paused_tap(a, opts, hv, row):
    m = a.model
    k = ('C12', hv.uuid, row['pid'], row['minor'])
    ident = sorted(hv.row_ident.get((row['pid'], row['minor'])) or ())
    claimed = sorted(set(r['vdi'] for r in hv.back_minor.get(row['minor'], [])) - set(ident))
    title = 'C12 paused tapdisk pid %s minor %s on %s' % (row['pid'], row['minor'], hv.name)
    evidence = ['state %s args %s:%s' % (tap_state_text(row['state']), row.get('type'), row.get('path'))]
    if claimed:
        return ev(k, 'C12', REPORT, hv.uuid, title, 'backend node(s) of %s point at it, but it serves %s (C20)'
                  % (', '.join(claimed), ', '.join(ident) or 'an unmapped image'), evidence)
    if len(ident) != 1:
        return ev(k, 'C12', REPORT, hv.uuid, title, 'the VDI it serves is not established', evidence)
    vu = ident[0]
    vref = m.vdi_by_uuid[vu]
    v = m.vdis[vref]
    sr = m.srs.get(v['SR'])
    title = 'C12 paused tapdisk pid %s on %s, VDI %s' % (row['pid'], hv.name, m.name_vdi(vref))
    evs = ((hv.smlog or {}).get('events') or {}).get('pause:' + vu) or []
    pauses = [e for e in evs if e[1] == 'pause']
    last_pause = pauses[-1] if pauses else None
    if last_pause and any(e[1] == 'unpause' and e[0] >= last_pause[0] for e in evs):
        last_pause = None
    if last_pause:
        evidence.append('the tapdisk-pause plugin paused it %s ago, with no unpause since' % (
            format_age(host_time(hv, a) - last_pause[0])))
    recipe = ('the tested recipe: once nothing holds the disk, xe host-call-plugin host-uuid=%s plugin=tapdisk-pause '
              'fn=unpause args:sr_uuid=%s args:vdi_uuid=%s' % (hv.uuid, sr['uuid'] if sr else '?', vu))
    if 'c12' not in opts.include:
        return ev(k, 'C12', REPORT, hv.uuid, title, 'unpausing is opt-in (--include c12). ' + recipe,
                  evidence + c12_context(a, hv, v, vu, sr), sig=[row['state'], vu])
    if row['minor'] is None:
        return ev(k, 'C12', REPORT, hv.uuid, title, 'it has no tap minor: the tapdisk-pause plugin finds a tapdisk '
                  'through the VDI\'s backend node and its minor, so it cannot unpause this one', evidence)
    problems, unknowns, waits = [], [], []
    ob = orphan_block(a, sr['uuid']) if sr else None
    if ob:
        problems.append(ob)
    ou = orphan_unknown(a, sr['uuid']) if sr else None
    if ou:
        unknowns.append(ou)
    if sr is None or sr['type'] not in LVM_SR_TYPES + FILE_SR_TYPES:
        return ev(k, 'C12', REPORT, hv.uuid, title, 'automatic unpause is only done on LVM SRs and on %s SRs, whose GC '
                  'journals this tool knows how to read, not on %s SRs. ' % ('/'.join(FILE_SR_TYPES),
                                                                            sr['type'] if sr else 'unknown') + recipe,
                  evidence)
    if not is_vhd(v, sr['type']):
        return ev(k, 'C12', REPORT, hv.uuid, title, 'automatic unpause is only done on VHD images. ' + recipe,
                  evidence)
    if 'unpause' not in ((hv.caps or {}).get('tapdisk_pause') or {}).get('funcs', []):
        problems.append('the tapdisk-pause plugin on %s has no unpause function' % hv.name)
    state, node, at = hv.node_state(sr['uuid'], vu)
    if state != 'own' or at is not row:
        problems.append('the plugin finds the tapdisk through the VDI\'s backend node, and that node is %s, not '
                        'this tapdisk' % ('missing' if state == 'none' else state if state != 'own' else
                                          'on another minor'))
    smc = v['sm_config']
    for key in ('paused', 'relinking', 'activating'):
        if key in smc:
            problems.append('the VDI carries %s' % key)
    if v.get('current_operations'):
        waits.append('the VDI has %s in progress' % ', '.join(sorted(set(v['current_operations'].values()))))
    if last_pause is None:
        unknowns.append('no "Pause for" line without a later "Unpause for" was found in SMlog on %s' % hv.name)
    elif host_time(hv, a) - last_pause[0] < ABORT_MIN_AGE:
        waits.append('paused only %s ago' % format_age(host_time(hv, a) - last_pause[0]))
    u2, w2, e2 = pause_owner(a, hv, vu, v['SR'])
    unknowns.extend(u2)
    waits.extend(w2)
    evidence.extend(e2)
    st = (hv.tap_stats or {}).get('%d:%d' % (row['pid'], row['minor']))
    if st is None:
        unknowns.append('the tapdisk was not asked for its stats')
    elif not st.get('ok') and 'deaf' in (st.get('error') or '') and not st.get('gone'):
        problems.append('the tapdisk does not answer: %s' % st.get('error'))
    elif not st.get('ok'):
        unknowns.append('the tapdisk gave no stats: %s%s' % (st.get('error'), ' (its process is gone)'
                                                             if st.get('gone') else ''))
    if m.pending_tasks(work=True):
        waits.append('%d task(s) are pending in the pool' % len(m.pending_tasks(work=True)))
    gstate, greasons = gc_state(a, v['SR'])
    if gstate != 'idle':
        waits.append('GC on the SR is %s' % gstate)
    gate, gate_unknown = host_gate(a, hv.href, opts)
    waits.extend(gate)
    unknowns.extend(gate_unknown)
    if hv.locks is None:
        unknowns.append('the SM locks on %s were not read' % hv.name)
    else:
        for l in hv.locks:
            if l['path'] == '%s/%s/vdi' % (SM_LOCK_DIR, vu):
                waits.append('its SM lock is held by pid %d' % l['pid'])
    mref = m.sr_master(v['SR'])
    for href in sorted(set([hv.href] + ([mref] if mref else []))):
        h2 = a.view(href)
        busy = h2.sm_busy()
        if busy is None:
            unknowns.append('the processes on %s were not read' % h2.name)
            continue
        for p in busy:
            if not any(x.endswith('cleanup.py') for x in p.get('argv') or []):
                waits.append('SM process %d runs on %s (%s)' % (p['pid'], h2.name,
                                                                ' '.join((p.get('argv') or [])[:2])[:120]))
    hold = hv.holders(sr['uuid'], vu)
    if hold is None:
        unknowns.append('openers not established')
    else:
        for h, hits in hold:
            if h['comm'] != 'tapdisk':
                problems.append('%s pid %d holds it' % (h['comm'], h['pid']))
    phy = hv.phy.get((sr['uuid'], vu))
    if phy is None:
        problems.append('no phy link for it on this host')
    elif sr['type'] in LVM_SR_TYPES:
        if phy.get('kind') != 'block':
            problems.append('its LV is not active on this host (%s): refresh it first (xe host-call-plugin ... '
                            'plugin=on-slave fn=multi with action1=refresh), then unpause' % phy.get('kind'))
        else:
            dmc = a.dmchecks.get((hv.uuid, 'VG_XenStorage-%s/VHD-%s' % (sr['uuid'], vu)))
            if dmc is None:
                unknowns.append('the device-mapper table of its LV was not compared with the LVM metadata')
            elif not dmc.get('ok'):
                unknowns.append('the device-mapper table of its LV could not be compared with the LVM metadata: %s'
                                % dmc.get('error'))
            elif not dmc['value'].get('match'):
                problems.append('the device-mapper table of its LV on %s does not match the LVM metadata (dm %s, lvm '
                                '%s): refresh the LV (lvchange --refresh) before it is unpaused'
                                % (hv.name, canon(dmc['value'].get('dm'))[:200], canon(dmc['value'].get('lvm'))[:200]))
            else:
                evidence.append('its device-mapper table matches the LVM metadata')
        lv = a.lvnames.get((hv.uuid, 'VG_XenStorage-' + sr['uuid']))
        if lv is not None:
            odd = [n for n, attr in lv if vu in n and n not in ('VHD-' + vu, 'LV-' + vu, vu + '.cbtlog')]
            if odd:
                problems.append('journal LV(s) name it: %s' % ', '.join(odd))
    else:
        st_ = a.statfiles.get((hv.uuid, phy.get('target')))
        if st_ is None or not st_.get('exists'):
            problems.append('its image file is not established to exist')
        listing = a.srdirs.get((hv.uuid, sr['uuid']))
        if listing is not None:
            odd = [n for n in listing if vu in n and n not in (vu + '.vhd', vu + '.cbtlog')]
            if odd:
                problems.append('other files name it: %s' % ', '.join(odd))
    p2, u3 = chain_problems(a, hv, v, sr)
    problems.extend(p2)
    unknowns.extend(u3)
    if phy is not None and phy.get('target'):
        chk = a.vhdchecks.get((hv.uuid, phy['target']))
        if chk is None:
            unknowns.append('vhd-util check of its image was not run')
        elif not chk.get('ok'):
            problems.append('vhd-util check of its image and its parents fails: %s' % chk.get('detail'))
        else:
            evidence.append('vhd-util check -p: %s and its parents are valid' % phy['target'])
            want = v['sm_config'].get('vhd-parent') or ''
            if 'parent' not in chk:
                unknowns.append('the parent its VHD header names was not read: %s' % chk.get('parent_error'))
            elif chk['parent'] != want:
                problems.append('its VHD header names parent %s, but xapi records %s'
                                % (chk['parent'] or 'none', want or 'none'))
    if v.get('cbt_enabled') is True:
        evidence.append('CBT is enabled: the plugin hands its log to the tapdisk')
    owner = [m.vms.get(vbd['VM']) for r, vbd in vdi_vbds(m, vref) if vbd['currently_attached']]
    for vm in owner:
        if vm and not vm['is_control_domain'] and vm['domid'] not in ('', '-1'):
            sd = a.xsread.get((hv.uuid, '/local/domain/%s/control/shutdown' % vm['domid']))
            if sd is None:
                unknowns.append('whether VM "%s" has a shutdown request pending was not read' % vm['name_label'])
            elif sd.get('present') and sd.get('value'):
                problems.append('VM "%s" has control/shutdown=%s pending and would act on it the moment its disk '
                                'resumes' % (vm['name_label'], sd['value']))
    verdict, reason = verdict_of(problems, unknowns, waits)
    if verdict == FIX:
        reason = ('whoever paused it is gone; nothing else holds the disk; its image and chain check out; SM\'s own '
                  'tapdisk-pause code unpauses it on %s, under the VDI\'s SM lock and with the GC of its SR held off'
                  % hv.name)
    item = {'cls': 'C12', 'phase': 'P', 'action': 'unpause', 'host': hv.uuid, 'sr': sr['uuid'], 'vdi': vu,
            'pid': row['pid'], 'minor': row['minor']}
    return ev(k, 'C12', verdict, hv.uuid, title, reason, evidence,
              sig=[row['state'] & ~RESUME_FAILED, vu, last_pause], item=item if verdict == FIX else None)


def eval_gc(a, opts):
    out = []
    m = a.model
    for sref, sr in m.srs.items():
        mref = m.sr_master(sref)
        if mref is None:
            continue
        hv = a.view(mref)
        tasks = [t for t in m.pending_tasks() if m.is_gc_task(t, sr['uuid'])]
        if tasks:
            st, why = gc_state(a, sref)
            others = [w for w in why if not w.startswith('GC task ') and not w.startswith('but ')]
            if st == 'running' and not others and hv.procs is not None and hv.locks is not None and \
                    hv.units is not None:
                out.append(ev(('C19', 'task', sr['uuid']), 'C19', REPORT, hv.uuid,
                              'C19 GC task on SR %s with no GC behind it' % m.name_sr(sref),
                              'task %s is pending, but no GC process, lock or unit runs for the SR on %s: a killed GC '
                              'leaves its task behind, and every check of this SR waits on it. Cancel it with xe '
                              'task-cancel uuid=%s once you are sure' % (tasks[0]['uuid'], hv.name, tasks[0]['uuid'])))
        if hv.smlog is None:
            continue
        runs = [r for r in hv.smlog.get('gc') or [] if r.get('sr') == sr['uuid']]
        if not runs:
            continue
        last = runs[-3:]
        bad = [r for r in last if r.get('aborted') or r.get('error')]
        if not bad:
            continue
        why = []
        if any(f['sr'] == sr['uuid'] and f['name'] == 'abort' for f in hv.ipc or []):
            why.append('an abort flag is set (C08)')
        pids_ = set(r['pid'] for r in runs)
        if any(e[1] in pids_ for e in hv.smlog.get('failed_tag') or []):
            why.append('"Failed to tag" means a stale activating key (C10)')
        st, swhy = gc_state(a, sref)
        vdis = [v for v in m.vdis.values() if v['SR'] == sref]
        tree = [v for v in vdis if v['sm_config'].get('vhd-parent')]
        extra = ['%d VDI(s) on the SR, %d of them with a parent in a COW tree' % (len(vdis), len(tree))]
        for note in (orphan_block(a, sr['uuid']), orphan_unknown(a, sr['uuid'])):
            if note:
                extra.append(note)
        latest = last[-1]
        recovered = latest.get('outcome') == 'exited' and not latest.get('aborted') and not latest.get('error')
        out.append(ev(('C19', sr['uuid']), 'C19', INFO if recovered else REPORT, hv.uuid,
                      'C19 GC on SR %s' % m.name_sr(sref),
                      '%d of its last %d runs failed%s%s' % (
                          len(bad), len(last), (': ' + '; '.join(why)) if why else '',
                          '; its latest run ended normally, so the GC works again' if recovered else ''),
                      ['%s %s' % (format_age(host_time(hv, a) - r['last']) + ' ago', r.get('outcome') or r.get('error'))
                       for r in last] + ['GC now: %s%s' % (st, (' (%s)' % '; '.join(swhy)) if swhy else '')] + extra))
    for href in sorted(set(m.sr_master(s) for s in m.srs) - set([None])):
        hv = a.view(href)
        runs = [r for r in (hv.smlog or {}).get('gc') or [] if not r.get('sr')]
        bad = [r for r in runs[-3:] if r.get('aborted') or r.get('error')]
        if bad:
            out.append(ev(('C19', 'nosr', hv.uuid), 'C19', REPORT, hv.uuid,
                          'C19 GC runs on %s that SMlog does not tie to an SR' % hv.name,
                          '%d of the last %d such runs failed; SMlog has no gc_active lock line for them, so their SR '
                          'is not known' % (len(bad), len(runs[-3:])),
                          ['pid %d, %s ago: %s' % (r['pid'], format_age(host_time(hv, a) - r['last']),
                                                   r.get('outcome') or r.get('error')) for r in runs[-3:]]))
    return out


def eval_hazards(a, opts):
    out = []
    m = a.model
    for href, h in m.hosts.items():
        hv = a.view(href)
        if not hv.live or hv.backend is None or hv.taps is None:
            continue
        for (sr, vdi), node in sorted(hv.back_node.items()):
            state, node_, at = hv.node_state(sr, vdi)
            if state != 'other':
                continue
            vref = m.vdi_by_uuid.get(vdi)
            users = []
            if vref:
                for r, vbd in vdi_vbds(m, vref):
                    vm = m.vms.get(vbd['VM'])
                    if vm and vbd['currently_attached'] and vm['resident_on'] == href:
                        users.append('dom0' if vm['is_control_domain'] else 'VM "%s"' % vm['name_label'])
            out.append(ev(('C20', hv.uuid, sr, vdi), 'C20', REPORT, hv.uuid,
                          'C20 backend node of VDI %s on %s points at another disk\'s tapdisk'
                          % (m.name_vdi(vref) if vref else vdi, hv.name),
                          'its own tapdisk is gone and tap minor %d now belongs to %s. Anything that deactivates, '
                          'pauses or unpauses this VDI on %s - unplugging its VBD, shutting down its VM, a snapshot, '
                          'the GC coalescing it - acts on that tapdisk instead and takes that disk away from its '
                          'user. Touch nothing that uses this VDI until its node is made inert' %
                          (node['rdev'][1], hv.row_label(at), hv.name),
                          ['attached here by: %s' % (', '.join(users) or 'nothing in xapi'),
                           '/dev/sm/backend/%s/%s is block %d:%d' % (sr, vdi, node['rdev'][0], node['rdev'][1])]))
    return out


EVALUATORS = (eval_hosts, eval_ha, eval_dps, eval_vbds, eval_vdis, eval_aborts, eval_taps, eval_hazards, eval_gc)


def evaluate(a, opts):
    out = collections.OrderedDict()
    for fn in EVALUATORS:
        for e in fn(a, opts):
            out[tuple(e['key'])] = e
    return out


def combine(per, gap_ok):
    last = per[-1]
    final = []
    for key, e in last.items():
        e = dict(e)
        if e['verdict'] == FIX:
            prev = [p.get(key) for p in per[:-1]]
            if not prev:
                e['verdict'], e['reason'], e['item'] = WAIT, 'seen in one audit only', None
            elif any(p is None or p['verdict'] != FIX or canon(p['sig']) != canon(e['sig']) for p in prev):
                bad = [p for p in prev if p is None or p['verdict'] != FIX]
                why = ('not in every audit' if any(p is None for p in prev) else
                       'judged %s in an earlier audit (%s)' % (bad[0]['verdict'], bad[0]['reason']) if bad else
                       'its state changed between audits')
                e['verdict'], e['reason'], e['item'] = WAIT, why, None
            elif not gap_ok:
                e['verdict'], e['reason'], e['item'] = WAIT, 'the audits are less than %ds apart' % SETTLE_FLOOR, None
        final.append(e)
    return final


def dead_duplicates(audit, host_uuid, vbd_uuid, vdi_uuid):
    m = audit.model
    vbref = m.vbd_by_uuid.get(vbd_uuid)
    href = m.host_by_uuid.get(host_uuid)
    if vbref is None or href is None:
        return []
    hv = audit.view(href)
    if hv.claim is None:
        return None
    try:
        dp = 'vbd/0/' + devname(m.vbds[vbref]['userdevice'])
    except ValueError:
        return None
    cl = hv.claim.get(dp) or []
    per_sr = collections.Counter(c[0] for c in cl)
    return sorted([c[0], c[1], dp] for c in cl if per_sr[c[0]] > 1 and c[1] != vdi_uuid)


def postprocess(final, audits):
    blockers = [e for e in final if e['cls'] == 'C18' and e['verdict'] in (UNKNOWN, REPORT)
                and (e['key'][0] in ('ENV', 'HA') and e['key'][1] in ('live', 'agent', 'ha', 'flag', 'incons',
                                                                      'unarmed', 'statefile', 'nostatefile',
                                                                      'split'))]
    for e in final:
        it = e.get('item')
        if it and it['action'] == 'storage-db' and blockers:
            e['verdict'], e['item'] = WAIT, None
            e['reason'] = ('xapi is not restarted anywhere while %s' % blockers[0]['title'])
    return dependencies(final, audits)


def dependencies(final, audits):
    by = dict((tuple(e['key']), e) for e in final)
    for e in final:
        it = e.get('item')
        if not (it and it['action'] == 'release-vbd' and it['attached'] and audits):
            continue
        dead = dead_duplicates(audits[-1], it['host'], it['vbd'], it['vdi'])
        if dead is None:
            e['verdict'], e['item'] = UNKNOWN, None
            e['reason'] = 'whether its datapath name has a dead duplicate in storage.db is not established'
            continue
        left = [d for d in dead if not (by.get(('DP0', it['host'], d[0], d[1], d[2])) or {}).get('item')]
        if left:
            e['verdict'], e['item'] = WAIT, None
            e['reason'] = ('its datapath name %s has a dead duplicate in storage.db (C01, VDI %s) that is not removed '
                           'in this run, and the unplug would fail on it' % (left[0][2], left[0][1]))
    for e in final:
        it = e.get('item')
        if not (it and it['action'] == 'dp-destroy' and it.get('needs')):
            continue
        for vbd in it['needs']:
            rel = by.get(('VBD', vbd))
            if rel is None or rel['verdict'] != FIX or not rel.get('item'):
                e['verdict'], e['item'] = WAIT, None
                e['reason'] = 'a tapdisk serves it for dom0 VBD %s, which is not being released' % vbd
                break
    for e in final:
        if e['cls'] != 'C20':
            continue
        base = e.setdefault('base', [e['verdict'], e['reason']])
        e['verdict'], e['reason'] = base
        for x in final:
            it = x.get('item')
            if it and x['verdict'] == FIX and it['action'] == 'release-vbd' and it.get('inert') and \
                    [it['host'], it['sr'], it['vdi']] == e['key'][1:]:
                e['verdict'] = INFO
                e['reason'] = 'handled by the planned release of dom0 VBD %s: its node is made inert first. ' % \
                    it['vbd'] + base[1]
    return final


def settle_plan(plan, final):
    alive = set(id(e['item']) for e in final if e['verdict'] == FIX and e.get('item'))
    keep = [it for it in plan if id(it) in alive]
    for i, it in enumerate(keep):
        it['seq'] = i + 1
    return keep


def classify(audits, opts):
    per = [evaluate(a, opts) for a in audits]
    gap_ok = len(audits) >= 2 and audits[-1].t - audits[0].t >= SETTLE_FLOOR - 1
    final = postprocess(combine(per, gap_ok), audits)
    for e in final:
        if e['cls'] == 'C11':
            seen = [i for i, p in enumerate(per) if tuple(e['key']) in p]
            e['evidence'] = list(e['evidence']) + ['seen in %d of %d audit(s), over %s' % (
                len(seen), len(per), format_age((audits[-1].t or 0) - (audits[seen[0]].t or 0)))]
    order = {'S': 0, 'V': 1, 'L': 2, 'F': 3, 'P': 4, 'G': 5}
    cls_order = {'C04': 1, 'C05': 2, 'C10': 0, 'C09': 1}
    plan = [e['item'] for e in final if e['verdict'] == FIX and e.get('item')]
    plan.sort(key=lambda it: (order[it['phase']], (it.get('host') or '') if it['phase'] == 'V' else '',
                              cls_order.get(it['cls'], 5), it.get('host') or '',
                              it.get('vbd') or it.get('vdi') or it.get('sr') or ''))
    for i, it in enumerate(plan):
        it['seq'] = i + 1
    return final, plan


def item_key(it):
    keep = dict((k, v) for k, v in it.items() if k not in ('seq',))
    return canon(keep)


class Ctx(object):
    def __init__(self, opts):
        self.opts = opts
        self.api = Api()
        self.transport = None
        self.inv = None
        self.my_uuid = None
        self.caps = {}
        self.rpm = {}
        self.xapi_pkg = {}
        self.workdir = None
        self.hosts = {}

    def host_objs(self, model):
        out = []
        for ref, rec in sorted(model.hosts.items(), key=lambda kv: kv[1]['name_label']):
            h = Host(ref, rec, rec['uuid'] == self.my_uuid, model.host_live(ref))
            h.is_master = ref == model.pool['master']
            out.append(h)
        self.hosts = dict((h.ref, h) for h in out)
        return out


def candidates_round2(a, opts):
    m = a.model
    q = collections.defaultdict(lambda: {'smlog': {'relink': set(), 'abort': set(), 'activate': set(),
                                                   'pause': set(), 'phy': set(), 'drbd': False},
                                         'pids': set(), 'statfiles': set(), 'vgs': set(), 'srdirs': set(),
                                         'xsread': set(), 'vhdcheck': set(), 'drbdres': set(), 'dmcheck': set()})
    for vref, v in m.vdis.items():
        smc = v['sm_config']
        mref = m.sr_master(v['SR'])
        sr = m.srs.get(v['SR'])
        if 'relinking' in smc and mref:
            q[mref]['smlog']['relink'].add(v['uuid'][:8])
            if sr and sr['type'] in LVM_SR_TYPES:
                q[mref]['vgs'].add('VG_XenStorage-' + sr['uuid'])
            elif sr and sr['type'] in PATH_SR_TYPES:
                q[mref]['srdirs'].add(sr['uuid'])
        if 'activating' in smc:
            for href in m.hosts:
                q[href]['smlog']['activate'].add(v['uuid'])
        if 'paused' in smc and mref:
            q[mref]['smlog']['pause'].add(v['uuid'])
            for href in m.hosts:
                if a.view(href).tap_vdis.get(v['uuid']):
                    q[href]['smlog']['pause'].add(v['uuid'])
    for href in m.hosts:
        hv = a.view(href)
        q[href]
        for f in hv.ipc or []:
            if f['name'] == 'abort':
                q[href]['smlog']['abort'].add(f['sr'])
        for row in orphan_rows(hv):
            p = row.get('path') or ''
            mm = re.match(r'^/dev/(VG_XenStorage-' + UUID_PAT + r')/', p)
            if mm:
                q[href]['vgs'].add(mm.group(1))
            elif p.startswith('/var/run/sr-mount/') or p.startswith('/run/sr-mount/'):
                q[href]['statfiles'].add(p)
        for row in hv.taps or []:
            if row['state'] is not None and row['state'] & PAUSED:
                vs = set(r['vdi'] for r in hv.back_minor.get(row['minor'], [])) | set(
                    hv.row_ident.get((row['pid'], row['minor'])) or ())
                for vu in vs:
                    q[href]['smlog']['pause'].add(vu)
                    if vu not in m.vdi_by_uuid:
                        continue
                    v = m.vdis[m.vdi_by_uuid[vu]]
                    mref = m.sr_master(v['SR'])
                    if mref is not None:
                        q[mref]['smlog']['pause'].add(vu)
                    if 'c12' not in opts.include:
                        continue
                    sr = m.srs.get(v['SR'])
                    if sr is None:
                        continue
                    ph = hv.phy.get((sr['uuid'], vu))
                    if ph and ph.get('target'):
                        q[href]['vhdcheck'].add(ph['target'])
                    if sr['type'] in LVM_SR_TYPES:
                        q[href]['vgs'].add('VG_XenStorage-' + sr['uuid'])
                        q[href]['dmcheck'].add(('VG_XenStorage-' + sr['uuid'], 'VHD-' + vu))
                    elif sr['type'] in FILE_SR_TYPES:
                        q[href]['srdirs'].add(sr['uuid'])
                        if ph and ph.get('target'):
                            q[href]['statfiles'].add(ph['target'])
                    for r, vbd in vdi_vbds(m, m.vdi_by_uuid[vu]):
                        vm = m.vms.get(vbd['VM'])
                        if vm and not vm['is_control_domain'] and vm['domid'] not in ('', '-1') \
                                and vbd['currently_attached']:
                            q[href]['xsread'].add('/local/domain/%s/control/shutdown' % vm['domid'])
        if hv.claim is not None:
            backed, _ = dom0_backed(a, href)
            for dp, cl in hv.claim.items():
                if not GUEST_DP_RE.match(dp):
                    continue
                for sr, vdi, st, key in cl:
                    if backed is not None and (vdi, dp) in backed:
                        continue
                    sref = m.sr_by_uuid.get(sr)
                    t = m.srs[sref]['type'] if sref else None
                    if t is None or t == 'linstor':
                        q[href]['smlog']['phy'].add(vdi)
                        q[href]['smlog']['drbd'] = True
                        if t == 'linstor':
                            q[href]['drbdres'] |= set(hv.linstor_vols(sr, vdi))
        dom0 = m.dom0_of(href)
        if dom0:
            for vb in m.vms[dom0]['VBDs']:
                vbd = m.vbds.get(vb)
                v = m.vdis.get(vbd['VDI']) if vbd else None
                if v is None:
                    continue
                sr = m.srs.get(v['SR'])
                if sr and (sr['uuid'], v['uuid']) not in hv.back_node:
                    q[href]['smlog']['activate'].add(v['uuid'])
                if sr and sr['type'] == 'linstor':
                    q[href]['smlog']['phy'].add(v['uuid'])
                    if vbd['currently_attached']:
                        q[href]['smlog']['drbd'] = True
                        q[href]['drbdres'] |= set(hv.linstor_vols(sr['uuid'], v['uuid']))
    return q


def collect_probes(ctx, a, only=None):
    m = a.model
    jobs = []
    for vref, v in sorted(m.vdis.items(), key=lambda kv: kv[1]['uuid']):
        smc = v['sm_config']
        if 'relinking' not in smc and 'activating' not in smc:
            continue
        if only is not None and v['uuid'] not in only:
            continue
        if any(k.startswith('host_') for k in smc):
            continue
        if 'relinking' in smc and not m.is_leaf(vref):
            continue
        if any(m.vbds[r]['currently_attached'] for r in v['VBDs'] if r in m.vbds):
            continue
        for href in m.plugged_hosts(v['SR']):
            hu = m.hosts[href]['uuid']
            funcs = ((ctx.caps.get(hu) or {}).get('on_slave') or {}).get('funcs')
            if funcs is not None and 'is_open' not in funcs:
                a.probes[(v['uuid'], hu)] = 'not asked: the on-slave plugin there has no is_open'
                continue
            jobs.append((v['uuid'], hu, v['SR']))

    def probe(job):
        vdi, hu, sref = job
        r = xe('host-call-plugin', 'host-uuid=' + hu, 'plugin=on-slave', 'fn=is_open', 'args:vdiUuid=' + vdi,
               'args:srRef=' + sref, timeout=PROBE_TIMEOUT)
        if not r.ok:
            return 'probe failed: %s' % r.why()
        out = r.out.strip()
        return out if out in ('True', 'False') else 'unexpected answer %s' % canon(out[:80])
    for job, (st, val) in parallel(probe, jobs, limit=4):
        a.probes[(job[0], job[1])] = val if st == 'ok' else 'probe failed: %s' % _text(val)


def collect_audit(ctx, n, first=False, only_hosts=None, probes=True, smlog=True, caps=False):
    opts = ctx.opts
    a = Audit(n)
    a.t0 = time.time()
    a.snap = pool_snapshot(ctx.api)
    a.model = Model(a.snap)
    hosts = ctx.host_objs(a.model)
    targets = [h for h in hosts if (h.live or h.local) and (only_hosts is None or h.uuid in only_hosts)]
    srs = sorted(r['uuid'] for r in a.model.srs.values())
    want = ['core'] + (['caps', 'rpm'] if first or not ctx.caps else ['caps'] if caps else [])

    def round1(h):
        return ctx.transport.call(h, 'facts', {'want': want, 'srs': srs})
    for h, (st, val) in parallel(round1, targets):
        if st != 'ok':
            a.errors[h.uuid] = _text(val)
            continue
        why = identity_problem(val, h.uuid)
        if why:
            a.errors[h.uuid] = why
            continue
        a.facts[h.uuid] = val
        for key, store in (('caps', ctx.caps), ('rpm', ctx.rpm), ('xapi_pkg', ctx.xapi_pkg)):
            f = val.get(key)
            if f is not None:
                if f.get('ok'):
                    store[h.uuid] = f['value']
                else:
                    store.pop(h.uuid, None)
    a.caps = ctx.caps
    a.rpm = ctx.rpm
    a.xapi_pkg = ctx.xapi_pkg
    a.vbd2 = sanitize(ctx.api.x.VBD.get_all_records())
    if not smlog:
        a.t = time.time()
        return a
    q = candidates_round2(a, opts)

    def round2(h):
        qq = q[h.ref]
        args = {'want': ['smlog', 'extra'] + (['drbd'] if qq['drbdres'] else []),
                'smlog': {'relink': sorted(qq['smlog']['relink']), 'abort': sorted(qq['smlog']['abort']),
                          'activate': sorted(qq['smlog']['activate']), 'pause': sorted(qq['smlog']['pause']),
                          'phy': sorted(qq['smlog']['phy']), 'drbd': qq['smlog']['drbd']},
                'statfiles': sorted(qq['statfiles']), 'vgs': sorted(qq['vgs']), 'srdirs': sorted(qq['srdirs']),
                'xsread': sorted(qq['xsread']), 'vhdcheck': sorted(qq['vhdcheck']), 'drbd': sorted(qq['drbdres']),
                'dmcheck': sorted([list(x) for x in qq['dmcheck']])}
        return ctx.transport.call(h, 'facts', args)
    for h, (st, val) in parallel(round2, [h for h in targets if h.uuid in a.facts]):
        if st != 'ok':
            a.errors.setdefault(h.uuid, _text(val))
            continue
        why = identity_problem(dict(val, identity_after=a.facts[h.uuid].get('identity')), h.uuid)
        if why:
            a.errors[h.uuid] = why
            a.facts.pop(h.uuid, None)
            continue
        sm = val.get('smlog') or {}
        if sm.get('ok'):
            a.smlog[h.uuid] = sm['value']
            for pid, info in sm['value'].get('pids', {}).items():
                a.pidinfo[(h.uuid, int(pid))] = info
            d = sm['value'].get('drbd') or {}
            if d.get('ok'):
                a.drbd.setdefault(h.uuid, {}).update(d['value'])
        d = val.get('drbd') or {}
        if d.get('ok'):
            a.drbd.setdefault(h.uuid, {}).update(d['value'])
        for key, store in (('statfiles', a.statfiles), ('lvnames', a.lvnames), ('srdir', a.srdirs),
                           ('xsread', a.xsread)):
            f = val.get(key) or {}
            if not f.get('ok'):
                continue
            for k, res in f['value'].items():
                if isinstance(res, dict) and 'ok' in res:
                    if res.get('ok'):
                        store[(h.uuid, k)] = res['value']
                else:
                    store[(h.uuid, k)] = res
        f = val.get('vhdcheck') or {}
        for k, rec in (f.get('value') or {}).items() if f.get('ok') else ():
            a.vhdchecks[(h.uuid, k)] = rec
        f = val.get('dmcheck') or {}
        for k, rec in (f.get('value') or {}).items() if f.get('ok') else ():
            a.dmchecks[(h.uuid, k)] = rec
    a._views = {}
    if probes:
        collect_probes(ctx, a)
    a.t = time.time()
    return a


def print_findings(ctx, final, plan, title=u'Findings'):
    if _OUT['json']:
        return
    order = {FIX: 0, UNKNOWN: 1, WAIT: 2, REPORT: 3, INFO: 4}
    shown = [e for e in final]
    say(u'')
    say(u'== %s ==' % title)
    if not shown:
        say(u'  Nothing found: every check came back clean.')
        return
    for e in sorted(shown, key=lambda e: (order[e['verdict']], e['cls'], e['title'])):
        say(u'  %-7s %s  %s' % (e['verdict'], e['cls'], e['title']))
        if e['reason']:
            for line in wrap(e['reason'], 96):
                say(u'                %s' % line)
        for x in e['evidence']:
            for line in wrap(x, 94):
                say(u'                  %s' % line)


def wrap(text, width):
    words = _text(text).split()
    lines, cur = [], u''
    for w in words:
        if cur and len(cur) + 1 + len(w) > width:
            lines.append(cur)
            cur = w
        else:
            cur = (cur + u' ' + w) if cur else w
    if cur:
        lines.append(cur)
    return lines or [u'']


def describe_item(model, it):
    hn = model.name_host(model.host_by_uuid.get(it.get('host'))) if it.get('host') else None
    a = it['action']
    if a == 'storage-db':
        return u'remove datapath %s of VDI %s from storage.db on %s' % (it['dp'], it['vdi'], hn)
    if a == 'release-vbd':
        txt = u'%s dom0 VBD %s on %s (VDI %s)' % ('unplug and destroy' if it['attached'] else 'destroy',
                                                  it['vbd'], hn, model.name_vdi(model.vdi_by_uuid.get(it['vdi'])))
        if it.get('inert'):
            txt += u', after making its stale backend node /dev/sm/backend/%s/%s (tap minor %d) inert' % (
                it['sr'], it['vdi'], it['inert']['rdev'][1])
        return txt
    if a == 'dp-destroy':
        return u'xe host-sm-dp-destroy %s of VDI %s on %s%s%s' % (
            it['dp'], it['vdi'], hn, (u' (once dom0 VBD(s) %s are released)' % ', '.join(it['needs']))
            if it.get('needs') else u'', (u', after making its stale backend node (tap minor %d) inert'
                                         % it['inert']['rdev'][1]) if it.get('inert') else u'')
    if a == 'remove-key':
        return u'remove sm-config:%s from VDI %s' % (it['key'], model.name_vdi(model.vdi_by_uuid.get(it['vdi'])))
    if a == 'unpause':
        return u'unpause tapdisk pid %s on %s (VDI %s) with SM\'s tapdisk-pause code, under the VDI\'s SM lock' % (
            it['pid'], hn, model.name_vdi(model.vdi_by_uuid.get(it['vdi'])))
    if a == 'unlink-abort':
        return u'remove %s/%s/abort on %s, then xe sr-scan the SR' % (IPC_DIR, it['sr'], hn)
    return canon(it)


def ha_off_bound(opts, hosts, master=False):
    per_host = (getattr(opts, 'ha_off_wait', 0) + 2 * AGENT_TIMEOUT + ACT_START_TIMEOUT + ACT_WAIT + FETCH_TIMEOUT +
                VERIFY_DELAY + LIVE_WAIT + ENSURE_TIMEOUT)
    enable = XHAD_GONE_WAIT + LIVE_WAIT + 2 * INIT_WAIT + HA_ENABLE_WINDOW + HA_ENABLE_TIMEOUT + REARM_WAIT
    if master:
        enable += ANSWER_WAIT + INIT_WAIT
    return int((per_host * hosts + enable + 59) // 60)


def print_plan(ctx, audit, plan, ha):
    if _OUT['json']:
        return
    model = audit.model
    say(u'')
    say(u'== Changes ==')
    if not plan:
        say(u'  None.')
        return
    for code, label in PHASES:
        items = [it for it in plan if it['phase'] == code]
        if not items:
            continue
        say(u'  %s:' % label)
        for it in items:
            for i, line in enumerate(wrap(describe_item(model, it), 92)):
                say((u'   %3d. %s' % (it['seq'], line)) if i == 0 else (u'        %s' % line))
    say(u'')
    say(u'Impact:')
    stops = []
    for it in plan:
        if it['action'] == 'storage-db' and it['host'] not in stops:
            stops.append(it['host'])
    if stops:
        master = model.hosts.get(model.pool['master'], {}).get('uuid')
        slaves = [model.name_host(model.host_by_uuid.get(u)) for u in stops if u != master]
        if slaves:
            say(u'  - xapi is stopped and started on %s, one host at a time, about a minute each. Running VMs are '
                u'not affected; no VM can be started, stopped or migrated on that host meanwhile, and backups '
                u'touching it fail.' % ', '.join(slaves))
        if master in stops:
            say(u'  - xapi on the pool master, %s, is stopped and started%s, about a minute. While it is down the '
                u'whole pool\'s API is down: no VM can be started, stopped or migrated on any host, Xen Orchestra '
                u'loses the pool, and backups of the pool fail. Running VMs are not affected.'
                % (model.name_host(model.pool['master']), ' last' if slaves else ''))
        for u in stops:
            href = model.host_by_uuid.get(u)
            if href is None:
                continue
            keys, why, notes = xapi_move(audit, href)
            if notes:
                say(u'  - %s: %s, so this restart starts the installed xapi there.'
                    % (model.name_host(href), '; '.join(notes)))
        if ha is not None:
            say(u'  - HA is on: it is disabled before the first xapi stop and enabled again after the last one, and the '
                u'pool is not protected by HA in between: normally a few minutes. If a host is slow to come back, '
                u'this run gives up after roughly %d minutes in all and prints how to put HA back. That is an '
                u'estimate, not a limit: a step that hangs (a xapi stop or start that never returns, a disk that stops '
                u'answering, this host failing) keeps HA off until it is resolved by hand; the agent on the host '
                u'reports a step that makes no progress for %d minutes, and this run then stops waiting for it.'
                % (ha_off_bound(ctx.opts, len(stops), master in stops), GUARDIAN_STALL // 60))
            say(u'    If this run is killed, %s recover puts HA back once every host is ready (on another host, if '
                u'this one is gone: recover --run with the run id the pool-wide note other-config:%s names);'
                % (sys.argv[0], HA_MARKER))
            say(u'    by hand, it is:')
            for line in ha.commands():
                say(u'        ' + line)
    n_vbd = len([it for it in plan if it['action'] == 'release-vbd'])
    if n_vbd:
        say(u'  - %d dom0 VBD(s) are unplugged and destroyed (the VDIs themselves are not touched).' % n_vbd)
    n_inert = len([it for it in plan if it.get('inert')])
    if n_inert:
        say(u'  - %d stale backend node(s) whose tapdisk is gone are replaced by an inert file first, so that SM\'s '
            u'teardown cannot shut down or pause whatever tapdisk now holds their old tap minor. SM removes the file '
            u'when it tears the disk down.' % n_inert)
    n_key = len([it for it in plan if it['action'] == 'remove-key'])
    if n_key:
        say(u'  - %d sm-config key(s) are removed.' % n_key)
    if any(it['action'] in ('unlink-abort',) for it in plan) or any(it.get('kick') for it in plan):
        say(u'  - The garbage collector is started on the affected SR(s) afterwards; it may coalesce and relink.')
    if any(it['action'] == 'unpause' for it in plan):
        say(u'  - Paused disks resume I/O; a VM that was waiting on one continues.')
    say(u'  Every change is re-proved from a fresh read right before it is made, and skipped if it no longer holds.')
    say(u'  No continuous event watch runs: instead, right before each call xapi\'s event log is checked for what that')
    say(u'  change depends on (its disk, the dom0 VBDs and VM operations on its host, tasks on its host, the GC of')
    say(u'  its SR), and the change is skipped if any of it changed since that read.')


class HaCapture(object):
    def __init__(self, d):
        self.d = d

    def enable_args(self):
        args = ['pool-ha-enable', 'heartbeat-sr-uuids=' + ','.join(self.d['srs'])]
        for k, v in self.d['config']:
            args.append('ha-config:%s=%s' % (k, v))
        return args

    def commands(self, enable=True):
        lines = [u' '.join(['xe'] + [_quote(a) for a in self.enable_args()])] if enable else []
        for param, value in (('ha-host-failures-to-tolerate', self.d['tolerate']),
                             ('ha-allow-overcommit', self.d['overcommit'])):
            lines.append(u'xe pool-param-set %s %s' % (_quote('uuid=' + self.d['pool']),
                                                       _quote('%s=%s' % (param, value))))
        return lines


def capture_ha(model):
    p = model.pool
    on = p.get('ha_enabled')
    if on is False:
        return None
    if on is not True:
        raise Refused('pool.ha_enabled reads %s, not true or false' % canon(on))
    srs, statefiles = [], []
    for sf in p.get('ha_statefiles') or []:
        vref = sf if sf.startswith('OpaqueRef:') else model.vdi_by_uuid.get(sf)
        v = model.vdis.get(vref)
        if v is None or v['type'] != 'ha_statefile':
            raise Refused('HA statefile %s cannot be resolved to an HA statefile VDI' % sf)
        sr = model.srs.get(v['SR'])
        if sr is None:
            raise Refused('the SR of HA statefile %s cannot be found' % v['uuid'])
        statefiles.append(v['uuid'])
        if sr['uuid'] not in srs:
            srs.append(sr['uuid'])
    if not srs:
        raise Refused('HA is enabled but no statefile is listed, so the heartbeat SR to enable it on again '
                      'cannot be established')
    oc = p.get('ha_allow_overcommit')
    if oc not in (True, False):
        raise Refused('pool.ha_allow_overcommit reads %s' % canon(oc))
    vms = {}
    for ref, vm in model.vms.items():
        if vm['is_control_domain'] or vm['is_a_template'] or vm['is_a_snapshot']:
            continue
        vms[vm['uuid']] = [vm.get('ha_restart_priority'), vm.get('order'), vm.get('start_delay')]
    return HaCapture({'pool': p['uuid'], 'srs': srs, 'statefiles': statefiles,
                      'config': sorted([k, v] for k, v in (p.get('ha_configuration') or {}).items()),
                      'tolerate': _text(p.get('ha_host_failures_to_tolerate')),
                      'overcommit': 'true' if oc else 'false', 'stack': p.get('ha_cluster_stack'),
                      'plan': _text(p.get('ha_plan_exists_for')), 'vms': vms,
                      'enabled': sorted(h['uuid'] for h in model.hosts.values() if h.get('enabled') is True)})


HA_MARKER = 'storage-state-fixer-ha-off'


def ha_operations(pool):
    return sorted(set(v for v in (pool.get('current_operations') or {}).values() if v in ('ha_enable', 'ha_disable')))


def ha_marker_of(pool):
    raw = (pool.get('other_config') or {}).get(HA_MARKER)
    if not raw:
        return None
    try:
        mark = json.loads(raw)
    except ValueError:
        return {'raw': _text(raw)[:200]}
    return mark if isinstance(mark, dict) else {'raw': _text(raw)[:200]}


HA_SETTINGS = ('pool', 'srs', 'statefiles', 'config', 'tolerate', 'overcommit', 'stack')


def same_ha(ha, ha2):
    if ha is None or ha2 is None:
        return ha is None and ha2 is None
    if canon([ha.d[k] for k in HA_SETTINGS]) != canon([ha2.d[k] for k in HA_SETTINGS]):
        return False
    both = set(ha.d['vms']) & set(ha2.d['vms'])
    return all(canon(ha.d['vms'][u]) == canon(ha2.d['vms'][u]) for u in both)


def ha_host_problems(model, ha):
    bad = []
    for href, h in model.hosts.items():
        if not model.host_live(href):
            bad.append('%s is not live' % h['name_label'])
        elif not h.get('ha_statefiles'):
            bad.append('%s has no access to the HA statefile' % h['name_label'])
    for ref, pif in sorted(model.pifs.items(), key=lambda kv: kv[1].get('uuid') or ''):
        if pif.get('disallow_unplug') is True and pif.get('currently_attached') is not True:
            bad.append('PIF %s (%s) on %s is marked disallow-unplug but is not attached: xapi refuses to enable HA '
                       'again while it is (REQUIRED_PIF_IS_UNPLUGGED)' % (pif.get('device'), pif.get('uuid'),
                                                                          model.name_host(pif.get('host'))))
    split = version_split(model)
    if split:
        bad.append('the hosts run different xapi or platform versions, and xapi refuses to enable HA while they do '
                   '(NOT_SUPPORTED_DURING_UPGRADE): %s' % '; '.join(split[:4]))
    for sr_uuid in ha.d['srs']:
        sref = model.sr_by_uuid.get(sr_uuid)
        plugged = set(model.plugged_hosts(sref)) if sref else set()
        for href, h in model.hosts.items():
            if href not in plugged:
                bad.append('%s does not have the heartbeat SR %s plugged' % (h['name_label'], sr_uuid))
    return bad


class Journal(object):
    def __init__(self, run_dir):
        self.path = os.path.join(run_dir, 'journal.jsonl')

    def rec(self, event, **fields):
        fields['event'] = event
        fields['t'] = time.time()
        line = (json.dumps(fields, sort_keys=True) + '\n').encode('utf-8')
        created = not os.path.exists(self.path)
        fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        try:
            start = os.fstat(fd).st_size
            try:
                append_all(fd, line)
                os.fsync(fd)
            except EnvironmentError:
                try:
                    os.ftruncate(fd, start)
                    os.fsync(fd)
                except EnvironmentError:
                    pass
                raise
        finally:
            os.close(fd)
        if created:
            fsync_dir(self.path)


def read_journal(path):
    out = []
    for line in read_text(path).splitlines():
        if not line.strip():
            continue
        try:
            out.append(json.loads(line))
        except ValueError:
            out.append({'event': 'unreadable', 'raw': line[:200]})
    return out


def open_journals():
    out = []
    root = os.path.join(RUN_ROOT, 'runs')
    for name in _listdir(root):
        p = os.path.join(root, name, 'journal.jsonl')
        if not os.path.exists(p):
            continue
        recs = read_journal(p)
        if not recs or recs[-1].get('event') != 'closed':
            out.append((name, p, recs))
    return out


def new_run_dir():
    root = os.path.join(RUN_ROOT, 'runs')
    if not os.path.isdir(root):
        os.makedirs(root, 0o700)
    st = os.statvfs(root)
    if st.f_bavail * st.f_frsize < (100 << 20):
        raise Refused('%s has less than 100 MiB free for the run record' % root)
    run_id = time.strftime('%Y%m%d-%H%M%S') + '-' + hashlib.sha256(os.urandom(16)).hexdigest()[:6]
    d = os.path.join(root, run_id)
    os.makedirs(d, 0o700)
    return run_id, d


def save_json_gz(path, obj):
    data = gzip.compress(json.dumps(obj, sort_keys=True, default=_text).encode('utf-8'))
    write_new(path, data)


def prune_runs(keep=20):
    root = os.path.join(RUN_ROOT, 'runs')
    closed = []
    for name in _listdir(root):
        d = os.path.join(root, name)
        p = os.path.join(d, 'journal.jsonl')
        has_backup = False
        for dirpath, dirs, files in os.walk(d):
            if any(f.endswith('.bak') for f in files):
                has_backup = True
        if has_backup:
            continue
        if os.path.exists(p):
            recs = read_journal(p)
            if not recs or recs[-1].get('event') != 'closed':
                continue
        closed.append(name)
    for name in sorted(closed)[:-keep] if len(closed) > keep else []:
        d = os.path.join(root, name)
        for dirpath, dirs, files in os.walk(d, topdown=False):
            for f in files:
                _unlink_quietly(os.path.join(dirpath, f))
            try:
                os.rmdir(dirpath)
            except OSError:
                pass


class Engine(object):
    def __init__(self, ctx, plan, audits, ha, run_id, run_dir):
        self.ctx = ctx
        self.opts = ctx.opts
        self.plan = plan
        self.audits = audits
        self.ha = ha
        self.run_id = run_id
        self.run_dir = run_dir
        self.j = Journal(run_dir)
        self.halt = None
        self.results = {}
        self.acting = set()
        self.problems = []
        self.ha_touched = False
        self.ha_restored = False
        self.ha_pending = None
        self.init_late = []
        self.settled = {}
        self.acts = {}
        self.attempts = collections.Counter()
        self.kicked = {}
        self.kick_tried = set()
        self.fixed_c10_srs = set()
        self.inert_made = set()
        self.storage_open = {}
        self.act_items = {}
        self.journal_broken = False
        self.token = None
        self.n = 10
        if audits:
            ctx.host_objs(audits[-1].model)

    def result(self, it, status, detail=u'', show=True):
        self.results[it['seq']] = (status, _text(detail))
        try:
            self.j.rec('item', seq=it['seq'], status=status, detail=_text(detail), item=it)
        except EnvironmentError as exc:
            if not self.journal_broken:
                self.journal_broken = True
                self.fail('the run record %s cannot be written: %s' % (self.j.path, _text(exc)))
        if show:
            step('  %d. %s: %s%s' % (it['seq'], it['cls'], status, (' - ' + _text(detail)) if detail else ''))

    def fail(self, text):
        self.problems.append(_text(text))
        error(text)

    def stop_forward(self, why):
        if self.halt is None:
            self.halt = _text(why)
            self.fail('stopping here: %s. Nothing more is attempted in this run.' % why)

    def host(self, uuid):
        for attempt in (0, 1):
            for h in self.ctx.hosts.values():
                if h.uuid == uuid:
                    return h
            if attempt == 0:
                self.ctx.host_objs(Model(pool_snapshot(self.ctx.api)))
        raise Failed('host %s is not in the pool any more' % uuid)

    def audit(self, hosts=None, smlog=True, probes=False, only_vdis=None):
        self.n += 1
        token = self.event_token()
        a = collect_audit(self.ctx, self.n, only_hosts=hosts, probes=False, smlog=smlog, caps=True)
        a.token = token
        if probes:
            collect_probes(self.ctx, a, only=only_vdis)
        return a

    def event_token(self):
        epoch = getattr(self.ctx.api, 'epoch', None)
        if epoch != getattr(self, 'token_epoch', None):
            self.token, self.token_epoch = None, epoch
        err = None
        for tok in ([self.token, ''] if self.token else ['']):
            try:
                self.token = getattr(self.ctx.api.x.event, 'from')(EVENT_CLASSES, tok, 0.0)['token']
                return self.token
            except Exception as exc:
                self.token, err = None, exc
        self.j.rec('event_token', error=_text(err))
        return None

    def changed(self, fresh, h, vdis=(), vbds=(), srs=()):
        token = getattr(fresh, 'token', None)
        if token is None:
            return 'the event check failed: no event token could be taken before the read'
        try:
            res = getattr(self.ctx.api.x.event, 'from')(EVENT_CLASSES, token, 0.0)
        except Exception as exc:
            return 'the event check failed: %s' % _text(exc)
        m = fresh.model
        href = m.host_by_uuid.get(h.uuid) if h is not None else None
        dom0 = m.dom0_of(href) if href else None
        vdi_refs = set(m.vdi_by_uuid[u] for u in vdis if u in m.vdi_by_uuid)
        sr_refs = set(m.sr_by_uuid[u] for u in srs if u in m.sr_by_uuid)
        known = set(m.vbd_by_uuid[u] for u in vbds if u in m.vbd_by_uuid)
        known |= set(r for r, v in m.vbds.items() if (dom0 and v['VM'] == dom0) or v['VDI'] in vdi_refs)
        owners = set(m.vbds[r]['VM'] for r in known if r in m.vbds) - set([dom0])
        names = set(vdis) | set(srs)
        out = []
        seen = 0
        for e in sanitize(res.get('events') or []):
            seen += 1
            cls, ref = e.get('class'), e.get('ref')
            op, snap = e.get('operation'), e.get('snapshot') or {}
            if not isinstance(snap, dict):
                snap = {}
            if cls == 'task':
                label = snap.get('name_label') or ''
                if op == 'del' or snap.get('status') != 'pending' or label in HOUSEKEEPING_TASKS:
                    continue
                if label == 'Garbage Collection':
                    gsr = [s for s in srs if (snap.get('name_description') or '').endswith(s)]
                    if gsr:
                        out.append('the GC of SR %s started' % gsr[0])
                elif h is not None and (h.is_master or snap.get('resident_on') == href):
                    out.append('task "%s" started' % label)
                elif h is None and (label.startswith(('VDI.', 'SR.')) or
                                    any(n in (snap.get('name_description') or '') for n in names)):
                    out.append('task "%s" started' % label)
            elif cls == 'vbd':
                if ref in known or (dom0 and snap.get('VM') == dom0) or snap.get('VDI') in vdi_refs:
                    out.append('VBD %s: %s' % (snap.get('uuid') or ref, op))
            elif cls == 'vm':
                ops = snap.get('current_operations') or {}
                if ref in owners or (href and ops and href in (snap.get('resident_on'),
                                                              snap.get('scheduled_to_be_resident_on'))):
                    out.append('VM "%s": %s' % (snap.get('name_label') or ref, op))
            elif cls == 'vdi':
                if ref in vdi_refs:
                    out.append('VDI %s: %s' % (snap.get('uuid') or ref, op))
            elif cls == 'pbd':
                if snap.get('SR') in sr_refs or (op == 'del' and any(ref in m.srs[s]['PBDs'] for s in sr_refs)):
                    out.append('PBD %s of SR %s: %s' % (snap.get('uuid') or ref, m.srs.get(snap.get('SR'), {})
                                                         .get('uuid') or '?', op))
            elif cls == 'sr':
                if ref in sr_refs and (op == 'del' or sorted(snap.get('PBDs') or []) != sorted(m.srs[ref]['PBDs'])):
                    out.append('SR %s: %s' % (snap.get('uuid') or ref, op))
            elif cls == 'pool':
                if op == 'del' or snap.get('master') != m.pool.get('master') or \
                        snap.get('ha_enabled') != m.pool.get('ha_enabled'):
                    out.append('the pool master or HA changed')
        out = list(collections.OrderedDict.fromkeys(out))
        self.j.rec('event_check', host=h.uuid if h is not None else None, vdis=list(vdis), srs=list(srs),
                   seen=seen, changed=out[:8])
        return '; '.join(out[:4]) if out else None

    def fence_up(self, it, plan, hold=FENCE_HOLD, action=None):
        self.fence_n = getattr(self, 'fence_n', 0) + 1
        tag = 'i%d-%d' % (it['seq'], self.fence_n)
        specs = []
        for h, locks in plan:
            spec = {'run_id': self.run_id, 'host_uuid': h.uuid, 'tag': tag, 'locks': locks, 'hold': hold}
            if action is not None:
                spec['action'] = action
            if self.ctx.transport.paths:
                spec['paths'] = self.ctx.transport.paths
            specs.append((h, spec))
        self.j.rec('fence_up', seq=it['seq'], tag=tag, hosts=[h.uuid for h, s in specs],
                   locks=[s['locks'] for h, s in specs], action=action)
        res = parallel(lambda hs: self.ctx.transport.call(hs[0], 'fence-start', {'spec': hs[1]},
                                                          timeout=FENCE_ACQUIRE + 60), specs)
        fences, why, states = [], None, {}
        for (h, spec), (st, val) in res:
            fences.append((h, spec))
            if st != 'ok':
                why = why or 'the exclusion could not be taken on %s: %s' % (h.name, _text(val))
                continue
            status = (val or {}).get('status') or {}
            states[h.uuid] = status.get('state')
            if action is None and status.get('state') != 'held':
                why = why or 'the exclusion could not be taken on %s: %s' % (
                    h.name, status.get('detail') or status.get('state') or 'no answer from its holder')
        self.j.rec('fence_state', seq=it['seq'], tag=tag, states=states, why=why)
        return fences, why

    def fence_check(self, fences, margin):
        for h, spec in fences:
            try:
                rep = self.ctx.transport.call(h, 'fence-status', {'run_id': spec['run_id'], 'host_uuid': h.uuid,
                                                                  'tag': spec['tag']}, timeout=60)
            except CallError as exc:
                return 'the exclusion on %s cannot be confirmed: %s' % (h.name, _text(exc))
            st = (rep.get('status') or {}).get('state')
            left = rep.get('left')
            if not rep.get('alive') or st != 'held':
                if st == 'lost':
                    return 'the exclusion on %s is no longer held: %s' % (
                        h.name, (rep.get('status') or {}).get('detail') or 'its lock file was removed')
                return 'the exclusion on %s is no longer held (%s)' % (h.name, st if rep.get('alive') else
                                                                        'its holder is gone')
            if left is None or left < margin:
                return 'the exclusion on %s ends in %ss, too soon to act within it' % (
                    h.name, int(left) if left is not None else '?')
        return None

    def fence_down(self, fences):
        for h, spec in fences:
            try:
                rep = self.ctx.transport.call(h, 'fence-release', {'run_id': spec['run_id'], 'host_uuid': h.uuid,
                                                                   'tag': spec['tag']}, timeout=60)
                self.j.rec('fence_down', host=h.uuid, tag=spec['tag'], state=(rep.get('status') or {}).get('state'),
                           alive=rep.get('alive'))
            except (CallError, EnvironmentError) as exc:
                warn('the SM lock(s) %s held on %s for this run could not be released by request (%s); its holder lets '
                     'them go by itself within %ds' % (canon(spec['locks']), h.name, _text(exc), int(spec['hold'])))

    def run(self):
        try:
            for name, fn in (('S', self.phase_s), ('V', self.phase_v), ('L', self.phase_l), ('F', self.phase_f),
                             ('P', self.phase_p), ('G', self.phase_g)):
                items = [it for it in self.plan if it['phase'] == name]
                if not items and not (name == 'G' and self.fixed_c10_srs):
                    continue
                if self.halt:
                    for it in items:
                        if it['seq'] not in self.results:
                            self.result(it, 'not-attempted', self.halt)
                    continue
                step('Phase %s: %s' % (name, dict(PHASES)[name]))
                fn(items)
                checkpoint()
        except Interrupted as exc:
            self.stop_forward(_text(exc))
        except (Failed, Refused, CallError) as exc:
            self.stop_forward(_text(exc))
        except Exception as exc:
            import traceback
            self.j.rec('crash', trace=_text(traceback.format_exc())[-4000:])
            self.stop_forward('internal error: %s: %s' % (exc.__class__.__name__, _text(exc)))
        finally:
            self.settle()
        for it in self.plan:
            if it['seq'] in self.results:
                continue
            if it['seq'] in self.acting:
                self.result(it, 'failed', 'the run stopped after its change was started, so whether it was made is not '
                            'established (see the final audit)%s' % ((': ' + self.halt) if self.halt else ''))
            else:
                self.result(it, 'not-attempted', self.halt or '')

    def act_on(self, *items):
        for it in items:
            self.acting.add(it['seq'])

    def recheck(self, fresh, it):
        per = evaluate(fresh, self.opts)
        key = changed = None
        for k, e in per.items():
            if e['verdict'] == FIX and e.get('item') is not None and \
                    item_key(e['item']) == item_key(dict(it, seq=None)):
                return e, None
            if self.same_target(e, it):
                if e['verdict'] != FIX:
                    key = e
                else:
                    changed = e
        if key is not None:
            return None, '%s: %s' % (key['verdict'], key['reason'])
        if changed is not None:
            return None, 'its state changed since it was planned (it still qualifies, but not as planned): run check again'
        return None, 'it is no longer found'

    def same_target(self, e, it):
        k = e['key']
        if it['action'] == 'storage-db':
            return k[0] == 'DP0' and k[1:] == [it['host'], it['sr'], it['vdi'], it['dp']]
        if it['action'] == 'release-vbd':
            return k == ['VBD', it['vbd']]
        if it['action'] == 'dp-destroy':
            return k == ['C03', it['host'], it['sr'], it['vdi'], it['dp']]
        if it['action'] == 'remove-key':
            return k == [it['cls'], it['vdi']]
        if it['action'] == 'unlink-abort':
            return k == ['C08', it['host'], it['sr']]
        if it['action'] == 'unpause':
            return k == ['C12', it['host'], it['pid'], it['minor']]
        return False

    def all_hosts_ha(self, with_ready=False):
        hosts = [h for h in self.ctx.hosts.values()]
        out = {}
        for h, (st, val) in parallel(lambda h: self.ctx.transport.call(h, 'facts', {'want': ['ha']}, timeout=120),
                                     hosts):
            if st != 'ok':
                out[h.uuid] = (None, None, _text(val), False)
                continue
            f = val.get('ha') or {}
            xs, ck = val.get('xapi') or {}, val.get('cookies') or {}
            ready = bool(xs.get('ok') and ck.get('ok') and xapi_ready(xs['value'], ck['value']))
            if not f.get('ok'):
                out[h.uuid] = (None, None, f.get('error'), ready)
            else:
                out[h.uuid] = (f['value']['armed'], f['value']['xhad'], None, ready)
        return out

    def unsettled(self):
        return sorted(u for u, ok in self.settled.items() if not ok)

    def disarmed_problems(self):
        bad = []
        for uuid, (armed, xh, err, ready) in sorted(self.all_hosts_ha().items()):
            name = self.name_of(uuid)
            if err:
                bad.append('%s: HA state not established (%s)' % (name, err))
            elif armed not in ('false', 'absent'):
                bad.append('%s has ha.armed=%s' % (name, armed))
            elif xh:
                bad.append('%s runs xhad (pid %s)' % (name, ', '.join(str(p) for p in xh)))
        return bad

    def stop_gate(self, h, items, ha_off):
        fresh = self.audit(smlog=True)
        m = fresh.model
        reasons = []
        if ha_off:
            if m.pool.get('ha_enabled') is not False:
                reasons.append('pool HA reads %s' % canon(m.pool.get('ha_enabled')))
            reasons.extend(self.disarmed_problems())
        href = m.host_by_uuid.get(h.uuid)
        if href is None or not m.host_live(href):
            return ['the host is not live'], fresh
        if ha_off or self.ha is not None:
            for r2, h2 in sorted(m.hosts.items()):
                if not m.host_live(r2):
                    reasons.append('%s is not live, so HA could not be enabled again' % h2['name_label'])
        hv = fresh.view(href)
        if hv.identity is None or hv.identity.get('uuid') != h.uuid:
            reasons.append('the host did not answer as itself')
        if hv.room is None or hv.sdb is None:
            reasons.append('the free space for the storage.db backup on this host is not established')
        elif hv.room['free'] < 2 * hv.sdb['size'] + (1 << 20):
            reasons.append('%s has %d bytes free, too little for the storage.db backup' % (hv.room['path'],
                                                                                         hv.room['free']))
        tasks = m.pending_tasks(None if h.is_master else href, work=True)
        for t in tasks:
            reasons.append('task "%s" (%s) is pending%s' % (t['name_label'], t['uuid'],
                                                            '' if h.is_master else ' on this host'))
        scope = list(m.hosts) if h.is_master else [href]
        for sref in scope:
            sv = fresh.view(sref)
            busy = sv.sm_busy()
            if busy is None:
                reasons.append('the processes on %s were not read' % sv.name)
            else:
                for p in busy:
                    reasons.append('SM is busy on %s: pid %d %s' % (sv.name, p['pid'],
                                                                   ' '.join((p.get('argv') or [])[:3])[:120]))
            if sv.locks is None:
                reasons.append('the SM locks on %s were not read' % sv.name)
            else:
                for l in sv.locks:
                    reasons.append('%s is held by pid %d on %s' % (l['path'] or 'an unlinked SM lock file', l['pid'],
                                                                   sv.name))
        if h.is_master:
            for sref2, sr in m.srs.items():
                if not sr['PBDs']:
                    continue
                st, why = gc_state(fresh, sref2)
                if st != 'idle' and m.plugged_hosts(sref2):
                    reasons.append('GC on SR %s: %s (%s)' % (sr['name_label'], st, '; '.join(why)))
        for vdi_uuid, rows in hv.tap_vdis.items():
            vref = m.vdi_by_uuid.get(vdi_uuid)
            if vref is None:
                continue
            v = m.vdis[vref]
            st, why = gc_state(fresh, v['SR'])
            if st != 'idle':
                reasons.append('GC on SR %s, which has a disk served here: %s' % (m.srs[v['SR']]['name_label'], st))
            for k in ('paused', 'relinking'):
                if k in v['sm_config']:
                    reasons.append('VDI %s, served here, carries %s' % (vdi_uuid, k))
        if hv.unmapped:
            reasons.append('%d tapdisk(s) here serve images that cannot be mapped to a VDI' % len(hv.unmapped))
        for row in hv.taps or []:
            if row['state'] is not None and row['state'] & PAUSED:
                reasons.append('tapdisk pid %s minor %s is paused' % (row['pid'], row['minor']))
            elif row['state'] is not None and row['state'] & ~LOG_DROPPED:
                reasons.append('tapdisk pid %s minor %s is in state %s (%s)' % (
                    row['pid'], row['minor'], tap_state_text(row['state']), tap_state_names(row['state'])))
        if hv.taps is None:
            reasons.append('tap-ctl list did not answer')
        if hv.sdb_error:
            reasons.append(hv.sdb_error)
        for it in items:
            e, why = self.recheck(fresh, it)
            if e is None:
                reasons.append('%s %s of %s: %s' % (it['cls'], it['dp'], it['vdi'], why))
        return sorted(set(reasons)), fresh

    def wait_gate(self, h, items, ha_off, limit, every):
        deadline = _now() + limit
        shown = None
        while True:
            reasons, fresh = self.stop_gate(h, items, ha_off)
            if not reasons:
                return [], fresh
            if _now() + every > deadline:
                return reasons, fresh
            if reasons != shown:
                step('  %s is not ready for a xapi stop yet: %s; re-checking every %ds for up to %s'
                     % (h.name, '; '.join(reasons[:4]), every, format_age(deadline - _now())))
                shown = reasons
            pause(every)

    def phase_s(self, items):
        by = collections.OrderedDict()
        for it in items:
            by.setdefault(it['host'], []).append(it)
        hosts = sorted((self.host(u) for u in by), key=lambda h: (h.is_master, h.name))
        ready = []
        for h in hosts:
            reasons, _ = self.wait_gate(h, by[h.uuid], False, self.opts.wait, RETEST_EVERY)
            if reasons:
                for it in by[h.uuid]:
                    self.result(it, 'skipped', 'not stopped: %s' % '; '.join(reasons[:6]))
            else:
                ready.append(h)
            checkpoint()
        if not ready:
            return
        if self.ha is not None:
            again = []
            for h in ready:
                reasons, _ = self.stop_gate(h, by[h.uuid], False)
                if reasons:
                    for it in by[h.uuid]:
                        self.result(it, 'skipped', 'not stopped: %s' % '; '.join(reasons[:6]))
                else:
                    again.append(h)
            ready = again
            if not ready:
                return
            try:
                self.disable_ha()
            except Skip as exc:
                for h in ready:
                    for it in by[h.uuid]:
                        self.result(it, 'skipped', _text(exc))
                return
        else:
            bad = self.disarmed_problems()
            if bad:
                raise Failed('HA is off in the pool but not disarmed everywhere (%s); xapi is not stopped'
                             % '; '.join(bad))
        checkpoint()
        late = None
        for h in ready:
            if self.halt or late:
                for it in by[h.uuid]:
                    self.result(it, 'not-attempted', self.halt or late)
                continue
            reasons, fresh = self.wait_gate(h, by[h.uuid], True, min(self.opts.ha_off_wait, self.opts.wait), 5)
            if reasons:
                for it in by[h.uuid]:
                    self.result(it, 'skipped', 'not stopped: %s' % '; '.join(reasons[:6]))
                continue
            self.stop_edit_start(h, by[h.uuid], fresh)
            if h.uuid in self.unsettled() or h.name in self.init_late:
                late = ('xapi on %s is not proven up and initialised after its restart, so xapi is not stopped on '
                        'another host' % h.name)
            checkpoint()
        if self.ha_touched:
            self.enable_ha()
            if self.ha_pending is not None:
                raise Failed('HA could not be put back (%s), so nothing else is changed with HA off'
                             % self.ha_pending)
        bad = sorted(set(self.init_late) | set(self.host(u).name for u in self.unsettled()))
        if bad:
            raise Failed('xapi on %s is not proven up and initialised after its restart, so nothing else is changed '
                         'in this run' % ', '.join(bad))

    def stop_edit_start(self, h, items, fresh):
        m = fresh.model
        href = m.host_by_uuid[h.uuid]
        hv = fresh.view(href)
        backed, naming = dom0_backed(fresh, href)
        if backed is None or naming:
            for it in items:
                self.result(it, 'skipped', 'not stopped: the dom0 VBDs of %s cannot all be named (%s)'
                            % (h.name, naming))
            return
        self.attempts[h.uuid] += 1
        attempt = self.attempts[h.uuid]
        spec = {'run_id': self.run_id, 'host_uuid': h.uuid, 'hostname': hv.identity['hostname'],
                'attempt': attempt, 'is_master': h.is_master,
                'items': [{'sr': it['sr'], 'vdi': it['vdi'], 'dp': it['dp'],
                           'lvm': hv.sr_type(it['sr']) in LVM_SR_TYPES} for it in items],
                'backed': sorted([list(b) for b in backed]),
                'paused': [[r['pid'], r['minor']] for r in hv.taps or [] if r['state'] is not None and r['state'] & PAUSED]}
        if self.ctx.transport.paths:
            spec['paths'] = self.ctx.transport.paths
        moved = self.changed(fresh, h, vdis=sorted(set(it['vdi'] for it in items)),
                             srs=sorted(set(it['sr'] for it in items)))
        if moved:
            self.settled[h.uuid] = True
            for it in items:
                self.result(it, 'skipped', 'not stopped: something changed since the host was re-checked (%s); run '
                                           'check again' % moved)
            return
        self.j.rec('act_begin', host=h.uuid, attempt=attempt, items=spec['items'])
        self.acts[h.uuid] = attempt
        self.act_items[h.uuid] = list(items)
        step('  %s: handing the stop/edit/start to its agent (it runs detached, with a guardian that starts '
             'xapi again if it dies)' % h.name)
        self.act_on(*items)
        self.ctx.transport.call(h, 'act-start', {'spec': spec}, timeout=ACT_START_TIMEOUT)
        st = self.poll_act(h, attempt)
        state = (st.get('status') or {}).get('state')
        detail = (st.get('status') or {}).get('detail')
        self.j.rec('act_end', host=h.uuid, attempt=attempt, state=state, status=st.get('status'))
        stat_ = st.get('status') or {}
        removed = set(tuple(x) for x in stat_.get('removed') or [])
        if stat_.get('backup'):
            self.keep_backup(h, attempt, stat_['backup'])
        done_start = {}
        if state == 'refused':
            self.settled[h.uuid] = True
            for it in items:
                self.result(it, 'skipped', 'the host refused, nothing was stopped: %s' % detail)
            return
        if state == 'rolled-back':
            after = stat_.get('start_after_rollback') or {}
            self.settled[h.uuid] = bool(after.get('answering') and after.get('complete'))
        elif state == 'done':
            done_start = self.start_record(h, stat_)
            self.settled[h.uuid] = bool(done_start.get('answering') and done_start.get('complete'))
        else:
            self.settled[h.uuid] = False
        for it in items:
            if (it['sr'], it['vdi'], it['dp']) in removed and state == 'done':
                self.result(it, 'written', 'removed from storage.db; not yet read back')
        if h.is_master:
            self.ctx.api.relogin(ANSWER_WAIT + INIT_WAIT)
        if state == 'hung':
            for it in items:
                self.result(it, 'unverified', 'the xapi stop/edit/start on %s has not ended, so what it does to '
                                              'storage.db is not established yet: %s' % (h.name, detail))
            raise Failed('the xapi stop/edit/start on %s has not ended: %s' % (h.name, detail))
        if state == 'unverified':
            for it in items:
                self.result(it, 'unverified', 'on %s: %s' % (h.name, detail))
            raise Failed('the storage.db edit on %s is written, but not verified yet: %s' % (h.name, detail))
        if state != 'done':
            for it in items:
                self.result(it, 'failed', 'xapi stop/edit/start on %s ended %s: %s' % (h.name, state, detail))
            raise Failed('the storage.db step on %s ended %s: %s' % (h.name, state, detail))
        start = done_start
        if not start.get('complete'):
            self.init_late.append(h.name)
            self.fail('xapi on %s is answering but did not finish initialising in time' % h.name)
        for u in start.get('missing_units') or []:
            warn('%s was active on %s before xapi was stopped and is not now; it was not started again: check it'
                 % (u, h.name))
        for note in start.get('units_notes') or []:
            warn('on %s, %s' % (h.name, note))
        self.wait_live([h.uuid] if not h.is_master else None)
        if stat_.get('skipped'):
            for it in items:
                self.result(it, 'skipped', 'nothing written: %s' % stat_['skipped'])
            return
        step('  %s: xapi is back; reading storage.db again in %ds' % (h.name, VERIFY_DELAY))
        pause(VERIFY_DELAY, False)
        check = self.audit(hosts=[h.uuid], smlog=False)
        cv = check.view(m.host_by_uuid[h.uuid])
        if cv.claim is None:
            raise Failed('storage.db on %s cannot be read back: %s' % (h.name, cv.sdb_error))
        try:
            self.memory_matches(h, cv, set((it['sr'], it['vdi'], it['dp']) for it in items))
        except Failed as exc:
            for it in items:
                self.result(it, 'failed', _text(exc))
            raise
        for it in items:
            key = (it['sr'], it['vdi'], it['dp'])
            if key not in removed:
                self.result(it, 'failed', 'the action did not report it removed')
                raise Failed('the storage.db edit on %s did not remove %s' % (h.name, it['dp']))
            if any(c[1] == it['vdi'] for c in cv.claim.get(it['dp'], [])):
                self.result(it, 'failed', 'it is back in storage.db after xapi restarted')
                raise Failed('xapi on %s brought %s of %s back' % (h.name, it['dp'], it['vdi']))
            if len(cv.claim.get(it['dp'], [])) > 1:
                self.result(it, 'failed', '%s still has %d claimants' % (it['dp'], len(cv.claim[it['dp']])))
                raise Failed('%s on %s still has more than one claimant' % (it['dp'], h.name))
            self.result(it, 'fixed', 'removed; backup %s on %s' % (stat_.get('backup'), h.name))
        before = dict((dp, len(cl)) for dp, cl in (hv.claim or {}).items())
        grown = sorted(dp for dp, cl in cv.claim.items() if len(cl) > 1 and len(cl) > before.get(dp, 0))
        if grown:
            raise Failed('after xapi restarted on %s, %s has more claimants than before' % (h.name, ', '.join(grown[:4])))
        known = set(tuple(x) for x in spec['paused'])
        newly = [r for r in cv.taps or [] if r['state'] is not None and r['state'] & PAUSED
                 and (r['pid'], r['minor']) not in known]
        if newly:
            self.fail('tapdisk(s) on %s are paused after the restart: %s' % (
                h.name, ', '.join('pid %s minor %s' % (r['pid'], r['minor']) for r in newly)))

    def start_record(self, h, stat_):
        rec = stat_.get('start') or stat_.get('guardian_start')
        if rec:
            return rec
        try:
            val = self.ctx.transport.call(h, 'facts', {'want': ['ha']}, timeout=120)
        except CallError as exc:
            return {'answering': False, 'complete': False, 'detail': _text(exc)}
        xs, ck = val.get('xapi') or {}, val.get('cookies') or {}
        ready = bool(xs.get('ok') and ck.get('ok') and xapi_ready(xs['value'], ck['value']))
        self.j.rec('start_asked', host=h.uuid, ready=ready)
        return {'answering': ready, 'complete': ready}

    def keep_backup(self, h, attempt, path):
        try:
            res = self.ctx.transport.call(h, 'fetch-backup', {'run_id': self.run_id, 'host_uuid': h.uuid,
                                                             'attempt': attempt, 'name': path}, timeout=FETCH_TIMEOUT)
            data = base64.b64decode(res['data'])
            if sha256_bytes(data) != res['sha256'] or len(data) != res['size']:
                raise Failed('the copy does not match its checksum')
            local = os.path.join(self.run_dir, 'storage.db.%s.%s' % (h.uuid[:8], res['name']))
            if not os.path.exists(local):
                write_new(local, data)
            self.j.rec('backup_copy', host=h.uuid, attempt=attempt, remote=path, local=local, sha256=res['sha256'])
        except Exception as exc:
            warn('the storage.db backup on %s (%s) could not be copied here: %s' % (h.name, path, _text(exc)))

    def memory_matches(self, h, cv, removed=()):
        r = xe('host-get-sm-diagnostics', 'uuid=' + h.uuid, timeout=XE_TIMEOUT)
        if not r.ok:
            raise Failed('xapi on %s cannot be asked which datapaths it holds: %s' % (h.name, r.why()))
        try:
            mem = parse_sm_diagnostics(r.out)
        except ValueError as exc:
            raise Failed('the datapaths xapi on %s holds cannot be read: %s' % (h.name, _text(exc)))
        back = sorted(set(removed) & mem)
        if back:
            raise Failed('xapi on %s still holds %s in memory after its restart, so it did not start from the edited '
                         'file; the backup is in the run record' % (h.name, ', '.join('%s of %s' % (x[2], x[1])
                                                                                      for x in back[:4])))
        want = file_dp_set(cv.sdb['obj'])
        if want and not (want & mem):
            raise Failed('xapi on %s holds none of the %d datapath(s) in its storage.db: it may have started with '
                         'a blank storage state; the backup is in the run record' % (h.name, len(want)))
        if want != mem:
            self.j.rec('memory_differs', host=h.uuid, file_only=sorted(list(x) for x in want - mem)[:20],
                       memory_only=sorted(list(x) for x in mem - want)[:20])

    def poll_act(self, h, attempt):
        deadline = _now() + ACT_WAIT
        last = None
        errors = 0
        lone = None
        seen = {}
        waiting(u'the xapi stop/edit/start on %s' % h.name)
        while True:
            try:
                st = self.ctx.transport.call(h, 'act-status', {'run_id': self.run_id, 'host_uuid': h.uuid,
                                                                'attempt': attempt}, timeout=60)
                errors = 0
            except CallError as exc:
                errors += 1
                if errors in (1, 10):
                    warn('cannot ask %s how the action is going (%s); retrying' % (h.name, _text(exc)))
                st = None
            if st is not None:
                status = st.get('status') or {}
                state = status.get('state')
                if state != last:
                    step('  %s: %s%s' % (h.name, state, (' - ' + _text(status.get('detail'))) if status.get('detail') else ''))
                    last = state
                if state in ACT_ENDS:
                    return st
                seen = st
                alive = st.get('alive') or {}
                bs = st.get('backstop') or {}
                if bs.get('stalled') and alive.get('action'):
                    return {'status': {'state': 'hung', 'detail': 'the action on %s has made no progress for %s '
                                       '(in state %s; %s): %s' % (h.name, format_age(time.time() - (bs.get('since') or
                                                                                                  time.time())),
                                                                  bs.get('state'), bs.get('proc'),
                                                                  hung_action_text(h, st))},
                            'alive': alive, 'hung': True}
                if alive.get('action') is False and alive.get('guardian') is None:
                    lone = lone if lone is not None else _now()
                    if _now() - lone > LONE_WAIT:
                        return {'status': {'state': 'failed', 'detail': 'the action died %s, and no guardian ever '
                                                                       'recorded itself; the action never stops xapi '
                                                                       'without one' % (
                                                                           ('in state %s' % state) if state else
                                                                           'before it wrote any status')}}
                else:
                    lone = None
                if alive.get('action') is False and alive.get('guardian') is False:
                    st2 = self.ctx.transport.call(h, 'act-status', {'run_id': self.run_id, 'host_uuid': h.uuid,
                                                                     'attempt': attempt}, timeout=60)
                    if ((st2.get('status') or {}).get('state')) in ACT_ENDS:
                        return st2
                    return {'status': {'state': 'failed', 'detail': 'the action and its guardian are both gone '
                                                                   'in state %s' % state}}
            if _now() > deadline:
                still = (seen.get('alive') or {}) if seen else {}
                return {'status': {'state': 'hung' if still.get('action') or still.get('guardian') else 'failed',
                                   'detail': 'no end state after %ds; %s' % (ACT_WAIT, hung_action_text(h, seen))}}
            pause(2, False)

    def wait_live(self, uuids=None):
        deadline = _now() + LIVE_WAIT
        while True:
            try:
                snap = pool_snapshot(self.ctx.api)
                model = Model(snap)
                down = [h['name_label'] for r, h in model.hosts.items()
                        if (uuids is None or h['uuid'] in uuids) and not model.host_live(r)]
            except Exception as exc:
                down = ['(the API did not answer: %s)' % _text(exc)]
                try:
                    self.ctx.api.relogin(30)
                except Failed:
                    pass
            if not down:
                return
            if _now() > deadline:
                raise Failed('not live after %ds: %s' % (LIVE_WAIT, ', '.join(down)))
            pause(3, False)

    def name_of(self, uuid):
        try:
            return self.host(uuid).name
        except Exception:
            return uuid

    def pool_record(self):
        return list(self.ctx.api.x.pool.get_all_records().items())[0]

    def set_marker(self):
        pref, pool = self.pool_record()
        value = json.dumps({'run': self.run_id, 'host': self.ctx.my_uuid, 'hostname': socket.gethostname(),
                            'time': int(time.time()), 'commands': self.ha.commands(),
                            'ha': dict((k, self.ha.d.get(k)) for k in HA_SETTINGS + ('enabled', 'plan'))},
                           sort_keys=True)
        self.j.rec('ha_marker', value=value)
        x = self.ctx.api.x
        if HA_MARKER in (pool.get('other_config') or {}):
            x.pool.remove_from_other_config(pref, HA_MARKER)
        x.pool.add_to_other_config(pref, HA_MARKER, value)

    def clear_marker(self):
        try:
            pref, pool = self.pool_record()
            mark = ha_marker_of(pool)
            if mark is not None and mark.get('run') == self.run_id:
                self.ctx.api.x.pool.remove_from_other_config(pref, HA_MARKER)
                self.j.rec('ha_marker_cleared')
        except Exception as exc:
            warn('the pool-wide note other-config:%s, which says this run turned HA off, could not be removed (%s); '
                 'remove it with xe pool-param-remove uuid=%s param-name=other-config param-key=%s'
                 % (HA_MARKER, _text(exc), self.ha.d['pool'], HA_MARKER))

    def disable_ha(self):
        snap = pool_snapshot(self.ctx.api)
        m = Model(snap)
        bad = ha_host_problems(m, self.ha)
        if bad:
            raise Skip('HA is not touched, since it could not be turned off and on again safely: %s' % '; '.join(bad))
        now = capture_ha(m)
        keys = ('srs', 'config', 'tolerate', 'overcommit', 'stack')
        if now is None or canon([now.d[k] for k in keys]) != canon([self.ha.d[k] for k in keys]):
            raise Skip('the pool\'s HA settings changed since they were shown; the storage.db steps are skipped')
        ops = ha_operations(m.pool)
        if ops:
            raise Skip('HA is not touched: xapi is running %s on the pool' % ', '.join(ops))
        hosts = self.all_hosts_ha()
        deaf = ['%s (%s)' % (self.name_of(u), v[2]) for u, v in sorted(hosts.items()) if v[2]]
        if deaf:
            raise Skip('HA is not touched: the agent on %s does not answer' % ', '.join(deaf))
        late = [self.name_of(u) for u, v in sorted(hosts.items()) if not v[3]]
        if late:
            raise Skip('HA is not touched: xapi on %s has not finished initialising, and HA could not be enabled '
                       'again around it' % ', '.join(late))
        deadline = _now() + TASK_WAIT
        while True:
            busy = [t for t in m.pending_tasks() if not m.is_gc_task(t)]
            if not busy:
                break
            if _now() > deadline:
                raise Skip('HA is not touched: task "%s" (%s) is still pending after %ds'
                           % (busy[0]['name_label'], busy[0]['uuid'], TASK_WAIT))
            waiting(u'task "%s" to finish before HA is turned off' % busy[0]['name_label'])
            pause(2)
            m = Model(pool_snapshot(self.ctx.api))
        try:
            self.set_marker()
        except Exception as exc:
            raise Skip('HA is not touched: the pool-wide note that this run turned it off could not be written (%s)'
                       % _text(exc))
        step('Disabling HA...')
        self.ha_touched = True
        self.j.rec('ha_disable_begin')
        waiting(u'xe pool-ha-disable')
        r = xe('pool-ha-disable', timeout=HA_DISABLE_TIMEOUT)
        if not r.ok:
            warn('xe pool-ha-disable: %s' % r.why())
        pool = self.pool_record()[1]
        if pool['ha_enabled'] is not False:
            ops = ha_operations(pool)
            raise Failed('HA still reads %s after xe pool-ha-disable (%s)%s' % (
                canon(pool['ha_enabled']), r.why(), ('; xapi is still running %s, which can turn HA off later on its '
                                                     'own' % ', '.join(ops)) if ops else ''))
        deadline = _now() + XHAD_GONE_WAIT
        waiting(u'every host to disarm HA')
        while True:
            bad = self.disarmed_problems()
            ops = ha_operations(self.pool_record()[1])
            if not bad and not ops:
                break
            if _now() > deadline:
                raise Failed('HA is off in the pool but not settled after %ds: %s'
                             % (XHAD_GONE_WAIT, '; '.join(bad + ['xapi still runs %s' % ', '.join(ops)] if ops
                                                          else bad)))
            pause(2)
        self.j.rec('ha_disabled')
        step('HA is disabled, and disarmed on every host.')

    def enable_ha(self):
        if self.ha is None or self.ha_restored:
            return
        stage = 'pre'
        try:
            waiting(u'HA to be enabled again')
            late = set(self.init_late)
            bad = [u for u in self.unsettled() if self.name_of(u) not in late]
            if bad:
                return self.ha_not_back('xapi on %s is not proven up and initialised, so HA is not enabled '
                                        'automatically' % ', '.join(self.name_of(u) for u in bad), 'pre')
            self.wait_live()
            deadline = _now() + INIT_WAIT
            while True:
                notready = [self.name_of(u) for u, v in sorted(self.all_hosts_ha().items()) if not v[3]]
                if not notready:
                    break
                if _now() > deadline:
                    raise Failed('xapi is not up and initialised on %s' % ', '.join(notready))
                pause(3, False)
            for u in self.unsettled():
                self.settled[u] = True
            snap = pool_snapshot(self.ctx.api)
            m = Model(snap)
            ops = ha_operations(m.pool)
            if ops:
                raise Failed('xapi is still running %s on the pool, started before this step: HA is left as it is '
                             'until that ends%s; run recover once xe pool-param-get uuid=%s '
                             'param-name=current-operations shows nothing'
                             % (', '.join(ops), ('. xapi retries an HA disable every 30s until it reaches the HA '
                                                 'statefile or every host, so bring back the host or the statefile '
                                                 'SR it waits for') if 'ha_disable' in ops else '',
                                m.pool.get('uuid')))
            split = version_split(m)
            if split and m.pool['ha_enabled'] is not True:
                raise Failed('the hosts run different xapi or platform versions (%s), and xapi refuses to enable HA '
                             'while they do (NOT_SUPPORTED_DURING_UPGRADE)' % '; '.join(split[:4]))
            for sr_uuid in self.ha.d['srs']:
                sref = m.sr_by_uuid.get(sr_uuid)
                plugged = set(m.plugged_hosts(sref)) if sref else set()
                missing = [h['name_label'] for r, h in m.hosts.items() if r not in plugged]
                if missing:
                    raise Failed('the heartbeat SR %s is not plugged on %s' % (sr_uuid, ', '.join(missing)))
            deadline = _now() + INIT_WAIT
            while True:
                off = [h['name_label'] for h in m.hosts.values()
                       if h['uuid'] in (self.ha.d.get('enabled') or []) and h.get('enabled') is not True]
                if not off:
                    break
                if _now() > deadline:
                    raise Failed('%s was enabled before and is disabled now' % ', '.join(off))
                pause(3, False)
                m = Model(pool_snapshot(self.ctx.api))
            stage = 'enable'
            if m.pool['ha_enabled'] is not True:
                step('Re-enabling HA (heartbeat SR %s)...' % ', '.join(self.ha.d['srs']))
                self.j.rec('ha_enable_begin')
                deadline = _now() + HA_ENABLE_WINDOW
                while True:
                    r = xe(*self.ha.enable_args(), timeout=HA_ENABLE_TIMEOUT)
                    pool = self.pool_record()[1]
                    if pool['ha_enabled'] is True:
                        break
                    if _now() > deadline or upgrade_refused(r.why()):
                        raise Failed('xe pool-ha-enable: %s' % r.why())
                    step('HA did not enable yet (%s); retrying in %ds' % (r.why(), HA_ENABLE_RETRY))
                    pause(HA_ENABLE_RETRY, False)
            stage = 'params'
            for param, key, want in (('ha-host-failures-to-tolerate', 'ha_host_failures_to_tolerate',
                                      self.ha.d['tolerate']),
                                     ('ha-allow-overcommit', 'ha_allow_overcommit', self.ha.d['overcommit'])):
                pool = self.pool_record()[1]
                now = _text(pool[key]).lower()
                if now == want:
                    continue
                r = xe('pool-param-set', 'uuid=' + self.ha.d['pool'], '%s=%s' % (param, want))
                pool = self.pool_record()[1]
                if _text(pool[key]).lower() != want:
                    raise Failed('HA is enabled, but %s reads %s and setting it back to %s failed (%s)'
                                 % (param, _text(pool[key]), want, r.why()))
                step('%s is %s again.' % (param, want))
            stage = 'armed'
            deadline = _now() + REARM_WAIT
            while True:
                bad = []
                for uuid, (armed, xh, err, ready) in sorted(self.all_hosts_ha().items()):
                    if err or armed != 'true' or not xh:
                        bad.append('%s: ha.armed=%s xhad=%s%s' % (self.name_of(uuid), armed, xh,
                                                                  (' (%s)' % err) if err else ''))
                if not bad:
                    break
                if _now() > deadline:
                    raise Failed('HA reads enabled, but not every host is armed after %ds: %s'
                                 % (REARM_WAIT, '; '.join(bad)))
                pause(2, False)
            ops = ha_operations(self.pool_record()[1])
            if ops:
                raise Failed('HA reads enabled and armed, but xapi is still running %s on the pool, which can change '
                             'that: HA is not counted as back' % ', '.join(ops))
            stage = 'compare'
            block, problems, notes = self.compare_ha()
            for note in notes:
                warn(note)
            for p in problems:
                self.fail(p)
            if block:
                raise Failed('HA reads enabled and armed, but %s' % '; '.join(block))
        except Exception as exc:
            return self.ha_not_back(_text(exc), stage)
        self.ha_restored = True
        try:
            self.j.rec('ha_enabled')
        except Exception as exc:
            warn('the run record could not be written (%s)' % _text(exc))
        step('HA is enabled again, armed on every host, and its settings read back as they were.')
        self.clear_marker()

    def ha_on_now(self):
        try:
            return self.pool_record()[1]['ha_enabled'] is True
        except Exception:
            return False

    def upgrade_note(self, why):
        split = []
        try:
            split = version_split(Model(pool_snapshot(self.ctx.api)))
        except Exception:
            pass
        if not split and not upgrade_refused(why):
            return ''
        return ('xapi refuses to enable HA while the hosts run different xapi or platform versions '
                '(NOT_SUPPORTED_DURING_UPGRADE)%s: %s. ' % ((' - %s' % '; '.join(split[:4])) if split else '',
                                                            UPGRADE_REMEDY))

    def ha_not_back(self, why, stage):
        self.ha_pending = _text(why)
        self.fail('HA is not back as it was: %s' % why)
        on = self.ha_on_now()
        if stage == 'armed':
            intro, lines = 'If it does not arm, turn HA off and on again with:', \
                ['xe pool-ha-disable'] + self.ha.commands()
        elif stage == 'params':
            intro, lines = 'HA is enabled; put its settings back with:', self.ha.commands(enable=False)
        elif stage == 'compare' and on:
            intro, lines = ('HA is enabled, but not as it was. If that was not done on purpose, put it back with:',
                            ['xe pool-ha-disable'] + self.ha.commands())
        else:
            intro, lines = 'Once every host is up, put it back with:', self.ha.commands(enable=not on)
        self.fail('%s%s\n%s\nthen run: %s recover. If HA was changed on purpose, remove the pool-wide note instead '
                  '(xe pool-param-remove uuid=%s param-name=other-config param-key=%s): recover then leaves HA as it '
                  'is' % (self.upgrade_note(_text(why)), intro, u'\n'.join(u'    ' + l for l in lines), sys.argv[0],
                          self.ha.d['pool'], HA_MARKER))
        try:
            self.j.rec('ha_restore_pending', why=_text(why), stage=stage)
        except Exception as exc:
            warn('the run record could not be written (%s): run %s recover all the same' % (_text(exc), sys.argv[0]))

    def compare_ha(self):
        try:
            snap = pool_snapshot(self.ctx.api)
            now = capture_ha(Model(snap))
        except Exception as exc:
            return ['its settings could not be read back to compare with the ones from before (%s)' % _text(exc)], \
                [], []
        if now is None:
            return ['HA reads off again'], [], []
        block, problems, notes = [], [], []
        for key, label, norm in (('srs', 'heartbeat SR(s)', sorted), ('config', 'HA configuration', None),
                                 ('tolerate', 'host failures to tolerate', None), ('overcommit', 'overcommit', None),
                                 ('stack', 'cluster stack', None)):
            was, cur = self.ha.d.get(key), now.d.get(key)
            if norm is not None:
                was, cur = norm(was or []), norm(cur or [])
            if canon(was) != canon(cur):
                block.append('its %s read %s where it was %s' % (label, canon(cur), canon(was)))
        if now.d['plan'].isdigit() and self.ha.d['tolerate'].isdigit() and \
                int(now.d['plan']) < int(self.ha.d['tolerate']):
            notes.append('HA has a plan for %s host failure(s) only, where %s are to be tolerated' % (
                now.d['plan'], self.ha.d['tolerate']))
        for uuid, val in sorted(self.ha.d['vms'].items()):
            if uuid in now.d['vms'] and now.d['vms'][uuid] != val:
                problems.append('VM %s: its HA restart priority/order/start delay read %s where they were %s (this '
                                'tool does not change them)' % (uuid, now.d['vms'][uuid], val))
        return block, problems, notes

    def phase_v(self, items):
        for it in items:
            if self.halt:
                break
            checkpoint()
            self.release(it)

    def fresh_check(self, h, it, recheck=None, **kw):
        deadline = _now() + self.opts.wait
        hosts = self.sr_hosts(it['sr'], h, self.audits[-1].model if self.audits else None)
        while True:
            fresh = self.audit(hosts=hosts, **kw)
            e, why = (recheck or self.recheck)(fresh, it)
            if e is not None or not (why or '').startswith(WAIT + ':') or _now() + RETEST_EVERY > deadline:
                return fresh, e, why
            step('  %d. %s: waiting - %s' % (it['seq'], it['cls'], why))
            pause(RETEST_EVERY)

    def release(self, it):
        x = self.ctx.api.x
        h = self.host(it['host'])
        fresh, e, why = self.fresh_check(h, it)
        m = fresh.model
        vbref = m.vbd_by_uuid.get(it['vbd'])
        if vbref is None:
            return self.result(it, 'already-fixed', 'the VBD is gone')
        if e is None:
            return self.result(it, 'skipped', why)
        attached = m.vbds[vbref]['currently_attached']
        if attached:
            dead = dead_duplicates(fresh, h.uuid, it['vbd'], it['vdi'])
            if dead is None or dead:
                return self.result(it, 'skipped', 'its datapath name %s' % (
                    'cannot be checked for a dead duplicate' if dead is None else
                    'still has a dead duplicate in storage.db (VDI %s): the unplug would fail' % dead[0][1]))
        for stage in ('before', 'after') if attached else ('after',):
            moved = self.changed(fresh, h, vdis=[it['vdi']], vbds=[it['vbd']], srs=[it['sr']])
            if moved:
                return self.result(it, 'skipped', 'something changed since it was re-checked (%s); run check '
                                   'again%s' % (moved, self.inert_note(h, it) if stage == 'after' else ''))
            if stage == 'before':
                why = self.before_sm(h, it)
                if why:
                    return self.result(it, 'skipped', why)
        self.act_on(it)
        if attached:
            since = self.host_now(fresh, h)
            ok, err = self.unplug(vbref)
            if not ok:
                tail, lines = self.smlog_tail(h, it['vdi'], since)
                return self.fail_item(it, 'the unplug failed: %s%s%s%s' % (
                    err, self.unplug_hint(err, lines), self.inert_note(h, it), tail))
        try:
            att = x.VBD.get_currently_attached(vbref)
        except Exception as exc:
            return self.fail_item(it, 'reading the VBD back failed: %s' % _text(exc))
        if att is not False:
            return self.fail_item(it, 'the VBD still reads attached after the unplug')
        try:
            x.VBD.destroy(vbref)
        except Exception as exc:
            return self.fail_item(it, 'VBD.destroy failed: %s%s' % (_text(exc), destroy_hint(exc)))
        if it['vbd'] in [r['uuid'] for r in sanitize(x.VBD.get_all_records()).values()]:
            return self.fail_item(it, 'the VBD is still there after destroy')
        left = self.leftovers(h, it)
        lost = self.victim_lost(h, it)
        if lost:
            return self.fail_item(it, 'unplugged and destroyed, but %s' % lost)
        self.result(it, 'fixed', 'unplugged and destroyed' + ('; ' + left if left else ''))

    def inert_note(self, h, it):
        if not it.get('inert') or it['seq'] not in self.inert_made:
            return ''
        return ('; its stale backend node %s/%s/%s on %s was already replaced by the inert file, which keeps any later '
                'unplug or teardown safe; SM cannot activate that VDI on %s again until the file is removed (rm it '
                'once the VBD and the datapath are gone)' % (SM_BACKEND, it['sr'], it['vdi'], h.name, h.name))

    def host_now(self, fresh, h):
        hv = fresh.view(fresh.model.host_by_uuid[h.uuid])
        if hv.identity and hv.identity.get('time'):
            return hv.identity['time'] + (time.time() - fresh.t)
        return time.time()

    def smlog_tail(self, h, vdi, since):
        try:
            res = self.ctx.transport.call(h, 'smlog-tail', {'vdi': vdi, 'since': since}, timeout=120)
        except CallError as exc:
            return '; its SMlog could not be read (%s)' % _text(exc), []
        lines = res.get('lines') or []
        self.j.rec('smlog_tail', host=h.uuid, vdi=vdi, lines=lines)
        if not lines:
            return '; SMlog on %s shows nothing for it since the call started' % h.name, []
        return '; SMlog on %s:\n%s' % (h.name, u'\n'.join(u'    ' + l for l in lines[-6:])), lines

    def before_sm(self, h, it):
        if it.get('inert'):
            args = {'sr': it['sr'], 'vdi': it['vdi'], 'expect': {'rdev': it['inert']['rdev'],
                                                                 'ino': it['inert']['ino']},
                    'path_sr': it['inert']['path_sr'], 'run_id': self.run_id}
            self.act_on(it)
            res = self.ctx.transport.call(h, 'inert-node', args, timeout=180)
            self.j.rec('inert', host=h.uuid, seq=it['seq'], result=res)
            if res.get('was') and not res.get('done'):
                self.fail_item(it, 'its backend node was replaced, but does not read back as the inert file: %s'
                               % '; '.join(res.get('problems') or ['no detail']))
            if res.get('problems'):
                return ('its stale backend node was not made inert, so it was not touched: %s'
                        % '; '.join(res['problems'][:6]))
            if not res.get('done') and not res.get('already'):
                self.fail_item(it, 'the backend node did not read back as inert')
            if res.get('gone'):
                step('  /dev/sm/backend/%s/%s on %s is already gone: there was nothing to make inert'
                     % (it['sr'], it['vdi'], h.name))
                return None
            self.inert_made.add(it['seq'])
            step('  /dev/sm/backend/%s/%s on %s is inert%s' % (
                it['sr'], it['vdi'], h.name, (' (it pointed at tap minor %d, which serves %s)' % (
                    it['inert']['rdev'][1], (res.get('minor_serves') or {}).get('path')))
                if res.get('minor_serves') else ''))
            return None
        if ((self.ctx.caps.get(h.uuid) or {}).get('blktap2') or {}).get('lsof_bug') is not False:
            res = self.ctx.transport.call(h, 'mount-probe', {'timeout': 10, 'budget': 120, 'dwait': 5}, timeout=600)
            self.j.rec('mount_probe', host=h.uuid, seq=it['seq'], result=res)
            if res.get('problems'):
                return ('SM runs lsof on this deactivate, and lsof hangs on a dead mount or a process stuck in D '
                        'state: %s' % '; '.join(res['problems'][:4]))
        return None

    def victim_lost(self, h, it):
        v = it.get('victim')
        if not v:
            return None
        a = self.audit(hosts=[h.uuid], smlog=False)
        hv = a.view(a.model.host_by_uuid[h.uuid])
        if hv.taps is None:
            return 'whether tapdisk pid %s on minor %s still runs is not established: %s' % (v[0], v[1], hv.why('tapdisks'))
        rows = [r for r in hv.taps if r['pid'] == v[0] and r['minor'] == v[1]]
        if not rows:
            return 'tapdisk pid %s on minor %s (%s), which held the reused minor, is gone' % (v[0], v[1], v[2])
        if rows[0].get('path') != v[2]:
            return 'tapdisk pid %s on minor %s now serves %s, not %s' % (v[0], v[1], rows[0].get('path'), v[2])
        return None

    def leftovers(self, h, it):
        deadline = _now() + VERIFY_DELAY
        while True:
            a = self.audit(hosts=[h.uuid], smlog=False)
            m = a.model
            hv = a.view(m.host_by_uuid[h.uuid])
            notes = []
            if hv.tap_vdis.get(it['vdi']):
                notes.append('a tapdisk still serves the VDI on %s' % h.name)
            if hv.backend is not None and (it['sr'], it['vdi']) in hv.back_node:
                notes.append('its backend node is still on %s' % h.name)
            vref = m.vdi_by_uuid.get(it['vdi'])
            href = m.host_by_uuid[h.uuid]
            if vref and ('host_' + href) in m.vdis[vref]['sm_config']:
                still = any(m.vbds[r]['currently_attached'] for r in m.vdis[vref]['VBDs'] if r in m.vbds
                            and m.vms.get(m.vbds[r]['VM'], {}).get('resident_on') == href)
                if not still:
                    notes.append('its host_ marker for %s is still set' % h.name)
            if not notes or _now() > deadline:
                return '; '.join(notes) + (' (left as it is; see the final audit)' if notes else '')
            pause(5, False)

    def fail_item(self, it, why):
        self.result(it, 'failed', why)
        raise Failed('%s %d failed: %s' % (it['cls'], it['seq'], why))

    def unplug(self, vbref):
        x = self.ctx.api.x
        try:
            task = x.Async.VBD.unplug_force(vbref)
        except Exception as exc:
            return False, _text(exc)
        deadline = _now() + UNPLUG_TIMEOUT
        while True:
            try:
                status = x.task.get_status(task)
            except Exception as exc:
                return False, 'the task could not be read: %s' % _text(exc)
            if status == 'success':
                self.destroy_task(task)
                return True, None
            if status in ('failure', 'cancelled'):
                try:
                    info = x.task.get_error_info(task)
                except Exception:
                    info = [status]
                self.destroy_task(task)
                return False, ' '.join(_text(i) for i in info)[:600]
            if _now() > deadline:
                try:
                    x.task.cancel(task)
                except Exception as exc:
                    return False, ('no answer within %ds, and the task could not be cancelled (%s): whether the unplug '
                                   'still takes effect is not established' % (UNPLUG_TIMEOUT, _text(exc)))
                end = _now() + CANCEL_WAIT
                while True:
                    try:
                        status = x.task.get_status(task)
                    except Exception as exc:
                        status = 'unreadable (%s)' % _text(exc)
                        break
                    if status in ('success', 'failure', 'cancelled') or _now() > end:
                        break
                    pause(1, False)
                if status == 'success':
                    self.destroy_task(task)
                    return True, None
                return False, ('no answer within %ds; a cancel was requested and the task then read %s, so whether '
                               'the unplug still takes effect is not established' % (UNPLUG_TIMEOUT, status))
            pause(1, False)

    def destroy_task(self, task):
        try:
            self.ctx.api.x.task.destroy(task)
        except Exception:
            pass

    def unplug_hint(self, err, lines=()):
        err = _text(err)
        text = err + u'\n' + u'\n'.join(_text(l) for l in lines)
        if 'Expected 0 or 1 VDI with datapath' in text:
            return ' (a duplicate dom0 datapath that was not predicted: run check again)'
        if lsof_failed(lines) or 'lsof' in err or 'Operation not permitted' in err:
            return (' (SM\'s lsof found no process behind the blktap device of a tapdisk that is gone: leftover '
                    'blktap files that were not predicted; run check again)')
        if 'Paused key found' in text or 'Paused or host_ref key found' in text:
            return ' (the VDI carries sm-config paused, so SM refused to deactivate it: see C11)'
        if re.search(r'VDI \S+ locked|SR locked, retrying', text):
            return ' (SM found the VDI or its SR locked by another SM operation)'
        if 'Device or resource busy' in text or 'still open' in text or 'errno -16' in text:
            return ' (the device is still open: something on the host still uses it)'
        if 'Connection timed out' in text and 'tap-ctl' in text:
            return ' (tap-ctl got no answer from the tapdisk: it may be deaf, see C15)'
        if 'no answer within' in err:
            return ' (the call did not finish in time, so its state is not known: run check again)'
        return ''

    def phase_l(self, items):
        for it in items:
            if self.halt:
                break
            checkpoint()
            h = self.host(it['host'])
            fresh, e, why = self.fresh_check(h, it, recheck=self.recheck_c03)
            if e is None:
                self.result(it, 'already-fixed' if why == 'gone' else 'skipped', why if why != 'gone' else
                            'the datapath is gone')
                continue
            moved = self.changed(fresh, h, vdis=[it['vdi']], srs=[it['sr']])
            if moved:
                self.result(it, 'skipped', 'something changed since it was re-checked (%s); run check again' % moved)
                continue
            why = self.before_sm(h, it)
            if why:
                self.result(it, 'skipped', why)
                continue
            moved = self.changed(fresh, h, vdis=[it['vdi']], srs=[it['sr']])
            if moved:
                self.result(it, 'skipped', 'something changed since it was re-checked (%s); run check again%s'
                            % (moved, self.inert_note(h, it)))
                continue
            since = self.host_now(fresh, h)
            self.act_on(it)
            r = xe('host-sm-dp-destroy', 'uuid=' + h.uuid, 'dp=' + it['dp'], 'allow-leak=false',
                   timeout=DP_DESTROY_TIMEOUT)
            forgot = None
            if not r.ok:
                tail, lines = self.smlog_tail(h, it['vdi'], since)
                first = '%s%s' % (r.why(), self.unplug_hint(r.why(), lines))
                if r.timed_out:
                    self.fail_item(it, 'xe host-sm-dp-destroy did not finish within %ds, so whether SM tore it down '
                                   'is not established: %s%s' % (DP_DESTROY_TIMEOUT, first, tail))
                cv0 = self.audit(hosts=self.sr_hosts(it['sr'], h), smlog=True)
                hv0 = cv0.view(cv0.model.host_by_uuid[h.uuid])
                left, unknown = self.footprint(hv0, it['sr'], it['vdi'], strict=True)
                if left or unknown:
                    self.fail_item(it, 'SM could not tear it down (%s). xapi still records the datapath, since it was '
                                   'not told to allow a leak, so nothing was forgotten; what is left on %s: %s%s'
                                   % (first, h.name, '; '.join((left + unknown)[:6]), tail))
                moved = self.leak_recheck(cv0, it) or self.changed(cv0, h, vdis=[it['vdi']], srs=[it['sr']])
                if moved:
                    self.fail_item(it, 'SM could not tear it down (%s), and nothing of it is left on %s, but it no '
                                   'longer qualifies as it did (%s), so xapi was not told to forget it: xapi still '
                                   'records the datapath%s' % (first, h.name, moved, tail))
                r = xe('host-sm-dp-destroy', 'uuid=' + h.uuid, 'dp=' + it['dp'], 'allow-leak=true',
                       timeout=DP_DESTROY_TIMEOUT)
                if not r.ok:
                    self.fail_item(it, 'SM could not tear it down (%s), and xe host-sm-dp-destroy allow-leak=true '
                                   'failed too: %s' % (first, r.why()))
                forgot = ('SM could not tear it down (%s), but nothing of it is left on %s, so xapi was told to '
                          'forget it' % (first, h.name))
            check = self.audit(hosts=[h.uuid], smlog=False)
            cv = check.view(check.model.host_by_uuid[h.uuid])
            if cv.claim is None:
                self.fail_item(it, 'storage.db cannot be read back')
            if any(c[1] == it['vdi'] for c in cv.claim.get(it['dp'], [])):
                self.fail_item(it, 'the datapath is still in storage.db')
            left, unknown, held = self.teardown_left(h, cv, it, since, grep=forgot is None)
            if left:
                self.fail_item(it, 'xapi forgot the datapath, but SM did not tear it down: %s' % '; '.join(left))
            if unknown:
                self.fail_item(it, 'xapi forgot the datapath, but whether SM tore it down is not established: %s'
                               % '; '.join(unknown))
            if held:
                done = ('destroyed; xapi did not call SM for it, because datapath(s) %s still hold the VDI on %s'
                        % (', '.join(held), h.name))
            else:
                done = 'destroyed, and nothing of it is left on %s' % h.name
            if forgot:
                done = forgot + '; ' + done
            out = r.out.strip()
            self.result(it, 'fixed', done + ('; xe printed: %s' % out[:300] if out else ''))

    def teardown_left(self, h, cv, it, since, grep=True):
        left, unknown = [], []
        if grep:
            try:
                res = self.ctx.transport.call(h, 'xlog-grep', {'since': since, 'needle': 'because allow_leak set',
                                                               'also': 'dp:%s state' % it['dp']}, timeout=120)
                left.extend('xensource.log: %s' % l[-240:] for l in res.get('lines') or [])
                if not res.get('covered', True):
                    unknown.append('xensource.log no longer covers the time of the call, so xapi\'s allow_leak line '
                                   'cannot be ruled out')
            except CallError as exc:
                self.j.rec('xlog_grep', host=h.uuid, seq=it['seq'], error=_text(exc))
                unknown.append('xensource.log could not be read for xapi\'s allow_leak line (%s)' % _text(exc))
        sr, vdi = it['sr'], it['vdi']
        held = sorted(dp for dp, cl in cv.claim.items() if dp != it['dp'] and any(c[1] == vdi for c in cl))
        if held:
            return left, unknown, held
        l2, u2 = self.footprint(cv, sr, vdi)
        return left + l2, unknown + u2, []

    def footprint(self, cv, sr, vdi, strict=False):
        left, unknown = [], []
        if cv.taps is None or cv.backend is None or cv.phy_list is None:
            unknown.append('whether anything of it is left is not established (%s)'
                           % cv.why('tapdisks', 'backend', 'phy'))
        else:
            rows = cv.ident_rows(vdi)
            if rows:
                left.append('tapdisk pid %s still serves it' % rows[0]['pid'])
            elif strict:
                rows, why = cv.serving(cv.sr_type(sr), vdi)
                if rows is None:
                    unknown.append(why)
                elif rows:
                    left.append('tapdisk pid %s still serves it' % rows[0]['pid'])
            if (sr, vdi) in cv.back_node:
                left.append('its backend node is still there')
            if (sr, vdi) in cv.phy:
                left.append('its phy link is still there')
        if cv.sr_type(sr) in LVM_SR_TYPES:
            if cv.smrefs is None or cv.blockmap is None:
                unknown.append('whether its LV is still active is not established')
            else:
                rc = (cv.smrefs.get('lvm-' + sr) or {}).get(vdi)
                if rc is not None:
                    left.append('SM still counts an activation of its LV (refcount %s)' % rc)
                for n in lv_dm_names(sr, vdi):
                    if n in (cv.blockmap.get('dm') or {}):
                        left.append('its LV is still active (%s)' % n)
        if strict:
            m = cv.audit.model
            vref = m.vdi_by_uuid.get(vdi)
            tag = (m.vdis[vref].get('sm_config') or {}).get('host_' + cv.href) if vref else None
            if tag is not None:
                left.append('SM still marks it activated here (sm-config host_%s=%s)' % (cv.href, tag))
        if strict and cv.sr_type(sr) not in PATH_SR_TYPES:
            vols = cv.linstor_vols(sr, vdi) if cv.sr_type(sr) == 'linstor' else []
            if not vols:
                unknown.append('its volumes are not named, so whether they are still open here is not established')
            for vol in vols:
                d = (cv.audit.drbd.get(cv.uuid) or {}).get(vol)
                if not d or not d.get('ok'):
                    unknown.append('the DRBD state of %s is not established' % vol)
                elif d['value'].get('exists') is not False and d['value'].get('open') != 'no':
                    left.append('%s is still open here (%s)' % (vol, canon(d['value'].get('open'))))
        return left, unknown

    def leak_recheck(self, fresh, it):
        e = evaluate(fresh, self.opts).get(('C03', it['host'], it['sr'], it['vdi'], it['dp']))
        if e is None:
            return 'it is no longer judged a leaked guest datapath'
        if e['verdict'] != FIX:
            return '%s: %s' % (e['verdict'], e['reason'])
        if e['item']['needs']:
            return 'a tapdisk serves it for dom0 VBD(s) %s' % ', '.join(e['item']['needs'])
        pick = lambda s: [s[0], s[2], s[5] if len(s) > 5 else None]
        if canon(pick(e['sig'])) != canon(pick(it['sig'])):
            return 'its claimants or its storage-dps routing record changed'
        return None

    def recheck_c03(self, fresh, it):
        per = evaluate(fresh, self.opts)
        e = per.get(('C03', it['host'], it['sr'], it['vdi'], it['dp']))
        if e is None:
            hv = fresh.view(fresh.model.host_by_uuid[it['host']])
            if hv.claim is not None and not any(c[1] == it['vdi'] for c in hv.claim.get(it['dp'], [])):
                return None, 'gone'
            return None, 'it no longer qualifies'
        if e['verdict'] != FIX:
            return None, '%s: %s' % (e['verdict'], e['reason'])
        if e['item']['needs']:
            return None, 'a tapdisk still serves it for dom0 VBD(s) %s' % ', '.join(e['item']['needs'])
        if canon(e['sig'][:3] + e['sig'][5:]) != canon(it['sig'][:3] + it['sig'][5:]) or \
                canon(e['item'].get('inert')) != canon(it.get('inert')):
            return None, 'its state changed'
        return e, None

    def phase_f(self, items):
        x = self.ctx.api.x
        for it in items:
            if self.halt:
                break
            checkpoint()
            m0 = Model(pool_snapshot(self.ctx.api))
            vref = m0.vdi_by_uuid.get(it['vdi'])
            if vref is None or it['key'] not in m0.vdis[vref]['sm_config']:
                self.result(it, 'already-fixed', 'the key is gone')
                continue
            hosts = set(m0.hosts[r]['uuid'] for r in m0.plugged_hosts(m0.vdis[vref]['SR']))
            sm = m0.sr_master(m0.vdis[vref]['SR'])
            if sm:
                hosts.add(m0.hosts[sm]['uuid'])
            fresh = self.audit(hosts=sorted(hosts), probes=True, only_vdis=set([it['vdi']]))
            e, why = self.recheck(fresh, it)
            if e is None:
                self.result(it, 'skipped', why)
                continue
            moved = self.changed(fresh, None, vdis=[it['vdi']], srs=[it['sr']])
            if moved:
                self.result(it, 'skipped', 'something changed since it was re-checked (%s); run check again' % moved)
                continue
            plan, why = self.flag_fence_plan(fresh, it)
            if plan is None:
                self.result(it, 'skipped', why)
                continue
            fences, why = self.fence_up(it, plan)
            try:
                if why:
                    self.result(it, 'skipped', 'not removed: %s' % why)
                    continue
                why = self.flag_final(fresh, it, plan, fences)
                if why:
                    self.result(it, 'skipped', 'not removed: %s' % why)
                    continue
                self.act_on(it)
                try:
                    x.VDI.remove_from_sm_config(vref, it['key'])
                    smc = x.VDI.get_sm_config(vref)
                except Exception as exc:
                    self.fail_item(it, 'remove_from_sm_config: %s' % _text(exc))
                if it['key'] in smc:
                    self.fail_item(it, '%s is still there after remove_from_sm_config' % it['key'])
                lost = self.fence_check(fences, 0)
                if lost:
                    self.fail_item(it, '%s was removed, but %s, so that no writer of it ran meanwhile is not '
                                   'established' % (it['key'], lost))
            finally:
                self.fence_down(fences)
            if it['cls'] == 'C10' and it.get('kick'):
                self.fixed_c10_srs.add(it['sr'])
            self.result(it, 'fixed', '%s removed and verified, with %s held on %s' % (
                it['key'], 'the GC lock of its SR' if it['key'] == 'relinking' else 'its SM VDI lock',
                ', '.join(h.name for h, locks in plan)))

    def flag_fence_plan(self, fresh, it):
        m = fresh.model
        sref = m.sr_by_uuid.get(it['sr'])
        if sref is None:
            return None, 'the SR is gone'
        hrefs = set(m.plugged_hosts(sref))
        mref = m.sr_master(sref)
        if mref is not None:
            hrefs.add(mref)
        lock = ['gc', it['sr']] if it['key'] == 'relinking' else ['vdi', it['vdi']]
        plan = []
        for href in sorted(hrefs, key=lambda r: m.hosts[r]['uuid'] if r in m.hosts else r):
            if href not in m.hosts or not m.host_live(href):
                return None, ('host %s has the SR plugged but is not live, so the SM lock that keeps the writers of '
                              'the key away cannot be taken there' % m.name_host(href))
            plan.append((self.host(m.hosts[href]['uuid']), [lock]))
        if not plan:
            return None, 'no host has the SR plugged, so no SM lock can keep the writers of the key away'
        return plan, None

    def flag_final(self, fresh, it, plan, fences):
        lost = self.fence_check(fences, FENCE_MARGIN)
        if lost:
            return lost
        try:
            m = Model(pool_snapshot(self.ctx.api))
        except Exception as exc:
            return 'the pool could not be read again under the lock: %s' % _text(exc)
        vref = m.vdi_by_uuid.get(it['vdi'])
        if vref is None:
            return 'the VDI is gone'
        smc = m.vdis[vref]['sm_config']
        m0 = fresh.model
        was = (m0.vdis.get(m0.vdi_by_uuid.get(it['vdi'])) or {}).get('sm_config') or {}
        if it['key'] not in smc:
            return 'the key is gone'
        if smc[it['key']] != was.get(it['key']):
            return 'its value changed from %s to %s' % (canon(was.get(it['key'])), canon(smc[it['key']]))
        others = sorted(k for k in smc if k.startswith('host_') or (k in ('paused', 'relinking', 'activating') and
                                                                     k != it['key']))
        if others:
            return 'the VDI now carries %s' % ', '.join(others)
        att = [m.vbds[r]['uuid'] for r in m.vdis[vref]['VBDs'] if r in m.vbds and m.vbds[r]['currently_attached']]
        if att:
            return 'VBD %s of the VDI is attached now' % att[0]
        sref = m.sr_by_uuid.get(it['sr'])
        now = set(m.plugged_hosts(sref)) if sref else set()
        if sref is not None and m.sr_master(sref):
            now.add(m.sr_master(sref))
        covered = set(h.uuid for h, locks in plan)
        extra = sorted(m.hosts[r]['name_label'] for r in now if r in m.hosts and m.hosts[r]['uuid'] not in covered)
        if extra:
            return '%s now %s the SR plugged and %s not covered by the lock' % (
                ', '.join(extra), 'has' if len(extra) == 1 else 'have', 'is' if len(extra) == 1 else 'are')
        moved = self.changed(fresh, None, vdis=[it['vdi']], srs=[it['sr']])
        if moved:
            return 'something changed since it was re-checked (%s); run check again' % moved
        return None

    def sr_hosts(self, sr_uuid, h, model=None):
        m = model or Model(pool_snapshot(self.ctx.api))
        out = set([h.uuid])
        sref = m.sr_by_uuid.get(sr_uuid)
        if sref is not None:
            out |= set(m.hosts[r]['uuid'] for r in m.plugged_hosts(sref) if r in m.hosts)
            mref = m.sr_master(sref)
            if mref in m.hosts:
                out.add(m.hosts[mref]['uuid'])
        return sorted(out)

    def phase_p(self, items):
        for it in items:
            if self.halt:
                break
            checkpoint()
            h = self.host(it['host'])
            fresh = self.audit(hosts=self.sr_hosts(it['sr'], h))
            e, why = self.recheck(fresh, it)
            if e is None:
                hv = fresh.view(fresh.model.host_by_uuid[h.uuid])
                if hv.taps is not None and not any(r['pid'] == it['pid'] and r['minor'] == it['minor'] and
                                                   r['state'] is not None and r['state'] & PAUSED for r in hv.taps):
                    self.result(it, 'already-fixed', 'the tapdisk is no longer paused')
                else:
                    self.result(it, 'skipped', why)
                continue
            moved = self.changed(fresh, h, vdis=[it['vdi']], srs=[it['sr']])
            if moved:
                self.result(it, 'skipped', 'something changed since it was re-checked (%s); run check again' % moved)
                continue
            action, why = self.unpause_target(fresh, h, it)
            if action is None:
                self.result(it, 'skipped', why)
                continue
            m = fresh.model
            mref = m.sr_master(m.sr_by_uuid[it['sr']])
            if mref is None:
                self.result(it, 'skipped', 'the SR master is not known, so its GC cannot be kept away')
                continue
            gc_fences, why = self.fence_up(it, [(self.host(m.hosts[mref]['uuid']), [['gc', it['sr']]])],
                                           hold=C12_FENCE_HOLD)
            try:
                if why:
                    self.result(it, 'skipped', 'not unpaused: %s' % why)
                    continue
                why = self.fence_check(gc_fences, FENCE_MARGIN)
                moved = why or self.changed(fresh, h, vdis=[it['vdi']], srs=[it['sr']])
                if moved:
                    self.result(it, 'skipped', 'not unpaused: %s' % moved)
                    continue
                self.act_on(it)
                res = self.unpause_on(h, it, action)
                lost = self.fence_check(gc_fences, 0)
            finally:
                self.fence_down(gc_fences)
            if res.get('already'):
                self.result(it, 'already-fixed', res.get('detail') or 'the tapdisk is no longer paused')
                continue
            if res.get('problems') and not res.get('done') and res.get('plugin') is None:
                self.result(it, 'skipped', 'not unpaused: %s' % '; '.join(res['problems'][:6]))
                continue
            if not res.get('done'):
                self.fail_item(it, 'the unpause did not take: %s' % '; '.join(res.get('problems') or
                                                                           [res.get('detail') or 'no detail']))
            if lost:
                self.fail(_text('C12 %d: tapdisk pid %s was unpaused, but %s while the unpause ran'
                                % (it['seq'], it['pid'], lost)))
            deadline = _now() + VERIFY_DELAY
            while True:
                a = self.audit(hosts=[h.uuid], smlog=False)
                hv = a.view(a.model.host_by_uuid[h.uuid])
                row = [x_ for x_ in hv.taps or [] if x_['minor'] == it['minor'] and x_['pid'] == it['pid']]
                if row and row[0]['state'] is not None and not row[0]['state'] & PAUSED:
                    st = (hv.tap_stats or {}).get('%d:%d' % (row[0]['pid'], row[0]['minor'])) or {}
                    if not st.get('ok'):
                        self.fail_item(it, 'it reads %s now, but does not answer tap-ctl stats: %s'
                                       % (tap_state_text(row[0]['state']), st.get('error') or 'not asked'))
                    stuck = self.io_stuck(h, row[0]['pid'], row[0]['minor'])
                    if stuck:
                        self.fail_item(it, 'it reads %s now and answers tap-ctl stats, but its I/O does not move: %s'
                                       % (tap_state_text(row[0]['state']), stuck))
                    self.result(it, 'fixed', 'state %s now; it answers tap-ctl stats and its I/O moves'
                                % tap_state_text(row[0]['state']))
                    break
                if _now() > deadline:
                    self.fail_item(it, 'tapdisk pid %s on minor %s %s' % (
                        it['pid'], it['minor'], ('still reads %s' % tap_state_text(row[0]['state'])) if row
                        else 'is gone from tap-ctl list'))
                pause(3, False)

    def unpause_target(self, fresh, h, it):
        m = fresh.model
        hv = fresh.view(m.host_by_uuid[h.uuid])
        rows = [r for r in hv.taps or [] if r['pid'] == it['pid'] and r['minor'] == it['minor']]
        if len(rows) != 1:
            return None, 'tapdisk pid %s minor %s is not listed once on %s' % (it['pid'], it['minor'], h.name)
        node = hv.back_node.get((it['sr'], it['vdi']))
        if not node or node.get('kind') != 'block' or node.get('ino') is None:
            return None, 'the backend node of the VDI on %s is not a block node with a known inode' % h.name
        phy = hv.phy.get((it['sr'], it['vdi'])) or {}
        return {'kind': 'unpause', 'sr': it['sr'], 'vdi': it['vdi'], 'pid': it['pid'], 'minor': it['minor'],
                'path': rows[0].get('path') or '', 'node': {'rdev': list(node['rdev']), 'ino': node['ino']},
                'phy': phy.get('target')}, None

    def unpause_on(self, h, it, action):
        fences, why = self.fence_up(it, [(h, [['vdi', it['vdi']]])], action=action)
        if why:
            return {'done': False, 'problems': [why]}
        spec = fences[0][1]
        deadline = _now() + UNPAUSE_WAIT
        rep = None
        waiting(u'the unpause of tapdisk pid %s on %s' % (it['pid'], h.name))
        while True:
            try:
                rep = self.ctx.transport.call(h, 'fence-status', {'run_id': spec['run_id'], 'host_uuid': h.uuid,
                                                                  'tag': spec['tag']}, timeout=60)
            except CallError as exc:
                rep = {'error': _text(exc)}
            st = (rep.get('status') or {}) if 'error' not in rep else {}
            state = st.get('state')
            if state in ('acted', 'refused', 'failed'):
                break
            if 'error' not in rep and rep.get('alive') is False:
                break
            if _now() > deadline:
                self.j.rec('unpause_unresolved', seq=it['seq'], host=h.uuid, report=rep)
                self.fail_item(it, 'the unpause on %s did not finish within %ds (worker pid %s, state %s): whether the '
                               'tapdisk was unpaused is not established, and the worker keeps its VDI lock until it '
                               'ends; check tap-ctl list there before anything else touches this disk'
                               % (h.name, UNPAUSE_WAIT, rep.get('pid'), state or rep.get('error')))
            pause(2, False)
        self.j.rec('unpause', seq=it['seq'], host=h.uuid, report=rep)
        if state == 'acted':
            return dict(st.get('result') or {}, detail=st.get('detail'))
        if state == 'refused':
            return {'done': False, 'problems': [st.get('detail') or 'the VDI lock could not be taken']}
        if state == 'failed':
            self.fail_item(it, 'the unpause on %s failed: %s; whether the tapdisk was unpaused is not established'
                           % (h.name, st.get('detail')))
        self.fail_item(it, 'the unpause worker on %s ended without a result (state %s); whether the tapdisk was '
                       'unpaused is not established' % (h.name, state))

    def io_stuck(self, h, pid, minor):
        deadline = _now() + IO_WAIT
        first = None
        while True:
            try:
                st = self.ctx.transport.call(h, 'tap-stats', {'pid': pid, 'minor': minor}, timeout=60)
            except CallError as exc:
                return 'its tap-ctl stats could not be asked: %s' % _text(exc)
            self.j.rec('io_sample', host=h.uuid, pid=pid, minor=minor, stats=st)
            if not st.get('ok'):
                return 'tap-ctl stats: %s' % st.get('error')
            out, done, failed = io_counts(st.get('value'))
            if out is None:
                return 'its tap-ctl stats cannot be read: %s' % canon(st.get('value'))[:200]
            if first is None:
                if out == 0:
                    return None
                first = (done, failed)
            else:
                if failed > first[1]:
                    return '%d sector(s) of its I/O failed while it was watched' % (failed - first[1])
                if out == 0 or done > first[0]:
                    return None
            if _now() + IO_EVERY > deadline:
                return '%d request(s) are outstanding, and none completed in %ds' % (out, IO_WAIT)
            pause(IO_EVERY, False)

    def phase_g(self, items):
        for it in items:
            if self.halt:
                break
            checkpoint()
            h = self.host(it['host'])
            fresh = self.audit(hosts=self.sr_hosts(it['sr'], h))
            e, why = self.recheck(fresh, it)
            if e is None:
                hv = fresh.view(fresh.model.host_by_uuid[h.uuid])
                if hv.ipc is not None and not any(f['sr'] == it['sr'] and f['name'] == 'abort' for f in hv.ipc):
                    self.result(it, 'already-fixed', 'the flag is gone')
                else:
                    self.result(it, 'skipped', why)
                continue
            moved = self.changed(fresh, None, srs=[it['sr']])
            if moved:
                self.result(it, 'skipped', 'something changed since it was re-checked (%s); run check again' % moved)
                continue
            self.act_on(it)
            res = self.ctx.transport.call(h, 'unlink-abort', {'sr': it['sr'], 'expect': it['expect']}, timeout=120)
            self.j.rec('c08', host=h.uuid, result=res)
            if res.get('problems'):
                self.result(it, 'skipped', 'not removed: %s' % '; '.join(res['problems']))
                continue
            if not res.get('done') and not res.get('already'):
                self.fail_item(it, 'the flag is still there')
            self.result(it, 'fixed', 'flag removed; the GC is not started again yet', show=False)
            try:
                self.kick(it['sr'], it)
            except Interrupted:
                if it['sr'] in self.kicked:
                    self.result(it, 'fixed', 'flag removed; xe sr-scan uuid=%s was run to start the GC again, but the '
                                'run was interrupted before a GC run was seen' % it['sr'])
                else:
                    self.result(it, 'fixed', 'flag removed; the GC was not started again, because the run was '
                                'interrupted: run xe sr-scan uuid=%s once nothing else runs on the SR' % it['sr'])
                raise
        for sr in sorted(self.fixed_c10_srs):
            if self.halt or sr in self.kicked:
                continue
            self.kick(sr, None)

    def kick(self, sr, it):
        self.kick_sr(sr, it)
        self.kick_tried.add(sr)

    def kick_sr(self, sr, it):
        deadline = _now() + 300
        while True:
            m = Model(pool_snapshot(self.ctx.api))
            sref = m.sr_by_uuid.get(sr)
            if sref is None:
                note = 'SR %s is gone, so its GC was not started again' % sr
                self.fail(note)
                if it is not None:
                    self.result(it, 'fixed', 'flag removed; ' + note)
                return
            mref = m.sr_master(sref)
            near = sorted(set([m.hosts[r]['uuid'] for r in m.plugged_hosts(sref) if r in m.hosts] +
                              ([m.hosts[mref]['uuid']] if mref else [])))
            a = self.audit(hosts=near, smlog=False) if mref else None
            ob = (orphan_block(a, sr) or orphan_unknown(a, sr)) if a else None
            if ob:
                note = 'the GC on SR %s is not started again: %s' % (sr, ob)
                self.fail(note)
                if it is not None:
                    self.result(it, 'fixed', 'flag removed; ' + note)
                return
            st, why = gc_state(a, sref) if a else ('unknown', ['no SR master'])
            if st == 'idle':
                break
            if _now() > deadline:
                note = ('the GC on SR %s is %s (%s), so it was not started again: run xe sr-scan uuid=%s once it '
                        'is idle' % (sr, st, '; '.join(why), sr))
                self.fail(note)
                if it is not None:
                    self.result(it, 'fixed', 'flag removed; ' + note)
                return
            waiting(u'the GC of SR %s to be idle before it is started again' % sr)
            pause(10)
        hv = a.view(mref)
        here = time.time()
        there = hv.identity['time'] + (here - a.t) if hv.identity and hv.identity.get('time') else here
        r = xe('sr-scan', 'uuid=' + sr, timeout=SCAN_TIMEOUT)
        self.kicked[sr] = (m.hosts[mref]['uuid'], there)
        if not r.ok:
            if it is not None:
                self.fail_item(it, 'flag removed, but xe sr-scan failed: %s' % r.why())
            self.fail('xe sr-scan uuid=%s, run to start the GC of the SR again, failed: %s' % (sr, r.why()))
            return
        seen = self.gc_started(sr, m.hosts[mref]['uuid'], there)
        if seen is None:
            note = 'xe sr-scan uuid=%s returned, but no GC was seen on the SR within %ds' % (sr, KICK_WAIT)
            self.fail(note)
        else:
            note = 'xe sr-scan uuid=%s started the GC (%s)' % (sr, seen)
        if it is not None:
            self.result(it, 'fixed', 'flag removed; ' + note)
        else:
            step('  ' + note)

    def gc_started(self, sr, mu, there):
        deadline = _now() + KICK_WAIT
        while True:
            a = self.audit(hosts=[mu])
            m = a.model
            sref = m.sr_by_uuid.get(sr)
            href = m.host_by_uuid.get(mu)
            if sref is None or href is None:
                return 'the SR or its master is gone'
            st, why = gc_state(a, sref)
            if st == 'running':
                return 'running: %s' % '; '.join(why[:2])
            runs = [r for r in (a.view(href).smlog or {}).get('gc') or [] if r.get('sr') == sr and r['first'] >= there - 5]
            if runs:
                return 'a GC run since the kick %s' % ('ended %s' % runs[-1]['outcome'] if runs[-1].get('outcome')
                                                       else 'is logging')
            if _now() + 5 > deadline:
                return None
            pause(5)

    def settle(self):
        _SETTLING[0] = True
        waiting(u'xapi and HA being put back')
        for uuid, attempt in sorted(self.acts.items()):
            if self.settled.get(uuid):
                continue
            self.settled[uuid] = False
            try:
                self.settle_host(uuid, attempt)
            except Exception as exc:
                self.fail('cannot make sure xapi runs on host %s: %s' % (uuid, _text(exc)))
        if self.ha_touched and not self.ha_restored and self.ha_pending is None:
            try:
                self.ctx.api.relogin(ANSWER_WAIT)
            except Exception as exc:
                self.ha_not_back(_text(exc), 'pre')
                return
            self.enable_ha()

    def settle_host(self, uuid, attempt):
        h = self.host(uuid)
        try:
            st = self.ctx.transport.call(h, 'act-status', {'run_id': self.run_id, 'host_uuid': uuid,
                                                           'attempt': attempt}, timeout=60)
        except CallError as exc:
            self.fail('cannot ask host %s about its action: %s' % (h.name, _text(exc)))
            return
        alive = st.get('alive') or {}
        if alive.get('action') or alive.get('guardian'):
            self.fail('the action on %s did not finish: %s' % (h.name, hung_action_text(h, st)))
            return
        try:
            res = self.ctx.transport.call(h, 'xapi-ensure', {'run_id': self.run_id, 'host_uuid': uuid,
                                                             'attempt': attempt}, timeout=ENSURE_TIMEOUT)
        except CallError as exc:
            self.fail('cannot make sure xapi runs on %s: %s' % (h.name, _text(exc)))
            return
        if res.get('started'):
            step('  started xapi on %s: %s' % (h.name, res.get('detail')))
        elif res.get('ready'):
            step('  %s: %s' % (h.name, res.get('detail')))
        if res.get('ready'):
            self.settled[uuid] = True
        else:
            self.fail('xapi on %s is not up and initialised: %s' % (h.name, res.get('detail')))
        sv = res.get('storage') or 'n/a'
        try:
            self.j.rec('settle', host=uuid, attempt=attempt, ready=bool(res.get('ready')), storage=sv,
                       detail=res.get('storage_detail'))
        except EnvironmentError as exc:
            warn('the run record could not be written (%s)' % _text(exc))
        if sv not in STORAGE_OK:
            self.storage_open[uuid] = res.get('storage_detail') or sv
            self.fail('the storage.db edit on %s is not verified (%s): %s' % (h.name, sv, res.get('storage_detail')))
            return
        self.storage_open.pop(uuid, None)
        if sv == 'verified':
            for it in self.act_items.get(uuid, []):
                if (self.results.get(it['seq']) or ('',))[0] == 'unverified':
                    self.result(it, 'fixed', 'removed; xapi on %s was found holding the edited storage state when the '
                                'run settled (%s)' % (h.name, res.get('storage_detail')))


def hung_action_text(h, st):
    pids_ = (st or {}).get('pids') or {}
    alive = (st or {}).get('alive') or {}
    if alive.get('action') and pids_.get('action'):
        return ('the action, pid %d on %s, is still alive (state %s). If it is hung, kill it there with kill -9 %d: its '
                'guardian then starts xapi and records what it found. Then run %s recover'
                % (pids_['action'], h.name, ((st or {}).get('status') or {}).get('state'), pids_['action'],
                   sys.argv[0]))
    if alive.get('guardian'):
        return 'the guardian on %s still watches xapi; run %s recover once it is done' % (h.name, sys.argv[0])
    return ('neither the action nor a guardian was seen alive on %s (state %s); run %s recover'
            % (h.name, ((st or {}).get('status') or {}).get('state'), sys.argv[0]))


SM_PID_RE = re.compile(r' SM: \[(\d+)\]')


def lsof_failed(lines):
    after_lsof = {}
    for raw in lines:
        l = _text(raw)
        mm = SM_PID_RE.search(l)
        if not mm:
            continue
        if after_lsof.get(mm.group(1)) and 'FAILED in util.pread: (rc 1)' in l:
            return True
        after_lsof[mm.group(1)] = "'/usr/sbin/lsof'" in l
    return False


def destroy_hint(exc):
    text = _text(exc)
    if 'HANDLE_INVALID' in text:
        return ' (the VBD was destroyed by something else meanwhile)'
    if 'OTHER_OPERATION_IN_PROGRESS' in text:
        return ' (another operation on the VBD is in progress)'
    if 'OPERATION_NOT_ALLOWED' in text or 'VBD_NOT_UNPLUGGED' in text or 'attached' in text:
        return ' (xapi does not allow it now: the VBD may be attached again)'
    return ''


def save_audits(d, audits):
    for a in audits:
        try:
            save_json_gz(os.path.join(d, 'audit-%d.json.gz' % a.n),
                         {'t': a.t, 'snap': a.snap, 'facts': a.facts, 'errors': a.errors, 'smlog': a.smlog,
                          'probes': dict(('%s@%s' % k, v) for k, v in a.probes.items())})
        except Exception as exc:
            warn('the audit record could not be saved: %s' % _text(exc))


def save_check(audits, final, plan, keep=20):
    root = os.path.join(RUN_ROOT, 'checks')
    if not os.path.isdir(root):
        os.makedirs(root, 0o700)
    st = os.statvfs(root)
    if st.f_bavail * st.f_frsize < (100 << 20):
        raise Failed('%s has less than 100 MiB free' % root)
    d = os.path.join(root, time.strftime('%Y%m%d-%H%M%S') + '-' + hashlib.sha256(os.urandom(16)).hexdigest()[:6])
    os.makedirs(d, 0o700)
    save_audits(d, audits)
    write_new(os.path.join(d, 'findings.json'),
              json.dumps(public(final, plan), sort_keys=True, indent=1, default=_text).encode('utf-8'))
    old = sorted(n for n in _listdir(root) if RUN_ID_RE.match(n))
    for name in old[:-keep] if len(old) > keep else []:
        p = os.path.join(root, name)
        for f in _listdir(p):
            _unlink_quietly(os.path.join(p, f))
        try:
            os.rmdir(p)
        except OSError:
            pass
    return d


def execute(ctx, plan, audits, ha, final):
    arm_signals()
    run_id, run_dir = new_run_dir()
    eng = Engine(ctx, plan, audits, ha, run_id, run_dir)
    eng.j.rec('open', run_id=run_id, version=VERSION, argv=sys.argv, plan=plan,
              ha=ha.d if ha is not None else None)
    _AUDIT[0] = True
    if ha is not None:
        write_json_atomic(os.path.join(run_dir, 'ha.json'), ha.d)
    save_audits(run_dir, audits)
    say('')
    step('Run %s: the record is in %s' % (run_id, run_dir))
    _log('info', 'started: %s (python %s)' % (' '.join(sys.argv), PYTHON))
    eng.run()
    return eng


def own_source():
    path = globals().get('__file__')
    if not path or not os.path.isfile(path):
        raise Refused('run this from a file (python3 %s ...): it ships its own source to the other hosts' % PROG)
    data = read_file(path)
    try:
        compile(data, path, 'exec')
    except SyntaxError as exc:
        raise Refused('%s does not compile: %s' % (path, _text(exc)))
    return data


def take_run_lock():
    import fcntl
    fd = os.open(RUN_LOCK, os.O_RDWR | os.O_CREAT, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except (IOError, OSError):
        os.close(fd)
        raise Refused('another run of %s holds %s' % (PROG, RUN_LOCK))
    return fd


def unarmed_prompt(fn, *args):
    old = signal.signal(signal.SIGINT, signal.default_int_handler)
    try:
        return fn(*args)
    except KeyboardInterrupt:
        raise Interrupted('interrupted at the password prompt')
    finally:
        signal.signal(signal.SIGINT, old)


def read_password(prompt_needed):
    if not prompt_needed:
        return None
    import getpass
    if sys.stdin.isatty():
        try:
            return getpass.getpass('Root password for the pool hosts (only handed to ssh; Enter alone = ssh keys): ')
        except EOFError:
            return None
    line = sys.stdin.readline()
    return line.rstrip('\n') or None


def unreached(transport, hosts):
    out = []
    for h, (st, val) in parallel(lambda h: transport.call(h, 'facts', {'want': []}, timeout=60), hosts):
        if st != 'ok':
            out.append((h, _text(val)))
    return out


def get_password(transport, hosts, known=None):
    if known is not None:
        transport.set_password(known)
        return known
    live = [h for h in hosts if h.live and not h.local]
    for tries in range(3):
        known = read_password(True) or ''
        transport.set_password(known)
        bad = unreached(transport, live) if live else []
        if not bad:
            return known
        if ' was refused' in bad[0][1] and tries < 2 and sys.stdin.isatty():
            error(bad[0][1])
            continue
        for h, e in bad:
            warn('%s cannot be reached: %s' % (h.name, e))
        return known
    return known


def preflight(opts):
    if os.geteuid() != 0:
        raise Refused('run this as root')
    try:
        inv = parse_inventory(read_text(INVENTORY))
    except EnvironmentError as exc:
        raise Refused('cannot read %s (%s): is this an XCP-ng host?' % (INVENTORY, _text(exc)))
    ver = inv.get('PRODUCT_VERSION', '')
    if not re.match(r'^8\.3(\.|$)', ver):
        raise Refused('this tool is for XCP-ng 8.3; this host runs %s %s' % (inv.get('PRODUCT_BRAND', '?'), ver or '?'))
    try:
        role = read_text(POOL_CONF).strip()
    except EnvironmentError as exc:
        raise Refused('cannot read %s: %s' % (POOL_CONF, _text(exc)))
    if role != 'master':
        if role.startswith('slave:'):
            raise Refused('this host is a pool member; run this on the pool master, %s' % role[len('slave:'):])
        raise Refused('%s says "%s", where "master" was expected' % (POOL_CONF, role))
    ctx = Ctx(opts)
    ctx.inv = inv
    ctx.my_uuid = inv.get('INSTALLATION_UUID')
    try:
        ctx.api.login()
        pool = list(ctx.api.x.pool.get_all_records().values())[0]
        master_uuid = ctx.api.x.host.get_uuid(pool['master'])
    except Exception as exc:
        raise Refused('xapi on this host is not answering (%s). This tool never starts xapi before you have '
                      'confirmed anything: if an earlier run of it stopped xapi, run %s recover' % (_text(exc), sys.argv[0]))
    if master_uuid != ctx.my_uuid:
        raise Refused('xapi says the pool master is %s, but this host is %s' % (master_uuid, ctx.my_uuid))
    ctx.workdir = make_workdir()
    ctx.transport = Transport(own_source(), ctx.workdir)
    snap = pool_snapshot(ctx.api)
    model = Model(snap)
    hosts = ctx.host_objs(model)
    say(u'Pool "%s": %d host(s), master %s' % (model.pool['name_label'] or model.pool['uuid'], len(hosts),
                                               model.name_host(model.pool['master'])))
    for h in hosts:
        say(u'  %-20s %-15s %s%s%s' % (h.name, h.address, 'live' if h.live else 'NOT LIVE',
                                       ', master' if h.is_master else '', '' if h.enabled else ', disabled'))
    say(u'HA: %s' % ('on' if model.pool['ha_enabled'] is True else 'off' if model.pool['ha_enabled'] is False
                     else canon(model.pool['ha_enabled'])))
    others = [h for h in hosts if not h.local]
    if others:
        ensure_run_root()
        say(u'ssh: the other hosts are reached only with a host key already known here (%s or %s); an unknown key '
            u'is shown and has to be confirmed first, and a changed key stops the connection before the password is '
            u'sent.' % (' or '.join(user_known_hosts()), GLOBAL_KNOWN_HOSTS))
        trust_hosts(ctx.transport, others, getattr(opts, 'trust_host_keys', False))
        get_password(ctx.transport, others)
    return ctx


def settle_wait(seconds, why='only state that persists is acted on'):
    step('Waiting %ds before the second audit, so that %s...' % (seconds, why))
    pause(seconds)


def needs_second(a, opts):
    for e in evaluate(a, opts).values():
        if e['verdict'] in (FIX, WAIT) or e['cls'] in ('C11', 'C12'):
            return True
    return False


def run_audits(ctx):
    opts = ctx.opts
    step('Audit 1...')
    a1 = collect_audit(ctx, 1, first=True)
    if not needs_second(a1, opts):
        step('Audit 1 found nothing that could need fixing; no second audit.')
        return [a1]
    wait = max(0, opts.settle - (time.time() - a1.t))
    settle_wait(int(wait + 0.999))
    step('Audit 2...')
    a2 = collect_audit(ctx, 2)
    return [a1, a2]


def caps_summary(ctx):
    rows = []
    for h in sorted(ctx.hosts.values(), key=lambda h: h.name):
        c = ctx.caps.get(h.uuid)
        if c is None:
            rows.append(u'  %-20s capabilities not read' % h.name)
            continue
        b = c.get('blktap2') or {}
        rows.append(u'  %-20s lsof deactivate bug: %s; GC log formats: %s; blktap2 %s' % (
            h.name, {True: 'yes', False: 'no'}.get(b.get('lsof_bug'), 'unknown'),
            'ok' if (c.get('cleanup') or {}).get('set_fmt') and (c.get('cleanup') or {}).get('del_fmt') else 'unknown',
            (b.get('sha256') or '?')[:12]))
    return rows


def exit_for(final):
    return 1 if any(e['verdict'] != INFO for e in final) else 0


def public(final, plan):
    out = []
    for e in final:
        d = dict(e)
        d.pop('sig', None)
        d.pop('base', None)
        if d.get('item'):
            d['item'] = dict(d['item'])
            d['item'].pop('sig', None)
        out.append(d)
    return {'version': VERSION, 'findings': out, 'plan': [dict((k, v) for k, v in it.items() if k != 'sig')
                                                          for it in plan]}


def show_open(journals):
    for name, path, recs in journals:
        error('run %s did not finish (%s): %s' % (name, path, ', '.join(sorted(set(r.get('event', '?') for r in recs)))))
    error('run %s recover to finish it' % sys.argv[0])


def plan_ha(audits, plan, final):
    if not any(it['action'] == 'storage-db' for it in plan):
        return plan, None
    model = audits[-1].model
    try:
        ha = capture_ha(model)
        bad = ha_host_problems(model, ha) if ha else []
        if ha:
            for href in sorted(model.hosts):
                hv = audits[-1].view(href)
                if not xapi_ready(hv.xapi, hv.cookies):
                    bad.append('xapi on %s is not established as up and initialised, and HA could not be enabled '
                               'again around it' % hv.name)
        if bad:
            raise Refused('HA cannot be turned off and on again safely: %s' % '; '.join(bad))
    except Refused as exc:
        return drop_stage_s(plan, _text(exc), final, audits), None
    return plan, ha


def run_in_progress():
    import fcntl
    try:
        fd = os.open(RUN_LOCK, os.O_RDWR | os.O_CREAT, 0o600)
    except OSError:
        return None
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except (IOError, OSError):
        return True
    finally:
        os.close(fd)
    return False


def marker_where(mark, me):
    if me is not None and mark.get('host') == me:
        return ('It was started on this host, but its record is not here any more (%s): finish it from here with %s '
                'recover --run %s' % (os.path.join(RUN_ROOT, 'runs', _text(mark.get('run'))), sys.argv[0],
                                      mark.get('run')))
    return ('Run recover on that host (if that host is gone: %s recover --run %s on this one)'
            % (sys.argv[0], mark.get('run')))


def marker_problem(model, jr, me=None):
    mark = ha_marker_of(model.pool)
    if mark is None:
        return None, None
    who = 'run %s on host %s (%s)' % (mark.get('run'), mark.get('hostname'), mark.get('host'))
    if model.pool.get('ha_enabled') is True:
        return None, ('the pool carries other-config:%s from %s, but HA is on: the note is stale; remove it with xe '
                      'pool-param-remove uuid=%s param-name=other-config param-key=%s'
                      % (HA_MARKER, who, model.pool['uuid'], HA_MARKER))
    if mark.get('run') in [name for name, path, recs in jr]:
        return None, None
    lines = mark.get('commands') if isinstance(mark.get('commands'), list) else []
    return ('%s turned HA off and did not put it back (other-config:%s). %s, or put HA back by hand%s\nIf HA is to '
            'stay off, remove the note (recover then leaves HA off): xe pool-param-remove uuid=%s '
            'param-name=other-config param-key=%s'
            % (who, HA_MARKER, marker_where(mark, me),
               (':\n' + '\n'.join('    ' + _text(l) for l in lines)) if lines else '', model.pool['uuid'],
               HA_MARKER)), None


def cmd_check(opts):
    ctx = preflight(opts)
    jr = open_journals()
    busy = run_in_progress() if jr else False
    if jr and busy:
        warn('a fix or recover of this tool is running on this host now (it holds %s): run %s is that run, so what '
             'is found below may be its work in progress' % (RUN_LOCK, ', '.join(name for name, p, r in jr)))
    elif jr:
        show_open(jr)
    audits = run_audits(ctx)
    final, plan = classify(audits, opts)
    plan, ha = plan_ha(audits, plan, final)
    mark, stale = marker_problem(audits[-1].model, jr, ctx.my_uuid)
    if stale:
        warn(stale)
    if mark:
        error(mark)
    if not _OUT['json']:
        say(u'')
        say(u'Capabilities found in the installed code:')
        for r in caps_summary(ctx):
            say(r)
    print_findings(ctx, final, plan)
    print_plan(ctx, audits[-1], plan, ha)
    try:
        rec = save_check(audits, final, plan)
    except Exception as exc:
        rec = None
        warn('the audit record could not be saved: %s' % _text(exc))
    if _OUT['json']:
        _write(sys.stdout, json.dumps(public(final, plan), sort_keys=True, indent=1))
    else:
        say(u'')
        if rec:
            say(u'The audit record is in %s.' % rec)
        say(u'Nothing was changed in the pool.%s' % (u' To apply: %s fix' % sys.argv[0] if plan else u''))
    if (jr and not busy) or mark:
        return 3
    return exit_for(final)


def ask(question):
    stream = sys.stderr if _OUT['json'] else sys.stdout
    out = getattr(stream, 'buffer', stream)
    try:
        out.write(_text(question).encode('utf-8', 'replace'))
        out.flush()
    except (IOError, OSError, ValueError, RuntimeError):
        pass
    line = getattr(sys.stdin, 'buffer', sys.stdin).readline()
    return _text(line).strip().lower() in ('y', 'yes')


def drop_stage_s(plan, why, final, audits):
    for it in plan:
        if it['action'] == 'storage-db':
            for e in final:
                if e.get('item') is it:
                    e['verdict'], e['item'] = WAIT, None
                    e['reason'] = why
    dependencies(final, audits)
    return settle_plan(plan, final)


def cmd_fix(opts):
    if os.geteuid() != 0:
        raise Refused('run this as root')
    lockfd = take_run_lock()
    try:
        return fix_locked(opts)
    finally:
        os.close(lockfd)


def fix_locked(opts):
    if not sys.stdin.isatty():
        raise Refused('fix asks before it changes anything and needs a terminal; check gives the same report '
                      'without one')
    ctx = preflight(opts)
    jr = open_journals()
    if jr:
        show_open(jr)
        raise Refused('an earlier run did not finish', 3)
    audits = run_audits(ctx)
    final, plan = classify(audits, opts)
    say(u'')
    say(u'Capabilities found in the installed code:')
    for r in caps_summary(ctx):
        say(r)
    model = audits[-1].model
    plan, ha = plan_ha(audits, plan, final)
    mark, stale = marker_problem(model, jr, ctx.my_uuid)
    if stale:
        warn(stale)
    if mark:
        error(mark)
        raise Refused('HA was left off by an earlier run: put it back (or remove the note if HA is to stay off), '
                      'then run fix again', 3)
    print_findings(ctx, final, plan)
    print_plan(ctx, audits[-1], plan, ha)
    if not plan:
        say(u'')
        say(u'Nothing to fix. Nothing was changed.')
        return exit_for(final)
    say(u'')
    if not ask(u'Apply these %d change(s)? [y/N] ' % len(plan)):
        say(u'Nothing was changed.')
        return 1
    step('Re-checking everything before the first change...')
    audits3 = audits + [collect_audit(ctx, len(audits) + 1)]
    a3 = audits3[-1]
    final3, plan3 = classify(audits3, opts)
    plan3, ha2 = plan_ha(audits3, plan3, final3)
    if any(it['action'] == 'storage-db' for it in plan3) and not same_ha(ha, ha2):
        plan3 = drop_stage_s(plan3, 'the pool\'s HA settings changed since they were shown', final3, audits3)
        warn('the pool\'s HA settings changed since they were shown: the storage.db steps, and what depends on '
             'them, are dropped; run fix again for them')
    keys3 = set(item_key(i) for i in plan3)
    shown = set(item_key(i) for i in plan)
    run_ = [i for i in plan if item_key(i) in keys3]
    dropped = [i for i in plan if item_key(i) not in keys3]
    new = [i for i in plan3 if item_key(i) not in shown]
    if new:
        say(u'')
        say(u'Not applied - these qualify now but were not shown before:')
        for it in new:
            say(u'   - %s' % describe_item(a3.model, it))
    if dropped:
        say(u'')
        say(u'No longer applicable, so not applied:')
        why = dict((item_key(e['item']), e) for e in final if e.get('item'))
        for it in dropped:
            say(u'   %3d. %s' % (it['seq'], describe_item(a3.model, it)))
            e3 = [e for e in final3 if e['key'] == (why.get(item_key(it)) or {}).get('key')]
            if e3:
                for line in wrap('now %s: %s' % (e3[0]['verdict'], e3[0]['reason']), 88):
                    say(u'          %s' % line)
        if not run_:
            say(u'Nothing is left to apply. Nothing was changed.')
            return 1
        if not ask(u'Apply the remaining %d change(s)? [y/N] ' % len(run_)):
            say(u'Nothing was changed.')
            return 1
    eng = execute(ctx, run_, audits3, ha2 if any(i['action'] == 'storage-db' for i in run_) else None, final3)
    return finish(ctx, eng)


def finish(ctx, eng):
    step('Final audit...')
    _SETTLING[0] = False
    _PENDING[0] = None
    if eng.ha_pending or eng.unsettled() or eng.storage_open:
        _STOP_NOTE[0] = (u'the final audit is skipped; xapi, HA or a storage.db edit is not settled, which is left to '
                         u'recover')
    else:
        _STOP_NOTE[0] = u'the final audit is skipped; xapi and HA are already settled'
    waiting(u'the final audit')
    last = None
    try:
        b1 = collect_audit(ctx, 101, first=False)
        checkpoint()
        if needs_second(b1, ctx.opts):
            settle_wait(ctx.opts.settle, 'the report below shows only state that persists')
            last = collect_audit(ctx, 102)
            final, plan = classify([b1, last], ctx.opts)
        else:
            last = b1
            final, plan = classify([b1], ctx.opts)
    except Interrupted as exc:
        eng.fail('the final audit was skipped (%s): run check to see the state now' % _text(exc))
        last, final, plan = None, [], []
    except Exception as exc:
        eng.fail('the final audit could not be taken: %s' % _text(exc))
        last, final, plan = None, [], []
    waiting(None)
    say(u'')
    say(u'== Result ==')
    counts = collections.Counter(s for s, _ in eng.results.values())
    shown = last if last is not None else eng.audits[-1]
    for it in eng.plan:
        status, detail = eng.results.get(it['seq'], ('not-attempted', ''))
        say(u'  %3d. %-14s %s' % (it['seq'], status, describe_item(shown.model, it)))
        if detail:
            for line in wrap(detail, 90):
                say(u'                      %s' % line)
    for sr, (where, t) in sorted(eng.kicked.items()):
        runs, unread = [], []
        for href in (last.model.hosts if last is not None else {}):
            hv = last.view(href)
            if hv.uuid != where:
                continue
            if hv.smlog is None:
                unread.append(hv.name)
            for r in (hv.smlog or {}).get('gc') or []:
                if r.get('sr') == sr and r['first'] >= t - 5:
                    runs.append(r)
        if runs:
            seen = ', '.join('%s' % (r.get('outcome') or 'running') for r in runs)
            ended = [r for r in runs if r.get('outcome')]
            if ended and all(r.get('aborted') for r in ended):
                eng.fail('the GC on SR %s still ends Aborted after it was started again: check SMlog on the SR '
                         'master' % sr)
        elif last is None:
            seen = 'not established (no final audit)'
        elif unread:
            seen = 'not established (SMlog not read on %s)' % ', '.join(sorted(unread))
        else:
            seen = 'no run seen yet (check again later)'
        say(u'  GC on SR %s since the kick: %s' % (sr, seen))
        before = eng.audits[-1].model if eng.audits else None
        sref0 = before.sr_by_uuid.get(sr) if before is not None else None
        for u in sorted(v['uuid'] for v in (before.vdis.values() if sref0 else [])
                        if v['SR'] == sref0 and 'relinking' in v['sm_config']):
            vref = last.model.vdi_by_uuid.get(u) if last is not None else None
            if last is None:
                state = 'not established (no final audit)'
            elif vref is None:
                state = 'gone'
            elif 'relinking' in last.model.vdis[vref]['sm_config']:
                state = 'still carries relinking: the GC has not relinked it yet'
            else:
                state = 'relinking removed'
            say(u'    VDI %s: %s' % (u, state))
    for sr in sorted(set(eng.fixed_c10_srs) - set(eng.kicked) - eng.kick_tried):
        eng.fail('the GC of SR %s was not started again after its activating key(s) were removed, because the run '
                 'stopped first: run xe sr-scan uuid=%s once nothing else runs on the SR' % (sr, sr))
    if last is not None:
        print_findings(ctx, final, plan, u'Final audit')
    open_ = bool(eng.ha_pending) or bool(eng.unsettled()) or bool(eng.storage_open)
    if open_:
        for u, why in sorted(eng.storage_open.items()):
            error('the storage.db edit on %s is not verified: %s. Its backup is kept in the run record; recover '
                  'checks it again' % (eng.name_of(u), why))
        error('the run is left open: run %s recover' % sys.argv[0])
        try:
            eng.j.rec('left-open', problems=eng.problems)
        except EnvironmentError as exc:
            error('the run record %s cannot be written: %s' % (eng.j.path, _text(exc)))
        return 3
    try:
        eng.j.rec('closed', results=dict((str(k), v) for k, v in eng.results.items()), problems=eng.problems)
    except EnvironmentError as exc:
        error('the run record %s cannot be closed (%s), so the run stays open: run %s recover once it can be '
              'written' % (eng.j.path, _text(exc), sys.argv[0]))
        return 3
    try:
        prune_runs()
    except Exception:
        pass
    if eng.problems:
        return 1
    if counts.get('fixed', 0) + counts.get('already-fixed', 0) == len(eng.plan) and exit_for(final) == 0:
        return 0
    return 1


def cmd_recover(opts):
    if os.geteuid() != 0:
        raise Refused('run this as root')
    lockfd = take_run_lock()
    try:
        return recover_locked(opts)
    finally:
        os.close(lockfd)


def report_act(hu, hname, st, copies, ha_lines=None, sv=None):
    if st is None:
        say(u'  %s: how its action ended is not known' % hname)
        return
    say(u'  %s: its action ended %s%s' % (hname, st.get('state'), (': %s' % st.get('detail')) if st.get('detail') else ''))
    if sv is not None and sv[0] not in STORAGE_OK:
        say(u'    what xapi holds now: %s (%s)' % (sv[0], sv[1]))
    if st.get('state') == 'done' and (sv is None or sv[0] in STORAGE_OK):
        return
    backup = st.get('backup')
    if not backup:
        say(u'    nothing was written there, so there is nothing to restore')
        return
    copy = copies.get((hu, backup))
    say(u'    the storage.db it replaced is kept on that host as %s%s' % (
        backup, (u', and on this host as %s' % copy) if copy else u''))
    say(u'    If xapi there lost datapaths it should hold (compare xe host-get-sm-diagnostics uuid=%s with that '
        u'file), put it back on that host with:' % hu)
    if ha_lines is not None:
        say(u'      (HA is on, or is put back by this recover: xapi must not be stopped while HA is armed, so turn HA '
            u'off first, on the pool master:)')
        say(u'        xe pool-ha-disable')
    for line in ('systemctl stop xapi', 'cp %s %s' % (_quote(backup), STORAGE_DB), 'systemctl start xapi'):
        say(u'        %s' % line)
    if ha_lines is not None:
        say(u'      (then, once xapi answers there again, put HA back on the pool master:)')
        for line in ha_lines:
            say(u'        %s' % line)
    say(u'    Do not do that if xapi holds the datapaths: it would bring back the removed ones and drop any made since.')


def ensure_xapi(transport, host, args, wait=None):
    deadline = _now() + (ACT_WAIT if wait is None else wait)
    shown = None
    while True:
        res = transport.call(host, 'xapi-ensure', args, timeout=ENSURE_TIMEOUT)
        if not res.get('busy'):
            return res
        if _now() + 10 > deadline:
            if res.get('busy') == 'action' and res.get('pid'):
                res['detail'] = ('%s. If it is hung, kill it on %s with kill -9 %d: its guardian then starts xapi and '
                                 'records what it found. Then run %s recover again'
                                 % (res.get('detail'), host.name, res['pid'], sys.argv[0]))
            return res
        if res.get('detail') != shown:
            shown = res.get('detail')
            say(u'  %s: %s; waiting for it to finish (up to %s)' % (host.name, shown, format_age(deadline - _now())))
        waiting(u'%s on %s to finish' % (shown, host.name))
        pause(10)


def pool_marker_here():
    try:
        s = local_session()
    except Exception as exc:
        return None, 'the local xapi cannot be asked (%s)' % _text(exc)
    try:
        pool = list(s.xenapi.pool.get_all_records().values())[0]
        return ha_marker_of(sanitize(pool)), None
    except Exception as exc:
        return None, 'the pool cannot be read (%s)' % _text(exc)
    finally:
        try:
            s.xenapi.session.logout()
        except Exception:
            pass


def adopt_run(run_id):
    if not RUN_ID_RE.match(run_id or ''):
        raise Refused('%s is not a run id' % run_id, 2)
    d = os.path.join(RUN_ROOT, 'runs', run_id)
    path = os.path.join(d, 'journal.jsonl')
    if os.path.exists(path):
        return None
    mark, why = pool_marker_here()
    if why:
        raise Refused('run %s has no record on this host, and %s' % (run_id, why))
    if mark is None or mark.get('run') != run_id:
        raise Refused('run %s has no record on this host, and the pool carries no note other-config:%s from it, so '
                      'there is nothing this host can finish for it' % (run_id, HA_MARKER))
    if not os.path.isdir(d):
        os.makedirs(d, 0o700)
    j = Journal(d)
    ha = mark.get('ha') if isinstance(mark.get('ha'), dict) else None
    j.rec('open', run_id=run_id, version=VERSION, argv=sys.argv, plan=[], ha=dict(ha, vms={}) if ha else None,
          adopted_from=mark.get('host'))
    j.rec('ha_marker', value=canon(mark))
    j.rec('adopted', note='the run record stayed on %s (%s); this host finishes it from the pool-wide note and the '
                          'action records on the hosts' % (mark.get('hostname'), mark.get('host')))
    return run_id, path, read_journal(path)


def recover_locked(opts):
    jr = open_journals()
    if getattr(opts, 'run', None):
        jr = [x for x in jr if x[0] == opts.run]
        if not jr:
            got = adopt_run(opts.run)
            if got is None:
                say(u'Run %s is closed: nothing to recover.' % opts.run)
                return 0
            jr = [got]
    if not jr:
        mark, why = pool_marker_here()
        if mark is not None and mark.get('run'):
            try:
                me = parse_inventory(read_text(INVENTORY)).get('INSTALLATION_UUID')
            except EnvironmentError:
                me = None
            if me is not None and mark.get('host') == me:
                error('no unfinished run is recorded on this host, but the pool carries other-config:%s from run %s, '
                      'which this host started and which turned HA off; its record is not here any more (%s). '
                      'Finish the run from here with: %s recover --run %s'
                      % (HA_MARKER, mark.get('run'), os.path.join(RUN_ROOT, 'runs', _text(mark.get('run'))),
                         sys.argv[0], mark.get('run')))
            else:
                error('no unfinished run is recorded on this host, but the pool carries other-config:%s from run %s, '
                      'started on %s (%s), which turned HA off. If that host is gone, finish the run from here with: '
                      '%s recover --run %s' % (HA_MARKER, mark.get('run'), mark.get('hostname'), mark.get('host'),
                                               sys.argv[0], mark.get('run')))
            return 3
        say(u'No unfinished run: nothing to recover.%s' % ((u' (%s, so a run left open elsewhere could not be '
                                                            u'looked for.)' % why) if why else u''))
        return 0
    _AUDIT[0] = True
    _STOP_NOTE[0] = u'recover stops before its next step and exits 3; run it again to finish'
    arm_signals()
    inv = parse_inventory(read_text(INVENTORY))
    try:
        role = read_text(POOL_CONF).strip()
    except EnvironmentError:
        role = None
    if role != 'master':
        say(u'This host is not the pool master now (%s says %s): the runs it started are finished from here all the '
            u'same, through the master.' % (POOL_CONF, canon(role)))
    worst = 0
    state = {'pw': None}
    for name, path, recs in jr:
        state['adopted'] = any(r.get('event') == 'adopted' for r in recs)
        say(u'Run %s:' % name)
        try:
            worst = max(worst, recover_run(opts, inv, name, path, recs, state))
        except Interrupted as exc:
            error('  %s: recover stopped here; run it again to finish' % _text(exc))
            return 3
        except Exception as exc:
            error('  the run could not be finished: %s: %s; run recover again' % (exc.__class__.__name__, _text(exc)))
            worst = 3
    return worst


def ha_not_ours(recs, name, pool):
    if not any(r.get('event') == 'ha_marker' for r in recs):
        return None
    mark = ha_marker_of(pool)
    if mark is None:
        return 'gone'
    if 'raw' not in mark and mark.get('run') != name:
        return 'replaced by run %s' % mark.get('run')
    return None


def recover_run(opts, inv, name, path, recs, state):
    run_dir = os.path.dirname(path)
    unreadable = [r for r in recs if r.get('event') == 'unreadable']
    acts = collections.OrderedDict()
    ha_d = None
    for r in recs:
        if r.get('event') == 'act_begin':
            acts[(r['host'], r['attempt'])] = None
        elif r.get('event') == 'act_end':
            acts[(r['host'], r['attempt'])] = r.get('state')
        elif r.get('event') == 'open':
            ha_d = r.get('ha')
    if ha_d is None:
        try:
            ha_d = read_json(os.path.join(run_dir, 'ha.json'))
        except (EnvironmentError, ValueError):
            ha_d = None
    ha_off = any(r.get('event') == 'ha_disable_begin' for r in recs)
    ha_on = any(r.get('event') == 'ha_enabled' for r in recs)
    if unreadable:
        warn('%d line(s) of the run record %s cannot be read: what they recorded is not known, so the hosts and the '
             'pool are asked for what this run left' % (len(unreadable), path))
    ctx = Ctx(opts)
    ctx.inv = inv
    ctx.my_uuid = inv.get('INSTALLATION_UUID')
    ctx.workdir = make_workdir()
    ctx.transport = Transport(own_source(), ctx.workdir)
    local = Host(None, {'uuid': ctx.my_uuid, 'name_label': 'this host', 'hostname': socket.gethostname(),
                        'address': '127.0.0.1', 'enabled': True}, True, True)
    settled, storage = {}, {}

    def discover(h):
        try:
            got = ctx.transport.call(h, 'act-list', {'run_id': name}, timeout=60)
        except CallError as exc:
            error('  %s: the action records of this run cannot be listed there: %s' % (h.name, _text(exc)))
            return False
        for odd in got.get('odd') or []:
            warn('%s: %s' % (h.name, odd))
        for a in got.get('acts') or []:
            key = (a['host_uuid'], a['attempt'])
            if key not in acts:
                acts[key] = None
                say(u'  %s: found the action %s/%d, which the run record does not list'
                    % (h.name, a['host_uuid'], a['attempt']))
        return True

    def ensure(h, hu, at):
        checkpoint()
        try:
            res = ensure_xapi(ctx.transport, h, {'run_id': name, 'host_uuid': hu, 'attempt': at})
        except CallError as exc:
            error('  %s: %s' % (h.name, _text(exc)))
            settled[hu] = False
            storage[(hu, at)] = ('unverified', _text(exc))
            return
        say(u'  %s: %s' % (h.name, res.get('detail')))
        settled[hu] = settled.get(hu, True) and bool(res.get('ready'))
        storage[(hu, at)] = (res.get('storage') or 'n/a', res.get('storage_detail'))
        if (res.get('storage') or 'n/a') not in STORAGE_OK:
            error('  %s: its storage.db edit is not verified (%s): %s' % (h.name, res.get('storage'),
                                                                          res.get('storage_detail')))
    listed = discover(local)
    for (hu, at) in [k for k in acts if k[0] == ctx.my_uuid]:
        ensure(local, hu, at)
    try:
        ctx.api.relogin(ANSWER_WAIT)
    except Failed as exc:
        error('  xapi on this host does not answer: %s; run recover again once it does' % _text(exc))
        return 3
    model = Model(pool_snapshot(ctx.api))
    hosts = ctx.host_objs(model)
    mark = ha_marker_of(model.pool)
    ours = mark is not None and (mark.get('run') == name or ('raw' in mark and ha_off and not ha_on))
    if ha_d is None and ours and isinstance(mark.get('ha'), dict):
        ha_d = dict(mark['ha'], vms={})
    look = bool(unreadable) or bool(state.get('adopted'))
    others = [k for k in acts if k[0] != ctx.my_uuid]
    if (others or look or ours or (ha_off and not ha_on)) and len(hosts) > 1:
        unarmed_prompt(trust_hosts, ctx.transport, hosts, getattr(opts, 'trust_host_keys', False))
        state['pw'] = unarmed_prompt(get_password, ctx.transport, hosts, state['pw'])
    if look:
        for h in hosts:
            if h.uuid == ctx.my_uuid:
                continue
            if not h.live:
                error('  %s is not live, so whether this run left an action there is not established' % h.name)
                listed = False
                continue
            listed = discover(h) and listed
        others = [k for k in acts if k[0] != ctx.my_uuid]
    for hu, at in others:
        hs = [h for h in hosts if h.uuid == hu]
        if not hs:
            error('  host %s is not in the pool' % hu)
            settled[hu] = False
            storage[(hu, at)] = ('unverified', 'the host is not in the pool')
            continue
        ensure(hs[0], hu, at)
    copies = dict(((r.get('host'), r.get('remote')), r.get('local')) for r in recs
                  if r.get('event') == 'backup_copy')
    ha_lines = None
    if ha_d and (ours or (ha_off and not ha_on)):
        ha_lines = HaCapture(ha_d).commands()
    elif model.pool.get('ha_enabled') is True:
        try:
            ha_lines = capture_ha(model).commands()
        except Refused:
            ha_lines = ['(the HA settings to put back could not be read: see xe pool-param-list)']
    for (hu, at), ended in acts.items():
        if ended in SETTLED_STATES and storage.get((hu, at), ('n/a',))[0] in STORAGE_OK:
            continue
        target = local if hu == ctx.my_uuid else ([h for h in hosts if h.uuid == hu] or [None])[0]
        st = None
        if target is not None:
            try:
                st = (ctx.transport.call(target, 'act-status', {'run_id': name, 'host_uuid': hu, 'attempt': at},
                                         timeout=60).get('status') or {})
            except CallError as exc:
                error('  %s: the action record cannot be read: %s' % (hu, _text(exc)))
        report_act(hu, (target.name if target is not None else hu), st, copies, ha_lines, storage.get((hu, at)))
    bad = sorted(u for u, ok in settled.items() if not ok)
    if bad:
        error('  xapi is not proven up and initialised on %s: run recover again once it is' % ', '.join(bad))
        return 3
    checkpoint()
    model = Model(pool_snapshot(ctx.api))
    mark = ha_marker_of(model.pool)
    ours = mark is not None and (mark.get('run') == name or ('raw' in mark and ha_off and not ha_on))
    not_ours = ha_not_ours(recs, name, model.pool) if ha_off and not ha_on and not ours else None
    if ours:
        if ha_d is None:
            error('  the pool-wide note other-config:%s says this run turned HA off, but the HA settings to put back '
                  'are not known here. Put HA back by hand:' % HA_MARKER)
            for line in mark.get('commands') if isinstance(mark.get('commands'), list) else []:
                say(u'    %s' % _text(line))
            return 3
        eng = Engine(ctx, [], [], HaCapture(ha_d), name, run_dir)
        eng.ha_touched = True
        eng.settled = dict((u, ok) for u, ok in settled.items())
        _SETTLING[0] = True
        try:
            eng.enable_ha()
        finally:
            _SETTLING[0] = False
        if not eng.ha_restored:
            return 3
    elif not_ours:
        on = model.pool.get('ha_enabled') is True
        say(u'  HA is left as it is (%s): the pool-wide note other-config:%s that this run set is %s, which says HA '
            u'is not this run\'s to put back.%s' % ('on' if on else 'off', HA_MARKER, not_ours,
                                                     '' if on or not ha_d else ' To turn it on again, on the pool '
                                                                               'master:'))
        if not on and ha_d:
            for line in HaCapture(ha_d).commands():
                say(u'    %s' % line)
    unsure = [(hu, at, v) for (hu, at), v in sorted(storage.items()) if v[0] not in STORAGE_OK]
    if unsure or unreadable or (look and not listed):
        why = []
        if unsure:
            why.append('%d storage.db edit(s) are not verified (%s)' % (len(unsure), '; '.join(
                '%s/%d: %s' % (hu, at, v[0]) for hu, at, v in unsure[:4])))
        if unreadable:
            why.append('%d line(s) of its record cannot be read' % len(unreadable))
        if look and not listed:
            why.append('not every host could be asked for the actions this run left')
        if getattr(opts, 'close', None) != name:
            error('  the run is left open: %s. When this has been checked and is accepted as it is, close it with: '
                  '%s recover --close %s' % ('; '.join(why), sys.argv[0], name))
            return 3
        warn('closing run %s as asked (--close), although %s' % (name, '; '.join(why)))
    Journal(run_dir).rec('closed', recovered=True, accepted=getattr(opts, 'close', None) == name,
                         unsure=[[hu, at, v[0]] for hu, at, v in unsure], unreadable=len(unreadable))
    say(u'  closed.')
    return 0


def minutes(lo, hi):
    def conv(text):
        try:
            v = float(text)
        except ValueError:
            raise argparse.ArgumentTypeError('%s is not a number' % text)
        if not math.isfinite(v):
            raise argparse.ArgumentTypeError('%s is not a finite number' % text)
        if v < lo:
            raise argparse.ArgumentTypeError('%s is below the floor of %s' % (text, lo))
        if v > hi:
            raise argparse.ArgumentTypeError('%s is above the ceiling of %s' % (text, hi))
        return v
    return conv


def build_parser():
    p = argparse.ArgumentParser(
        prog=os.path.basename(sys.argv[0]) if sys.argv and sys.argv[0] else PROG,
        description='Find stale storage coordination state in an XCP-ng 8.3 pool (dead dom0 datapaths, stale '
                    'dom0 VBDs, leaked datapaths, stale relinking/activating keys, GC abort flags, backend nodes '
                    'pointing at another disk\'s tapdisk, paused tapdisks), prove each piece stale, and repair what '
                    'is proven. Run it as root on the pool master. check changes nothing in the pool; fix shows '
                    'every change and asks first.',
        epilog='On a pool with more than one host it asks for the pool\'s root password, to reach the other hosts '
               'over ssh; it is kept in memory and handed to ssh through the environment only. A host is reached '
               'only with an ssh host key already known here (%s/known_hosts, ~/.ssh/known_hosts or %s); an unknown '
               'one is shown and must be confirmed. Run records, and the backup of every storage.db it edits, are '
               'kept in %s. Exit status: 0 nothing found, or everything fixed and verified; 1 findings remain or '
               'something was skipped; 2 usage error; 3 a run was left open (xapi, HA or a storage.db edit not '
               'confirmed): run recover.' % (RUN_ROOT, GLOBAL_KNOWN_HOSTS, RUN_ROOT))
    p.add_argument('--version', action='version', version='%(prog)s ' + VERSION + ' (python ' + PYTHON + ')')
    sub = p.add_subparsers(dest='cmd', metavar='COMMAND')
    sub.required = True
    for name, func, text in (('check', cmd_check, 'audit the pool twice, settle apart, and report; changes nothing in the pool'),
                             ('fix', cmd_fix, 'audit, show the changes, ask, then apply them (HA handled)')):
        c = sub.add_parser(name, help=text, description=text)
        c.add_argument('--settle', type=minutes(SETTLE_FLOOR, 3600), default=SETTLE_FLOOR, metavar='SECONDS',
                       help='seconds between the two audits (default and floor %d, at most 3600)' % SETTLE_FLOOR)
        c.add_argument('--include', default='', metavar='NAMES',
                       help='opt-in classes, comma separated: c05 (release dom0 VBDs on a VM\'s live disk when '
                            'the VM is halted or runs elsewhere), c12 (unpause a tapdisk paused by a process '
                            'that is gone)')
        c.add_argument('--min-vbd-age', type=minutes(15, 10080), default=60, metavar='MINUTES',
                       help='a dom0 VBD with an attach on its host must be this old (default 60, floor 15, at most '
                            '10080)')
        c.add_argument('--relink-min-age', type=minutes(1, 720), default=6, metavar='HOURS',
                       help='a relinking key proven stale from SMlog must be this old (default 6, floor 1, at most '
                            '720)')
        c.add_argument('--stuck-export-age', type=minutes(1, 720), default=24, metavar='HOURS',
                       help='an export older than this is reported as stuck (default 24, floor 1, at most 720)')
        if name == 'check':
            c.add_argument('--json', action='store_true', help='print the findings and the plan as JSON')
        else:
            c.add_argument('--wait', type=minutes(0, 1440), default=15, metavar='MINUTES',
                           help='how long to wait, re-checking every minute, for a host to become safe to stop '
                                'before HA is touched, and for each change that has to wait before it is skipped '
                                '(default 15, at most 1440)')
            c.add_argument('--ha-off-wait', type=minutes(0, 1440), default=2, metavar='MINUTES',
                           help='how long to wait per host once HA is off (default 2, at most --wait)')
        c.add_argument('--trust-host-keys', action='store_true', help=TRUST_HELP)
        c.set_defaults(func=func)
    r = sub.add_parser('recover', help='finish a run that was interrupted: start xapi where it stopped it, put '
                                       'HA back', description='finish a run that was interrupted')
    r.add_argument('--run', metavar='RUN_ID', type=run_id_arg,
                   help='finish this run only; if its record is not on this host (the host that started it is gone), '
                        'it is finished from the pool-wide note it left and the action records on the hosts')
    r.add_argument('--close', metavar='RUN_ID', type=run_id_arg,
                   help='close this run although a storage.db edit could not be verified or part of its record cannot '
                        'be read, once you have checked it; xapi must still be up and HA settled')
    r.add_argument('--trust-host-keys', action='store_true', help=TRUST_HELP)
    r.set_defaults(func=cmd_recover)
    return p


TRUST_HELP = ('record the ssh host keys of pool members this tool has not reached before without asking (their '
              'fingerprints are still printed). Without it, an unknown key is shown and must be confirmed, or the '
              'host is not reached')


def run_id_arg(text):
    if not RUN_ID_RE.match(text or ''):
        raise argparse.ArgumentTypeError('%s is not a run id (like 20261007-101500-a1b2c3)' % text)
    return text


def normalise(opts):
    inc = set(x.strip().lower() for x in (getattr(opts, 'include', '') or '').split(',') if x.strip())
    bad = inc - set(['c05', 'c12'])
    if bad:
        raise Usage('unknown --include name(s): %s (known: c05, c12)' % ', '.join(sorted(bad)))
    opts.include = inc
    if hasattr(opts, 'min_vbd_age'):
        opts.min_vbd_age = opts.min_vbd_age * 60
        opts.relink_min_age = opts.relink_min_age * 3600
        opts.stuck_export_age = opts.stuck_export_age * 3600
    if hasattr(opts, 'wait'):
        opts.wait = opts.wait * 60
        opts.ha_off_wait = min(opts.ha_off_wait * 60, opts.wait)
    return opts


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if argv[:1] == ['--ssf-act'] and len(argv) == 2:
        return act_main(argv[1])
    if argv[:1] == ['--ssf-guard'] and len(argv) == 2:
        return guard_main(argv[1])
    if argv[:1] == ['--ssf-fence'] and len(argv) == 2:
        return fence_main(argv[1])
    parser = build_parser()
    if not argv:
        parser.print_help()
        return 2
    try:
        opts = normalise(parser.parse_args(argv))
    except Usage as exc:
        _write(sys.stderr, u'%s: %s' % (PROG, _text(exc)))
        return 2
    _OUT['json'] = bool(getattr(opts, 'json', False))
    say(u'%s %s (python %s)' % (PROG, VERSION, PYTHON))
    try:
        return opts.func(opts)
    except Refused as exc:
        error(_text(exc))
        if not _AUDIT[0]:
            say(u'Nothing was changed.')
        return exc.code
    except (Failed, CallError, EnvironmentError) as exc:
        error(_text(exc))
        if not _AUDIT[0]:
            say(u'Nothing was changed.')
        return 1
    except (KeyboardInterrupt, Interrupted):
        if _AUDIT[0]:
            error('interrupted. Run %s recover to finish what this run started.' % sys.argv[0])
            return 3
        error('interrupted. Nothing was changed.')
        return 1


if __name__ == '__main__':
    sys.exit(main())
elif __name__ == 'ssf_agent':
    sys.exit(agent_entry(SSF_REQUEST, SSF_SOURCE))
