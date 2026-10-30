"""Preflight for private official-channel state; not an OS sandbox."""
import os
import stat

def validate_state(state):
    # Refuse accidental use of a linked, shared or foreign-owned state tree.
    # This is a preflight, not a substitute for an isolated service account:
    # SQLite opens paths later and a writable parent can still race the check.
    state = state.absolute()
    if state.resolve() != state:
        raise ValueError('State path must not traverse symlinks')
    info = state.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
        raise ValueError('State directory must be owned by the operator and mode 0700')
    for base in ('official.sqlite', 'access.sqlite'):
        for suffix in ('', '-wal', '-shm', '-journal'):
            path = state / (base + suffix)
            try:info = path.lstat()
            except FileNotFoundError:
                if suffix:continue
                raise
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o600:
                raise ValueError('State databases and existing sidecars must be private owned regular files with one link')
    return state

