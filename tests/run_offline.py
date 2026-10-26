"""Run all synthetic tests with a disposable HOME and IPv4/IPv6 disabled.

Requires system GnuPG and, for full Fedora evidence tests, system RPM bindings.
No installation, real package inventory, Hermes profile or network is required.
"""
import os
from pathlib import Path
import socket
import sys
import tempfile
import unittest


def main():
    source = Path(__file__).resolve().parent.parent
    sys.dont_write_bytecode = True
    sys.path.insert(0, str(source))
    sys.path.insert(0, str(source/'tests'))
    def offline(event, args):
        if event == 'socket.__new__' and args[1] in (socket.AF_INET, socket.AF_INET6):
            raise AssertionError('offline tests forbid network sockets')
        if event == 'socket.getaddrinfo':
            raise AssertionError('offline tests forbid DNS')
    sys.addaudithook(offline)
    with tempfile.TemporaryDirectory(prefix='SYNTHETIC-test-home-') as home:
        os.environ['HOME'] = home
        # GnuPG --no-autostart still requires its existing private home directory.
        (Path(home)/'.gnupg').mkdir(mode=0o700)
        for key in list(os.environ):
            if key.startswith('SOFTWARE_WATCHER_'):
                del os.environ[key]
        os.environ.pop('GNUPGHOME', None)
        os.environ['TMPDIR'] = home
        tempfile.tempdir = home
        try:
            suite = unittest.defaultTestLoader.discover(str(source/'tests'))
            result = unittest.TextTestRunner(verbosity=2).run(suite)
        finally:
            helper = sys.modules.get('synthetic_encryption')
            if helper is not None:
                import atexit
                atexit.unregister(helper.cleanup)
                helper.cleanup()
    return 0 if result.wasSuccessful() else 1


if __name__ == '__main__':
    raise SystemExit(main())
