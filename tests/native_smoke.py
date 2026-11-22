import codecs
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import urllib.parse

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from vaccum_actions import cleanup, uninstall


def command(arguments, **kwargs):
    result = subprocess.run(arguments, capture_output=True, text=True, timeout=60, **kwargs)
    if result.returncode:
        raise AssertionError((arguments, result.returncode, result.stdout, result.stderr))
    return result


def approve(plan):
    return plan['confirmation_phrase']


def trash_smoke(base):
    home = base / 'home'
    data = home / '.local/share'
    data.mkdir(parents=True)
    root = home / 'selected'
    root.mkdir()
    first = root / 'one.tmp'
    first.write_bytes(b'recover-file')
    folder = root / 'folder'
    folder.mkdir()
    (folder / 'child').write_bytes(b'recover-child')
    environment = dict(os.environ)
    os.environ.update(HOME=str(home), XDG_DATA_HOME=str(data))
    for key in ('DBUS_SESSION_BUS_ADDRESS', 'XDG_RUNTIME_DIR'):
        os.environ.pop(key, None)
    try:
        for answer in (None, 'wrong', True):
            report = cleanup([root], [first], lambda plan: answer)
            assert report['status'] == 'cancelled' and first.read_bytes() == b'recover-file', report
        def stale(plan):
            first.write_bytes(b'changed')
            return approve(plan)
        report = cleanup([root], [first], stale)
        assert report['items'][0]['status'] == 'changed' and first.read_bytes() == b'changed', report
        report = cleanup([root], [first, folder], approve)
        assert report['complete'] and all(item['status'] == 'trashed' for item in report['items']), report
        assert not first.exists() and not folder.exists()
        infos = list((data / 'Trash/info').glob('*.trashinfo'))
        assert len(infos) == 2
        uri_supported = True
        for info in infos:
            original = next(line[5:] for line in info.read_text().splitlines() if line.startswith('Path='))
            destination = Path(urllib.parse.unquote(original))
            trashed = data / 'Trash/files' / info.name[:-10]
            uri = 'trash:///' + urllib.parse.quote(trashed.name)
            restored = subprocess.run(['/usr/bin/gio', 'trash', '--restore', uri], capture_output=True, text=True, timeout=15)
            if restored.returncode:
                uri_supported = False
                assert trashed.exists() and not destination.exists()
                command(['/usr/bin/gio', 'move', '--', str(trashed), str(destination)])
                info.unlink()
            assert destination.exists()
        assert first.read_bytes() == b'changed' and (folder / 'child').read_bytes() == b'recover-child'
        print('PASS native Trash, rejected confirmations/stale target, and content recovery; restore_URI_supported=' + str(uri_supported))
    finally:
        os.environ.clear()
        os.environ.update(environment)


def package_child(rootfs):
    mapping = Path('/proc/self/uid_map').read_text().split()
    assert os.geteuid() == 0 and len(mapping) == 3 and mapping[0] == '0' and mapping[2] == '1'
    assert rootfs.name == 'rootfs' and rootfs.parent.name.startswith('vaccum-native-smoke-')
    for encoding in ('ascii', 'utf-8'):
        codecs.lookup(encoding)
    command(['/usr/bin/mount', '--make-rprivate', '/'])
    command(['/usr/bin/mount', '-t', 'proc', 'proc', str(rootfs / 'proc')])
    command(['/usr/bin/mount', '--bind', '/dev/null', str(rootfs / 'dev/null')])
    for name in ('dpkg', 'dpkg-query', 'dpkg-deb', 'tar'):
        executable = str(rootfs / 'usr/bin' / name)
        command(['/usr/bin/mount', '--bind', executable, executable])
        command(['/usr/bin/mount', '-o', 'remount,bind,ro', executable])
    os.chroot(rootfs)
    os.chdir('/')
    assert os.stat('/').st_uid == os.stat('/usr/bin/dpkg').st_uid == 0
    native = ['/usr/bin/dpkg', '--root=/target', '--log=/target/var/log/dpkg.log']
    command(native + ['--install', '/vaccum-qa-fixture.deb', '/vaccum-qa-dependent.deb', '/vaccum-qa-protected.deb'])
    payload = Path('/target/usr/share/vaccum-qa-fixture/data')
    assert payload.read_bytes() == b'disposable'
    protected = uninstall(['vaccum-qa-protected:all'], approve, root='/target')
    assert not protected['complete'] and protected['plan'] is None, protected
    dependency = uninstall(['vaccum-qa-fixture:all'], approve, root='/target')
    assert not dependency['complete'] and dependency['plan'] is None and payload.exists(), dependency
    for answer in (None, 'wrong'):
        preview = uninstall(['vaccum-qa-dependent:all'], lambda plan: answer, root='/target')
        assert preview['status'] == 'cancelled', preview
    removed = uninstall(['vaccum-qa-dependent:all'], approve, root='/target')
    assert removed['complete'], removed
    removed = uninstall(['vaccum-qa-fixture:all'], approve, root='/target')
    assert removed['complete'] and removed['items'][0]['status'] == 'removed' and not payload.exists(), removed
    print('PASS native dpkg fixture install/query/remove, protection/dependency refusal and cancelled preview; private chroot/root/database/log only')


def package_smoke(base):
    rootfs = base / 'rootfs'
    for relative in ('usr/bin', 'usr/lib', 'usr/share/dpkg', 'proc', 'dev', 'target/var/lib/dpkg', 'target/var/log', 'tmp'):
        (rootfs / relative).mkdir(parents=True, exist_ok=True)
    for name, target in (('bin', 'usr/bin'), ('lib', 'usr/lib'), ('lib64', 'usr/lib64')):
        (rootfs / name).symlink_to(target)
    (rootfs / 'usr/lib64').mkdir()
    (rootfs / 'dev/null').touch()
    (rootfs / 'target/var/lib/dpkg/status').touch()
    shutil.copytree('/usr/share/dpkg', rootfs / 'usr/share/dpkg', dirs_exist_ok=True)
    for source in ('/usr/bin/dpkg', '/usr/bin/dpkg-query', '/usr/bin/dpkg-deb', '/usr/bin/dpkg-split', '/usr/bin/tar', '/usr/bin/sh', '/usr/bin/rm', '/usr/bin/diff', '/usr/sbin/ldconfig', '/usr/sbin/start-stop-daemon'):
        destination = rootfs / source.lstrip('/')
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, destination)
        dependency = subprocess.run(['/usr/bin/ldd', source], capture_output=True, text=True, timeout=15)
        assert dependency.returncode == 0 or 'not a dynamic executable' in dependency.stderr, dependency.stderr
        libraries = dependency.stdout
        for library in set(re.findall(r'(/[\w.+/\-]+)', libraries)):
            destination = rootfs / library.lstrip('/')
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(library, destination)
    for name, extra in (('vaccum-qa-fixture', ''), ('vaccum-qa-dependent', 'Depends: vaccum-qa-fixture\n'), ('vaccum-qa-protected', 'Protected: yes\n')):
        source = base / name
        (source / 'DEBIAN').mkdir(parents=True)
        (source / 'usr/share' / name).mkdir(parents=True)
        (source / 'usr/share' / name / 'data').write_bytes(b'disposable')
        (source / 'DEBIAN/control').write_text('Package: ' + name + '\nVersion: 1.0\nArchitecture: all\nMaintainer: QA <qa@example.invalid>\n' + extra + 'Description: Disposable no-script QA fixture\n')
        command(['/usr/bin/dpkg-deb', '--root-owner-group', '-Znone', '--build', str(source), str(rootfs / (name + '.deb'))])
    result = command(['/usr/bin/unshare', '-Urnmpf', sys.executable, '-B', str(Path(__file__).resolve()), '--package-child', str(rootfs)])
    print(result.stdout, end='')


if __name__ == '__main__':
    if len(sys.argv) == 3 and sys.argv[1] == '--package-child':
        package_child(Path(sys.argv[2]))
    else:
        assert os.geteuid() != 0, 'Run this disposable smoke check as a normal user.'
        with tempfile.TemporaryDirectory(prefix='vaccum-native-smoke-') as temporary:
            fixture = Path(temporary)
            trash_smoke(fixture)
            package_smoke(fixture)
        print('PASS all native fixtures cleaned; no host package actions requested')
