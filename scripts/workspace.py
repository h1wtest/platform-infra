#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Resolve moving references explicitly; obtain audited, exact Git source revisions.

No source scripts, hooks, smudge filters, submodules, or build commands are run.
Local development inputs require explicit --local NAME=/absolute/repository.
"""
from __future__ import annotations

from contextlib import contextmanager
import ctypes
import argparse
import json
import hashlib
import os
from pathlib import Path
import re
import secrets
import shutil
import subprocess
import sys
from urllib.parse import urlsplit

OWNERS = (
    'platform-infra', 'platform-contracts', 'identity-service',
    'user-notification-service', 'frontend', 'catalog-service',
    'billing-service', 'subscription-service', 'referral-service',
)
SHA = re.compile(r'[0-9a-f]{40}\Z')
REMOTE_PATH = re.compile(r'/[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})/[A-Za-z0-9_][A-Za-z0-9_.-]*\Z')
BLOCKED_DIRECTORIES = frozenset({
    '.git', '.local', '.generic-local', '.venv', 'venv', 'node_modules', 'target', 'build', 'dist',
    '__pycache__', '.pytest_cache', '.mypy_cache', '.ruff_cache', 'coverage',
    'backups', 'acceptance-artifacts', 'secrets',
})


class WorkspaceError(ValueError):
    """An unsafe or unavailable source, manifest, or destination."""


def checked_path(raw: str | Path, *, exists: bool = False) -> Path:
    path = Path(raw).expanduser()
    if '..' in path.parts:
        raise WorkspaceError('path traversal is not allowed')
    path = path.absolute()
    for part in (path, *path.parents):
        if part.is_symlink():
            raise WorkspaceError('symlink paths are not allowed')
    if exists and not path.exists():
        raise WorkspaceError('required path does not exist')
    return path


@contextmanager
def bound_parent(raw: str | Path):
    """Walk without following links; keep writes bound to the opened parent."""
    if not sys.platform.startswith('linux'):
        raise WorkspaceError('safe workspace publication requires Linux/WSL renameat2 support')
    path = checked_path(raw)
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    descriptor = os.open('/', flags)
    try:
        for part in path.parent.parts[1:]:
            following = os.open(part, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = following
        try:
            os.stat(path.name, dir_fd=descriptor, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise WorkspaceError('destination is occupied; choose a new path (even empty directories are refused)')
        yield descriptor, path.name
    finally:
        os.close(descriptor)


def atomic_publish(parent: int, staging: str, destination: str) -> None:
    """Publish one complete sibling, atomically, without replacing any leaf."""
    library = ctypes.CDLL(None, use_errno=True)
    try:
        rename = library.renameat2
    except AttributeError as error:
        raise WorkspaceError('renameat2 unavailable; refusing non-atomic publication') from error
    rename.argtypes = (ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint)
    rename.restype = ctypes.c_int
    if rename(parent, os.fsencode(staging), parent, os.fsencode(destination), 1):
        code = ctypes.get_errno()
        raise OSError(code, 'atomic no-replace publication failed')
    os.fsync(parent)


def create_staging(parent: int) -> tuple[str, Path]:
    name = '.workspace-' + secrets.token_hex(16)
    os.mkdir(name, mode=0o700, dir_fd=parent)
    # Git subprocesses can reach our retained descriptor through this process's
    # proc entry; no operation reopens the original mutable parent pathname.
    return name, Path(f'/proc/{os.getpid()}/fd/{parent}') / name


def unique_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise WorkspaceError('duplicate JSON key in manifest')
        value[key] = item
    return value


def validate_url(value) -> None:
    if not isinstance(value, str):
        raise WorkspaceError('source URL must be an HTTPS GitHub repository URL')
    try:
        url = urlsplit(value)
    except ValueError as error:
        raise WorkspaceError('invalid source URL') from error
    if (url.scheme != 'https' or url.netloc != 'github.com' or url.query or url.fragment
            or not REMOTE_PATH.fullmatch(url.path) or any(part in ('.', '..') for part in url.path.split('/'))
            or any(ord(char) < 33 for char in value)):
        raise WorkspaceError('source URL must be https://github.com/OWNER/REPO without credentials, port, query, or fragment')


def valid_revision(value) -> bool:
    return isinstance(value, str) and SHA.fullmatch(value) is not None and value != '0' * 40


def load_manifest(path: Path, *, resolving: bool) -> dict:
    path = checked_path(path, exists=True)
    try:
        document = json.loads(path.read_text(encoding='utf-8'), object_pairs_hook=unique_object)
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise WorkspaceError('cannot read valid UTF-8 JSON manifest') from error
    if (not isinstance(document, dict) or set(document) != {'version', 'sources'}
            or type(document['version']) is not int or document['version'] != 1
            or not isinstance(document['sources'], list)):
        raise WorkspaceError('manifest must contain version 1 and a sources array')
    names = set()
    for entry in document['sources']:
        if not isinstance(entry, dict) or not {'name', 'url', 'revision'} <= entry.keys():
            raise WorkspaceError('every source requires name, url, and revision')
        if not set(entry) <= {'name', 'url', 'revision', 'ref', 'local', 'local_path'}:
            raise WorkspaceError('unknown source manifest field')
        name = entry['name']
        if not isinstance(name, str) or name not in OWNERS or name in names:
            raise WorkspaceError('source names must be unique known owner directories')
        names.add(name)
        local = entry.get('local', False)
        if type(local) is not bool:
            raise WorkspaceError('source local flag must be boolean')
        if entry['url'] is None:
            if not local:
                raise WorkspaceError(f'{name}: unpublished source must be explicitly marked local')
        else:
            validate_url(entry['url'])
        if 'local_path' in entry:
            if not local or not isinstance(entry['local_path'], str):
                raise WorkspaceError('local_path is identity metadata for explicit local inputs only')
        revision = entry['revision']
        if revision is not None and not valid_revision(revision):
            raise WorkspaceError(f'{name}: revision must be a nonzero lowercase 40-character commit SHA')
        if not resolving and revision is None:
            raise WorkspaceError(f'{name}: unresolved source; run resolve explicitly before checkout')
        if 'ref' in entry and entry['ref'] != 'main':
            raise WorkspaceError('only the explicit moving reference main is supported')
    missing = set(OWNERS) - names
    if missing:
        raise WorkspaceError('manifest missing owners: ' + ', '.join(sorted(missing)))
    return document


def git(*args: str, cwd: Path | None = None, local: bool = False) -> bytes:
    # An owner-supplied Git config must not turn a source read into execution.
    environment = {key: value for key, value in os.environ.items() if not key.startswith('GIT_')}
    environment.update(GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL=os.devnull,
                       GIT_TERMINAL_PROMPT='0', GIT_ATTR_NOSYSTEM='1', GIT_NO_REPLACE_OBJECTS='1')
    command = [
        'git', '-c', 'core.hooksPath=' + os.devnull, '-c', 'core.fsmonitor=false',
        '-c', 'core.attributesFile=' + os.devnull, '-c', 'http.followRedirects=false',
        '-c', 'credential.helper=', '-c', 'credential.interactive=false', '-c', 'core.askPass=',
        '-c', 'protocol.allow=never', '-c', 'protocol.https.allow=always',
        '-c', 'protocol.file.allow=' + ('always' if local else 'never'),
        '-c', 'fetch.fsckObjects=true', '-c', 'transfer.fsckObjects=true',
        *map(str, args),
    ]
    try:
        result = subprocess.run(command, cwd=cwd, env=environment, stdin=subprocess.DEVNULL,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=180, check=False)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise WorkspaceError('Git unavailable or source operation timed out') from error
    if result.returncode:
        # Git diagnostics may contain credential helpers' output or private source paths.
        raise WorkspaceError('Git source operation failed; check repository access and exact commit availability')
    return result.stdout


def local_overrides(arguments: list[str]) -> dict[str, Path]:
    overrides = {}
    for argument in arguments:
        name, separator, raw = argument.partition('=')
        if not separator or name not in OWNERS or name in overrides or not raw:
            raise WorkspaceError('--local requires one unique known NAME=/absolute/repository per owner')
        if not Path(raw).is_absolute():
            raise WorkspaceError('local source paths must be absolute')
        overrides[name] = checked_path(raw, exists=True)
    return overrides


def inspect_local(path: Path) -> str:
    if not path.is_dir():
        raise WorkspaceError('local source must be a Git repository root directory')
    checked_path(path / '.git', exists=True)
    root = git('rev-parse', '--show-toplevel', cwd=path, local=True).decode().strip()
    if Path(root) != path:
        raise WorkspaceError('local source must be the Git repository root, not a nested directory')
    # Compare raw tracked blobs instead of git status: status may invoke a
    # repository-configured clean/process filter. No source filter is executable.
    head = {}
    for record in git('ls-tree', '-rz', '--full-tree', 'HEAD', cwd=path, local=True).split(b'\0'):
        if record:
            metadata, filename = record.split(b'\t', 1)
            mode, _kind, object_id = metadata.split(b' ')
            head[filename] = (mode, object_id)
    index = {}
    for record in git('ls-files', '--stage', '-z', cwd=path, local=True).split(b'\0'):
        if record:
            metadata, filename = record.split(b'\t', 1)
            mode, object_id, stage = metadata.split(b' ')
            if stage != b'0':
                raise WorkspaceError('dirty local source has unresolved index entries')
            index[filename] = (mode, object_id)
    if head != index or git('ls-files', '--others', '--exclude-standard', '-z', cwd=path, local=True):
        raise WorkspaceError('dirty local source; commit tracked and nonignored source changes before pinning')
    for filename, (mode, object_id) in index.items():
        try:
            tracked = checked_path(path / filename.decode('utf-8'), exists=True)
            if not tracked.is_file() or mode not in (b'100644', b'100755'):
                raise WorkspaceError('local source contains symlinks, submodules, or unsupported files')
            if os.name != 'nt' and bool(tracked.stat().st_mode & 0o111) != (mode == b'100755'):
                raise WorkspaceError('dirty local source; tracked executable mode changed')
            content = tracked.read_bytes()
        except (OSError, UnicodeError) as error:
            raise WorkspaceError('cannot read tracked local source file safely') from error
        digest = hashlib.sha1(b'blob ' + str(len(content)).encode() + b'\0' + content).hexdigest().encode()
        if digest != object_id:
            raise WorkspaceError('dirty local source; tracked content differs from committed revision')
    revision = git('rev-parse', '--verify', 'HEAD', cwd=path, local=True).decode().strip()
    if not valid_revision(revision):
        raise WorkspaceError('local HEAD is not a supported SHA-1 commit')
    return revision


def safe_tree(repo: Path, revision: str) -> None:
    if git('cat-file', '-t', revision, cwd=repo, local=True).strip() != b'commit':
        raise WorkspaceError('selected revision is not a commit')
    for record in git('ls-tree', '-rz', '--full-tree', revision, cwd=repo, local=True).split(b'\0'):
        if not record:
            continue
        metadata, raw_path = record.split(b'\t', 1)
        mode, kind, _object = metadata.split(b' ')
        if mode not in (b'100644', b'100755') or kind != b'blob':
            raise WorkspaceError('source tree contains a symlink, submodule, or unsupported file mode')
        try:
            path = raw_path.decode('utf-8')
        except UnicodeError as error:
            raise WorkspaceError('source paths must be valid UTF-8') from error
        parts = path.split('/')
        if (any(part in ('', '.', '..') for part in parts) or '\\' in path or ':' in path
                or any(ord(char) < 32 for char in path)
                or any(part.casefold() in BLOCKED_DIRECTORIES for part in parts)):
            raise WorkspaceError('source tree contains unsafe paths or tracked private/build artifacts')
        filename = parts[-1].casefold()
        if ((filename == '.env' or filename.startswith('.env.'))
                and filename not in ('.env.example', '.env.sample', '.env.template')):
            raise WorkspaceError('source tree contains tracked owner environment secrets')
        if (filename.endswith(('.key', '.p12', '.pfx')) or filename in ('id_rsa', 'id_ed25519', 'secrets.json')
                or filename.startswith('acceptance-result')):
            raise WorkspaceError('source tree contains tracked private credentials or acceptance artifacts')


def selected_sources(document: dict, overrides: dict[str, Path], *, resolving: bool) -> dict:
    selected = []
    # Validate every source before any destination/output file can be created.
    for entry in document['sources']:
        name = entry['name']
        source = dict(entry)
        if name in overrides:
            path = overrides[name]
            head = inspect_local(path)
            revision = head if resolving else source['revision']
            safe_tree(path, revision)
            source.update(local=True, local_path=str(path), revision=revision)
        elif source.get('local', False):
            raise WorkspaceError(f'{name}: unpublished/local source requires explicit --local {name}=/absolute/repository; local_path metadata is never auto-used')
        elif resolving:
            # This is the only moving-reference read. Never called by checkout.
            rows = git('ls-remote', '--exit-code', source['url'], 'refs/heads/main').decode().splitlines()
            if len(rows) != 1:
                raise WorkspaceError(f'{name}: main did not resolve to one published commit')
            revision, reference = rows[0].split('\t', 1)
            if reference != 'refs/heads/main' or not valid_revision(revision):
                raise WorkspaceError(f'{name}: remote returned an invalid main commit')
            source['revision'] = revision
        source.pop('ref', None)
        selected.append(source)
    return {'version': 1, 'sources': selected}


def write_new_json(path: Path, value: dict) -> None:
    with path.open('x', encoding='utf-8', newline='\n') as handle:
        json.dump(value, handle, indent=2, ensure_ascii=False)
        handle.write('\n')
        handle.flush()
        os.fsync(handle.fileno())


def resolve(manifest: Path, output: Path, overrides: dict[str, Path]) -> None:
    with bound_parent(output) as (parent, name):
        document = load_manifest(manifest, resolving=True)
        selected = selected_sources(document, overrides, resolving=True)
        staging = '.workspace-' + secrets.token_hex(16)
        descriptor = os.open(staging, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                             0o600, dir_fd=parent)
        published = False
        try:
            with os.fdopen(descriptor, 'w', encoding='utf-8', newline='\n') as handle:
                json.dump(selected, handle, indent=2, ensure_ascii=False)
                handle.write('\n')
                handle.flush()
                os.fsync(handle.fileno())
            atomic_publish(parent, staging, name)
            published = True
        finally:
            if not published:
                try:
                    os.unlink(staging, dir_fd=parent)
                except FileNotFoundError:
                    pass


def checkout(manifest: Path, destination: Path, overrides: dict[str, Path]) -> None:
    with bound_parent(destination) as (parent, name):
        document = load_manifest(manifest, resolving=False)
        selected = selected_sources(document, overrides, resolving=False)
        staging_name, staging = create_staging(parent)
        published = False
        try:
            for source in selected['sources']:
                target = staging / source['name']
                git('init', '--quiet', '--template=', str(target))
                local = source['name'] in overrides
                location = str(overrides[source['name']]) if local else source['url']
                git('fetch', '--quiet', '--no-tags', '--depth=1', '--', location, source['revision'], cwd=target, local=local)
                safe_tree(target, source['revision'])
                git('checkout', '--quiet', '--detach', source['revision'], cwd=target)
                actual = git('rev-parse', 'HEAD', cwd=target).decode().strip()
                if actual != source['revision']:
                    raise WorkspaceError('checked-out revision differs from pinned source')
                if source['url'] is not None:
                    git('remote', 'add', 'origin', source['url'], cwd=target)
                if local:
                    git('config', 'workspace.sourcePath', location, cwd=target)
            write_new_json(staging / 'workspace.sources.json', selected)
            atomic_publish(parent, staging_name, name)
            published = True
        finally:
            if not published:
                try:
                    shutil.rmtree(staging_name, dir_fd=parent)
                except FileNotFoundError:
                    pass


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    for command in ('resolve', 'checkout'):
        child = commands.add_parser(command)
        child.add_argument('--manifest', type=Path, default=Path(__file__).resolve().parents[1] / 'workspace.sources.json')
        child.add_argument('--local', action='append', default=[], metavar='NAME=/absolute/repository')
        if command == 'resolve':
            child.add_argument('--output', required=True, type=Path)
        else:
            child.add_argument('--destination', required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        overrides = local_overrides(args.local)
        if args.command == 'resolve':
            resolve(args.manifest, args.output, overrides)
            print('Resolved source revisions; review the pinned manifest before checkout.')
        else:
            checkout(args.manifest, args.destination, overrides)
            print('Checked out exact source revisions; this does not build or prove application readiness.')
    except (WorkspaceError, OSError) as error:
        print(f'workspace: {error}', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
