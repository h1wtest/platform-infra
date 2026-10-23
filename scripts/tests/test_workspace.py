# SPDX-License-Identifier: MIT
"""Real Git/filesystem regressions; no network, source-text assertions, or mocks."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / 'workspace.py'
OWNERS = ('platform-infra', 'platform-contracts', 'identity-service',
          'user-notification-service', 'frontend', 'catalog-service',
          'billing-service', 'subscription-service', 'referral-service')


class WorkspaceBehavior(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.source = self.root / 'source'
        self.source.mkdir()
        self.git('init', '-q', str(self.source), cwd=self.root)
        self.git('config', 'user.name', 'Workspace Fixture')
        self.git('config', 'user.email', 'fixture@example.invalid')
        (self.source / '.gitignore').write_text('.env\n.local/\n.generic-local/\nnode_modules/\nbuild/\n', encoding='utf-8')
        (self.source / 'source.txt').write_text('first revision\n', encoding='utf-8')
        self.git('add', '.')
        self.git('commit', '-qm', 'first fixture revision')
        self.first = self.git('rev-parse', 'HEAD').strip()
        self.manifest = self.root / 'sources.json'
        self.destination = self.root / 'fresh'
        self.write_manifest()

    def git(self, *args, cwd=None):
        result = subprocess.run(['git', '-c', 'core.hooksPath=/dev/null', *args],
                                cwd=cwd or self.source, text=True,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
        return result.stdout

    def write_manifest(self, entries=None):
        if entries is None:
            entries = [{'name': name, 'url': None, 'revision': self.first, 'local': True}
                       for name in OWNERS]
        self.manifest.write_text(json.dumps({'version': 1, 'sources': entries}), encoding='utf-8')

    def command(self, command='checkout', *, local=True, destination=None, extra=()):
        args = [sys.executable, str(SCRIPT), command, '--manifest', str(self.manifest)]
        args += ['--destination', str(destination or self.destination)] if command == 'checkout' else []
        if local:
            for name in OWNERS:
                args += ['--local', f'{name}={self.source}']
        args += list(extra)
        return subprocess.run(args, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    def assert_rejected_without_destination(self, **kwargs):
        result = self.command(**kwargs)
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertFalse(self.destination.exists(), result.stderr)
        return result

    def test_checkout_pins_real_detached_revision_not_source_current_head(self):
        (self.source / 'source.txt').write_text('second revision\n', encoding='utf-8')
        self.git('add', '.')
        self.git('commit', '-qm', 'second fixture revision')
        result = self.command()
        self.assertEqual(result.returncode, 0, result.stderr)
        for name in OWNERS:
            target = self.destination / name
            self.assertEqual((target / 'source.txt').read_text(), 'first revision\n')
            self.assertEqual(self.git('rev-parse', 'HEAD', cwd=target).strip(), self.first)
            symbolic = subprocess.run(['git', '-C', str(target), 'symbolic-ref', '-q', 'HEAD'], capture_output=True)
            self.assertNotEqual(symbolic.returncode, 0)
        selected = json.loads((self.destination / 'workspace.sources.json').read_text())
        self.assertEqual(selected['sources'][0]['revision'], self.first)
        self.assertEqual(selected['sources'][0]['local_path'], str(self.source))
        self.assertIsNone(selected['sources'][0]['url'])

    def test_checkout_never_copies_ignored_secrets_outputs_or_source_hooks(self):
        (self.source / '.env').write_text('PRIVATE_TOKEN=do-not-copy\n')
        for folder in ('.local', '.generic-local', 'build', 'node_modules'):
            (self.source / folder).mkdir()
            (self.source / folder / 'private').write_text('do-not-copy')
        hook = self.source / '.git/hooks/post-checkout'
        marker = self.root / 'hook-executed'
        hook.write_text(f'#!/bin/sh\ntouch "{marker}"\n')
        hook.chmod(0o700)
        result = self.command()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(marker.exists())
        for name in OWNERS:
            for excluded in ('.env', '.local', '.generic-local', 'build', 'node_modules'):
                self.assertFalse((self.destination / name / excluded).exists())

    def test_resolve_explicit_local_inputs_pins_current_head_without_checkout(self):
        self.write_manifest([{'name': name, 'url': None, 'revision': None, 'local': True} for name in OWNERS])
        output = self.root / 'pinned.json'
        result = self.command('resolve', extra=('--output', str(output)))
        self.assertEqual(result.returncode, 0, result.stderr)
        document = json.loads(output.read_text())
        self.assertEqual({entry['revision'] for entry in document['sources']}, {self.first})
        self.assertFalse(self.destination.exists())
        self.manifest = output
        checked = self.command()
        self.assertEqual(checked.returncode, 0, checked.stderr)

    def test_unpublished_source_requires_explicit_local_override(self):
        result = self.assert_rejected_without_destination(local=False)
        self.assertIn('unpublished', result.stderr.lower())

    def test_unresolved_revision_cannot_bootstrap_moving_main(self):
        entries = [{'name': name, 'url': 'https://github.com/example/' + name,
                    'revision': None, 'ref': 'main'} for name in OWNERS]
        self.write_manifest(entries)
        result = self.assert_rejected_without_destination(local=False)
        self.assertIn('resolve', result.stderr.lower())

    def test_invalid_manifests_reject_before_target_writes(self):
        valid = [{'name': name, 'url': None, 'revision': self.first, 'local': True} for name in OWNERS]
        cases = []
        for value in ('a' * 39, 'G' * 40, 'A' * 40, 'main', '0' * 40, None):
            entries = [dict(entry) for entry in valid]
            entries[0]['revision'] = value
            cases.append(entries)
        cases += [valid[:-1], valid + [dict(valid[0])]]
        for name in ('../escape', '/absolute', 'unknown-service', 'frontend/child', 'frontend\\child'):
            entries = [dict(entry) for entry in valid]
            entries[0]['name'] = name
            cases.append(entries)
        for entries in cases:
            with self.subTest(entries=entries):
                self.write_manifest(entries)
                self.assert_rejected_without_destination()

    def test_remote_urls_reject_credentials_query_fragment_ports_and_other_protocols(self):
        urls = ('http://github.com/example/repo', 'https://user:pass@github.com/example/repo',
                'https://github.com:443/example/repo', 'https://github.com/example/repo?token=secret',
                'https://github.com/example/repo#main', 'git@github.com:example/repo',
                'file:///private/source', 'https://evil.invalid/example/repo',
                'https://github.com/example/../repo', 'https://github.com/example/repo/extra')
        for url in urls:
            with self.subTest(url=url):
                entries = [{'name': name, 'url': url, 'revision': self.first} for name in OWNERS]
                self.write_manifest(entries)
                self.assert_rejected_without_destination(local=False)

    def test_missing_fields_and_duplicate_json_keys_reject(self):
        self.manifest.write_text('{"version":1,"version":1,"sources":[]}')
        self.assert_rejected_without_destination()
        self.write_manifest([{'name': name, 'revision': self.first, 'local': True} for name in OWNERS])
        self.assert_rejected_without_destination()

    def test_existing_empty_destination_is_not_reused(self):
        self.destination.mkdir()
        result = self.command()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(list(self.destination.iterdir()), [])

    def test_dirty_destination_is_preserved(self):
        self.destination.mkdir()
        marker = self.destination / 'owner-data'
        marker.write_text('preserve')
        result = self.command()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(marker.read_text(), 'preserve')
        self.assertEqual(list(self.destination.iterdir()), [marker])

    def test_dirty_local_source_rejects_instead_of_claiming_uncommitted_sources_pinned(self):
        (self.source / 'source.txt').write_text('uncommitted')
        self.assert_rejected_without_destination()

    def test_untracked_nonignored_source_rejects(self):
        (self.source / 'untracked-source.txt').write_text('uncommitted')
        self.assert_rejected_without_destination()

    def test_unavailable_commit_leaves_no_partial_workspace(self):
        self.write_manifest([{'name': name, 'url': None, 'revision': '1' * 40, 'local': True} for name in OWNERS])
        self.assert_rejected_without_destination()

    def test_symlink_source_or_destination_parent_rejects(self):
        alias = self.root / 'alias'
        alias.symlink_to(self.source, target_is_directory=True)
        overrides = tuple(item for name in OWNERS for item in ('--local', f'{name}={alias if name == "frontend" else self.source}'))
        result = self.command(local=False, extra=overrides)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.destination.exists())
        outside = self.root / 'outside'
        outside.mkdir()
        parent = self.root / 'linked-parent'
        parent.symlink_to(outside, target_is_directory=True)
        result = self.command(destination=parent / 'workspace')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(list(outside.iterdir()), [])

    def test_destination_traversal_and_dangling_symlink_reject(self):
        result = self.command(destination=self.root / 'missing' / '..' / 'fresh')
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.destination.exists())
        self.destination.symlink_to(self.root / 'does-not-exist')
        result = self.command()
        self.assertNotEqual(result.returncode, 0)
        self.assertTrue(self.destination.is_symlink())

    def test_tracked_symlinks_submodules_and_sensitive_paths_reject_before_publish(self):
        for kind in ('symlink', 'secret', 'build', 'generic-private', 'submodule'):
            with self.subTest(kind=kind):
                self.git('reset', '--hard', self.first)
                if kind == 'symlink':
                    (self.source / 'escape').symlink_to('/etc/passwd')
                    self.git('add', 'escape')
                elif kind == 'submodule':
                    self.git('update-index', '--add', '--cacheinfo', f'160000,{self.first},nested')
                else:
                    path = '.env' if kind == 'secret' else '.generic-local/identity.env' if kind == 'generic-private' else 'build/output'
                    target = self.source / path
                    target.parent.mkdir(exist_ok=True)
                    target.write_text('private')
                    self.git('add', '-f', path)
                self.git('commit', '-qm', 'unsafe fixture')
                revision = self.git('rev-parse', 'HEAD').strip()
                self.write_manifest([{'name': name, 'url': None, 'revision': revision, 'local': True} for name in OWNERS])
                self.assert_rejected_without_destination()

    def test_resolve_never_overwrites_existing_output(self):
        output = self.root / 'pinned.json'
        output.write_text('owner output')
        result = self.command('resolve', extra=('--output', str(output)))
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(output.read_text(), 'owner output')

    def test_local_source_must_be_repository_root(self):
        nested = self.source / 'nested'
        nested.mkdir()
        overrides = tuple(item for name in OWNERS for item in ('--local', f'{name}={nested if name == "frontend" else self.source}'))
        result = self.command(local=False, extra=overrides)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.destination.exists())


    def test_selected_local_metadata_never_grants_implicit_source_access(self):
        entries = [{'name': name, 'url': None, 'revision': self.first,
                    'local': True, 'local_path': str(self.source)} for name in OWNERS]
        self.write_manifest(entries)
        self.assert_rejected_without_destination(local=False)

    def test_dirty_last_source_leaves_no_earlier_owner_copy(self):
        other = self.root / 'other'
        self.git('clone', '--quiet', '--', str(self.source), str(other), cwd=self.root)
        (other / 'source.txt').write_text('dirty late owner')
        overrides = tuple(item for name in OWNERS for item in ('--local', f'{name}={other if name == "referral-service" else self.source}'))
        self.assert_rejected_without_destination(local=False, extra=overrides)
        self.assertEqual(list(self.root.glob('.workspace-*')), [])

    def test_duplicate_local_override_rejects_without_writes(self):
        self.assert_rejected_without_destination(extra=('--local', f'frontend={self.source}'))

    def test_source_hooks_and_external_filters_do_not_execute(self):
        (self.source / '.gitattributes').write_text('source.txt filter=unsafe\n')
        self.git('add', '.gitattributes')
        self.git('commit', '-qm', 'attribute fixture')
        revision = self.git('rev-parse', 'HEAD').strip()
        marker = self.root / 'filter-executed'
        self.git('config', 'filter.unsafe.smudge', f'touch "{marker}"')
        self.git('config', 'filter.unsafe.clean', f'touch "{marker}"')
        self.write_manifest([{'name': name, 'url': None, 'revision': revision, 'local': True} for name in OWNERS])
        result = self.command()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(marker.exists())
        self.assertEqual((self.destination / 'frontend/source.txt').read_text(), 'first revision\n')

    def test_staged_source_change_is_dirty_even_when_worktree_matches_index(self):
        (self.source / 'source.txt').write_text('staged but not committed')
        self.git('add', 'source.txt')
        self.assert_rejected_without_destination()

    def test_changed_executable_bit_is_dirty(self):
        (self.source / 'source.txt').chmod(0o755)
        self.assert_rejected_without_destination()

    def test_local_git_metadata_symlink_rejects(self):
        metadata = self.source / '.git'
        actual = self.root / 'source-git-metadata'
        metadata.rename(actual)
        metadata.symlink_to(actual, target_is_directory=True)
        self.assert_rejected_without_destination()

    def scheduled_command(self, command, boundary, destination):
        # Scheduling barrier only: real source inspection, Git, filesystem writes,
        # and the real atomic publication still execute in the child process.
        code = '''
import importlib.util, sys
spec = importlib.util.spec_from_file_location('workspace_fixture', sys.argv[1])
workspace = importlib.util.module_from_spec(spec)
spec.loader.exec_module(workspace)
boundary = sys.argv[2]
original = getattr(workspace, boundary)
def scheduled(*args, **kwargs):
    if boundary == 'selected_sources':
        result = original(*args, **kwargs)
    print('BARRIER', flush=True)
    if sys.stdin.readline().strip() != 'continue':
        raise RuntimeError('fixture scheduling interrupted')
    if boundary == 'selected_sources':
        return result
    return original(*args, **kwargs)
setattr(workspace, boundary, scheduled)
raise SystemExit(workspace.main(sys.argv[3:]))
'''
        args = [sys.executable, '-c', code, str(SCRIPT), boundary, command,
                '--manifest', str(self.manifest)]
        args += ['--destination' if command == 'checkout' else '--output', str(destination)]
        for name in OWNERS:
            args += ['--local', f'{name}={self.source}']
        child = subprocess.Popen(args, text=True, stdin=subprocess.PIPE,
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.addCleanup(lambda: child.poll() is None and child.kill())
        self.assertEqual(child.stdout.readline().strip(), 'BARRIER')
        return child

    def continue_child(self, child):
        output, error = child.communicate('continue\n', timeout=90)
        return child.returncode, output, error

    def assert_complete_workspace(self, destination):
        self.assertEqual({entry.name for entry in destination.iterdir()},
                         set(OWNERS) | {'workspace.sources.json'})
        for name in OWNERS:
            self.assertEqual((destination / name / 'source.txt').read_text(), 'first revision\n')
        self.assertEqual(len(json.loads((destination / 'workspace.sources.json').read_text())['sources']), 9)

    def test_checkout_publication_exposes_only_complete_workspace(self):
        child = self.scheduled_command('checkout', 'atomic_publish', self.destination)
        self.assertFalse(self.destination.exists())
        staging = list(self.root.glob('.workspace-*'))
        self.assertEqual(len(staging), 1)
        self.assert_complete_workspace(staging[0])
        code, _, error = self.continue_child(child)
        self.assertEqual(code, 0, error)
        self.assert_complete_workspace(self.destination)
        self.assertEqual(list(self.root.glob('.workspace-*')), [])

    def test_competing_creator_empty_destination_is_not_replaced(self):
        child = self.scheduled_command('checkout', 'atomic_publish', self.destination)
        self.destination.mkdir()
        original_inode = self.destination.stat().st_ino
        code, _, _ = self.continue_child(child)
        self.assertNotEqual(code, 0)
        self.assertEqual(self.destination.stat().st_ino, original_inode)
        self.assertEqual(list(self.destination.iterdir()), [])
        self.assertEqual(list(self.root.glob('.workspace-*')), [])

    def test_killed_checkout_before_publish_leaves_no_partial_final_name(self):
        child = self.scheduled_command('checkout', 'atomic_publish', self.destination)
        self.assertFalse(self.destination.exists())
        child.kill()
        child.communicate(timeout=10)
        self.assertFalse(self.destination.exists())

    def test_parent_swap_cannot_redirect_checkout_or_resolve_writes(self):
        for command in ('checkout', 'resolve'):
            with self.subTest(command=command):
                parent = self.root / ('parent-' + command)
                parent.mkdir()
                moved = self.root / ('original-' + command)
                outside = self.root / ('outside-' + command)
                outside.mkdir()
                sentinel = outside / 'owner-data'
                sentinel.write_text('preserve')
                leaf = 'workspace' if command == 'checkout' else 'pinned.json'
                child = self.scheduled_command(command, 'selected_sources', parent / leaf)
                parent.rename(moved)
                parent.symlink_to(outside, target_is_directory=True)
                code, _, error = self.continue_child(child)
                self.assertEqual(code, 0, error)
                self.assertEqual(list(outside.iterdir()), [sentinel])
                self.assertEqual(sentinel.read_text(), 'preserve')
                if command == 'checkout':
                    self.assert_complete_workspace(moved / leaf)
                else:
                    self.assertEqual(len(json.loads((moved / leaf).read_text())['sources']), 9)
                self.assertFalse((outside / leaf).exists())

    def test_resolve_publishes_complete_json_and_preserves_competing_file(self):
        output = self.root / 'resolved.json'
        child = self.scheduled_command('resolve', 'atomic_publish', output)
        self.assertFalse(output.exists())
        output.write_text('competing owner file')
        code, _, _ = self.continue_child(child)
        self.assertNotEqual(code, 0)
        self.assertEqual(output.read_text(), 'competing owner file')
        self.assertEqual(list(self.root.glob('.workspace-*')), [])

    def test_killed_resolve_before_publish_leaves_no_truncated_manifest(self):
        output = self.root / 'resolved.json'
        child = self.scheduled_command('resolve', 'atomic_publish', output)
        self.assertFalse(output.exists())
        child.kill()
        child.communicate(timeout=10)
        self.assertFalse(output.exists())

    def test_parent_swap_at_publication_keeps_rename_and_cleanup_bound(self):
        for command in ('checkout', 'resolve'):
            with self.subTest(command=command):
                parent = self.root / ('publish-parent-' + command)
                parent.mkdir()
                moved = self.root / ('publish-original-' + command)
                outside = self.root / ('publish-outside-' + command)
                outside.mkdir()
                leaf = 'workspace' if command == 'checkout' else 'pinned.json'
                child = self.scheduled_command(command, 'atomic_publish', parent / leaf)
                parent.rename(moved)
                parent.symlink_to(outside, target_is_directory=True)
                # Force no-replace failure in the originally bound directory.
                # The replacement target must not be touched by publication or cleanup.
                competitor = moved / leaf
                competitor.mkdir() if command == 'checkout' else competitor.write_text('owner data')
                sentinel = outside / 'unrelated'
                sentinel.write_text('preserve')
                code, _, _ = self.continue_child(child)
                self.assertNotEqual(code, 0)
                self.assertEqual(list(outside.iterdir()), [sentinel])
                self.assertEqual(sentinel.read_text(), 'preserve')
                self.assertEqual(list(moved.glob('.workspace-*')), [])
                if command == 'checkout':
                    self.assertEqual(list(competitor.iterdir()), [])
                else:
                    self.assertEqual(competitor.read_text(), 'owner data')

if __name__ == '__main__':
    unittest.main()
