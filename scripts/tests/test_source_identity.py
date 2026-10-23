import pathlib
import sys
import tempfile
import unittest
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
from cli import workspace_hash


class PortableSourceIdentity(unittest.TestCase):
    def test_worktree_git_pointers_and_private_env_do_not_change_source_identity(self):
        with tempfile.TemporaryDirectory() as left, tempfile.TemporaryDirectory() as right:
            first, second = pathlib.Path(left), pathlib.Path(right)
            for root, location in ((first, '/private/one'), (second, '/another/worktree')):
                directory = root / 'identity-service'; directory.mkdir()
                (directory / '.git').write_text('gitdir: ' + location)
                (directory / '.env').write_text('PASSWORD=' + location)
                (directory / 'src').mkdir()
                (directory / 'src/main.rs').write_text('fn main() {}\n')
            self.assertEqual(workspace_hash(first), workspace_hash(second))
            (second / 'identity-service/src/main.rs').write_text('fn main() { println!("changed"); }\n')
            self.assertNotEqual(workspace_hash(first), workspace_hash(second))

    def test_path_and_content_boundaries_are_unambiguous(self):
        with tempfile.TemporaryDirectory() as left, tempfile.TemporaryDirectory() as right:
            first, second = pathlib.Path(left), pathlib.Path(right)
            for root in (first, second): (root / 'frontend').mkdir()
            (first / 'frontend/ab').write_text('c')
            (second / 'frontend/a').write_text('bc')
            self.assertNotEqual(workspace_hash(first), workspace_hash(second))

    def test_gateway_recipe_changes_invalidate_source_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            workspace = pathlib.Path(directory)
            recipe = workspace / 'platform-infra/components/nginx/Dockerfile'
            recipe.parent.mkdir(parents=True)
            recipe.write_text('FROM pinned-base\n')
            before = workspace_hash(workspace)
            recipe.write_text('FROM pinned-base\nRUN install-fixed-packages\n')
            self.assertNotEqual(before, workspace_hash(workspace))

    def test_grafana_dependency_and_probe_changes_invalidate_source_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            workspace = pathlib.Path(directory)
            component = workspace / 'platform-infra/components/grafana'
            component.mkdir(parents=True)
            for filename in ('Dockerfile', 'go.sum', 'healthcheck.go'):
                with self.subTest(input=filename):
                    path = component / filename
                    path.write_text('original\n')
                    before = workspace_hash(workspace)
                    path.write_text('changed\n')
                    self.assertNotEqual(before, workspace_hash(workspace))


if __name__ == '__main__': unittest.main()
