import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch

source = Path(__file__).resolve().parents[1] / 'release-metadata.py'
spec = importlib.util.spec_from_file_location('release_metadata', source)
release = importlib.util.module_from_spec(spec)
spec.loader.exec_module(release)


class ReleaseGuards(unittest.TestCase):
    def test_synchronized_repository_versions(self):
        info = release.metadata(source.parent.parent)
        self.assertRegex(info['tag'], r'^v[0-9]+\.[0-9]+\.[0-9]+$')

    def test_new_current_main_creates_tag(self):
        self.assertEqual(release.decision('refs/heads/main', 'push', 'v2.4.0',
                                         'a', 'a', ''), 'create')

    def test_existing_tag_is_never_moved_or_republished_by_main(self):
        for existing in ('a', 'older'):
            self.assertEqual(release.decision('refs/heads/main', 'push', 'v2.4.0',
                                             'a', 'a', existing), 'skip')

    def test_outdated_main_run_cannot_release(self):
        self.assertEqual(release.decision('refs/heads/main', 'push', 'v2.4.0',
                                         'older', 'newer', ''), 'skip')

    def test_matching_explicit_tag_can_retry(self):
        self.assertEqual(release.decision('refs/tags/v2.4.0', 'push', 'v2.4.0',
                                         'a', 'newer', 'a'), 'publish')
        with self.assertRaises(ValueError):
            release.decision('refs/tags/v2.4.0', 'push', 'v2.4.0', 'a', 'a', 'b')

    def test_pr_other_branches_and_wrong_tags_cannot_publish(self):
        for ref, event in (('refs/heads/main', 'pull_request'),
                           ('refs/heads/develop', 'push'),
                           ('refs/tags/v2.3.4', 'push'),
                           ('refs/pull/10/merge', 'pull_request')):
            with self.subTest(ref=ref, event=event), self.assertRaises(ValueError):
                release.decision(ref, event, 'v2.4.0', 'a', 'a', '')

    def test_inconsistent_or_unsafe_versions_are_rejected(self):
        original = Path.read_text
        for replacement in ('0.0.0', '2.4.0\nINJECTED=1'):
            def text(path, *args, **kwargs):
                value = original(path, *args, **kwargs)
                if str(path).endswith('tauri.conf.json'):
                    import json
                    data = json.loads(value); data['version'] = replacement
                    return json.dumps(data)
                return value
            with patch.object(Path, 'read_text', text), self.assertRaises(ValueError):
                release.metadata(source.parent.parent)
