"""Creating a repository through the REST API is refused like `gh repo create` (found 23 Nov 2026: the guard refused
`gh repo create` but allowed `gh api -X POST user/repos`)."""
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "hooks"))
import guard  # noqa: E402

CWD = "/home/yourt/zchat-ios"


class RepoCreation(unittest.TestCase):
    def test_api_repo_creation_refused(self):
        for cmd in ['gh api -X POST user/repos -f name=zchat-ios -F private=true',
                    'gh api --method POST /user/repos -f name=x',
                    'gh api user/repos -f name=x',
                    'gh api -X POST orgs/decentrathai/repos -f name=x',
                    'GH_TOKEN="$T" gh api --method=POST /orgs/decentrathai/repos --input body.json',
                    'gh api -X POST repos/decentrathai/zchat-android/forks',
                    'gh api -X POST repos/decentrathai/template/generate -f name=x',
                    'gh api -X POST repos/decentrathai/zchat-android/transfer -f new_owner=x']:
            with self.subTest(cmd=cmd):
                self.assertIsNotNone(guard.check_bash(cmd, CWD))

    def test_reading_repos_allowed(self):
        for cmd in ['gh api user/repos', 'gh api /orgs/decentrathai/repos --jq ".[].name"',
                    'gh repo list decentrathai', 'gh repo view decentrathai/zchat-android']:
            with self.subTest(cmd=cmd):
                self.assertIsNone(guard.check_bash(cmd, CWD))


if __name__ == "__main__":
    unittest.main()
