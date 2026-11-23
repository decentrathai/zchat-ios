"""Fable review of cbf9a85: GitHub's API is reached only through `gh api`, whose methods and paths the guard
checks. curl, wget and other HTTP clients to api.github.com / uploads.github.com are refused (a token in a header
could make a repo public in one command)."""
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "hooks"))
import guard  # noqa: E402

IOS = "/home/yourt/zchat-ios"


class GithubHttp(unittest.TestCase):
    def test_refused(self):
        for cmd in ['curl -s -X PATCH -H "Authorization: Bearer $T" https://api.github.com/repos/decentrathai/zchat-ios '
                    '-d "{\\"private\\":false}"',
                    "curl https://api.github.com/user",
                    "wget -qO- https://API.GitHub.com/user",
                    "curl -T f https://uploads.github.com/repos/x/y/releases/1/assets",
                    "http PATCH api.github.com/repos/x/y private:=false",
                    "python3 -c 'import urllib.request; urllib.request.urlopen(\"https://api.github.com/user\")'"]:
            with self.subTest(cmd=cmd):
                self.assertIsNotNone(guard.check_bash(cmd, IOS))

    def test_other_hosts_fine(self):
        self.assertIsNone(guard.check_bash("curl -s https://example.com/x", IOS))


if __name__ == "__main__":
    unittest.main()
