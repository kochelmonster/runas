"""test autoupdate methods"""
import sys
import unittest
from pathlib import Path
from commands import SudoCommands
from runas import SudoProxy

DIR = str(Path(__file__).resolve().parent)

sys.path.append(DIR)


class TestSudo(unittest.TestCase):
    def test_autoupdate(self):
        proxy = SudoProxy(SudoCommands())
        proxy.start()
        self.assertTrue(proxy.is_root())
        proxy.terminate()


if __name__ == "__main__":
    unittest.main()
