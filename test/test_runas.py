"""test autoupdate methods"""
import sys
import os
import unittest
from pathlib import Path
from commands import SudoCommands
from runas import SudoProxy, can_get_root

DIR = str(Path(__file__).resolve().parent)

sys.path.append(DIR)


class TestSudo(unittest.TestCase):
    def test_runas(self):
        self.assertTrue(can_get_root())
        proxy = SudoProxy(SudoCommands())
        proxy.start("root", os.environ["PASS"])
        self.assertTrue(proxy.is_root())
        proxy.terminate()


if __name__ == "__main__":
    unittest.main()
