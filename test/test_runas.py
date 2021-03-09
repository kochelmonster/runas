"""test autoupdate methods"""
import sys
import os
import unittest
import logging
from pathlib import Path
from commands import SudoCommands
from runas import SudoProxy, can_get_root

DIR = str(Path(__file__).resolve().parent)

sys.path.append(DIR)


class TestSudo(unittest.TestCase):
    def test_runas(self):
        self.assertTrue(can_get_root())
        proxy = SudoProxy(SudoCommands())
        user = "Administrator" if sys.platform == "win32" else "root"
        proxy.start(user, os.environ["PASS"])
        self.assertTrue(proxy.is_root())
        proxy.terminate()


if __name__ == "__main__":
    log_format = (
        "> test %(created)f %(levelname)s %(name)s %(pathname)s(%(lineno)d): %(message)s")
    logging.basicConfig(level=logging.DEBUG, format=log_format, filename="runas.log", filemode="w")
    unittest.main()
