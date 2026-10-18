import os
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.dont_write_bytecode = True
EXAMPLE = ROOT / 'examples' / 'search-fixture'


REAL_ENGINE_HOME = os.environ.get('REA_BOT_ENGINE_HOME')


class TempHome(unittest.TestCase):
    use_real_engine = False

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.old = os.environ.get('REA_BOT_HOME')
        os.environ['REA_BOT_HOME'] = str(self.root / 'runs')
        self.old_engine = os.environ.get('REA_BOT_ENGINE_HOME')
        if not self.use_real_engine:
            os.environ['REA_BOT_ENGINE_HOME'] = str(self.root / 'no-engine')
        self.addCleanup(self._restore)

    def _restore(self):
        if self.old is None:
            os.environ.pop('REA_BOT_HOME', None)
        else:
            os.environ['REA_BOT_HOME'] = self.old
        if self.old_engine is None:
            os.environ.pop('REA_BOT_ENGINE_HOME', None)
        else:
            os.environ['REA_BOT_ENGINE_HOME'] = self.old_engine
