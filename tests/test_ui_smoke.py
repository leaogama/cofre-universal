import os
import unittest
from unittest.mock import patch

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

try:
    from PySide6.QtWidgets import QApplication
    from cofre_universal.app import MainWindow
except ImportError:
    QApplication = None


@unittest.skipIf(QApplication is None, "PySide6 não instalado")
class UiSmokeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls): cls.app = QApplication.instance() or QApplication([])

    def test_main_window_constructs_with_authenticated_repository(self):
        class FakeRepository:
            def vault_exists(self): return True
            def unlock(self, password): self.unlocked = True
            def lock(self): self.unlocked = False
            def is_unlocked(self): return True
            def list_metadata(self, query=""): return []

        with patch("cofre_universal.app.QInputDialog.getText", return_value=("fake master password", True)):
            window = MainWindow(FakeRepository())
            window.show(); self.app.processEvents()
            self.assertEqual(window.table.rowCount(), 0)
            window.lock(); self.app.processEvents()
            self.assertFalse(window.is_locked)
        window.close(); window.deleteLater(); self.app.processEvents()


if __name__ == "__main__": unittest.main()
