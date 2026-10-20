from __future__ import annotations
import sys
import hashlib
from PySide6.QtCore import Qt, QTimer, QEvent
from PySide6.QtGui import QAction
from PySide6.QtWidgets import (QApplication, QComboBox, QDialog, QDialogButtonBox,
    QFormLayout, QHBoxLayout, QHeaderView, QLineEdit, QMainWindow, QMessageBox,
    QPushButton, QSystemTrayIcon, QTableWidget, QTableWidgetItem, QTextEdit,
    QVBoxLayout, QWidget, QMenu, QInputDialog, QCheckBox, QLabel, QStyle)
from .models import Credential
from .repository import CredentialRepository
from .crypto import InvalidMasterPassword
from .github_sync import GitHubConfigStore, GitHubContentsClient, GitHubError, GitHubConflict, GitHubSyncService
from .mcp_policy import AgentPolicyStore

STYLE = """
QWidget { background:#10131b; color:#e7eaf2; font-family:'Segoe UI'; font-size:10pt; }
QMainWindow { background:#10131b; }
QLineEdit,QTextEdit,QComboBox { background:#191e29; border:1px solid #2b3342; border-radius:8px; padding:9px; }
QPushButton { background:#252d3c; border:1px solid #364156; border-radius:8px; padding:9px 14px; }
QPushButton:hover { background:#303b50; }
QPushButton#primary { background:#7068f5; border:0; font-weight:600; }
QTableWidget { background:#151a24; alternate-background-color:#191f2a; border:1px solid #252c39; border-radius:10px; gridline-color:#252c39; }
QHeaderView::section { background:#191e29; border:0; padding:10px; color:#a9b2c3; }
"""


class CredentialDialog(QDialog):
    def __init__(self, parent=None, credential: Credential | None = None):
        super().__init__(parent)
        self.setWindowTitle("Editar credencial" if credential else "Nova credencial")
        self.setMinimumWidth(440)
        self.ident = credential.id if credential else ""
        self.credential = credential
        form = QFormLayout(self)
        self.name = QLineEdit(credential.name if credential else "")
        self.service = QLineEdit(credential.service if credential else "")
        self.project = QLineEdit(credential.project if credential else "")
        self.environment = QComboBox(); self.environment.setEditable(True)
        self.environment.addItems(["Desenvolvimento", "Testes", "Homologação", "Produção", "Sandbox", "Local"])
        if credential: self.environment.setCurrentText(credential.environment)
        self.secret = QLineEdit(credential.secret if credential else ""); self.secret.setEchoMode(QLineEdit.EchoMode.Password)
        reveal = QPushButton("Mostrar")
        reveal.clicked.connect(lambda: self.secret.setEchoMode(QLineEdit.EchoMode.Normal if self.secret.echoMode()==QLineEdit.EchoMode.Password else QLineEdit.EchoMode.Password))
        secret_row = QWidget(); row = QHBoxLayout(secret_row); row.setContentsMargins(0,0,0,0); row.addWidget(self.secret); row.addWidget(reveal)
        self.notes = QTextEdit(credential.usage_notes if credential else ""); self.notes.setMaximumHeight(90)
        form.addRow("Nome da chave",self.name); form.addRow("Serviço",self.service)
        form.addRow("Projeto",self.project); form.addRow("Ambiente",self.environment)
        form.addRow("Valor secreto",secret_row); form.addRow("Instruções",self.notes)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Save | QDialogButtonBox.StandardButton.Cancel)
        buttons.accepted.connect(self.accept); buttons.rejected.connect(self.reject); form.addRow(buttons)

    def value(self) -> Credential:
        return Credential(self.ident,self.name.text().strip(),self.service.text().strip(),self.project.text().strip(),
                          self.environment.currentText().strip(),self.notes.toPlainText().strip(),self.secret.text(),
                          not bool(self.secret.text()))

    def accept(self):
        required=(self.name.text().strip(),self.service.text().strip(),self.project.text().strip())
        can_remain_draft=bool(self.credential and self.credential.pending_secret)
        if not all(required) or (not self.secret.text() and not can_remain_draft):
            QMessageBox.warning(self,"Campos obrigatórios","Preencha nome, serviço, projeto e valor da chave."); return
        super().accept()


class GitHubSettingsDialog(QDialog):
    def __init__(self, parent=None, config=None):
        super().__init__(parent); self.setWindowTitle("Sincronização GitHub"); self.setMinimumWidth(500)
        form=QFormLayout(self)
        self.owner=QLineEdit((config or {}).get("owner", "")); self.owner.setPlaceholderText("usuário ou organização")
        self.repo=QLineEdit((config or {}).get("repo", "")); self.repo.setPlaceholderText("cofre-privado")
        self.token=QLineEdit((config or {}).get("token", "")); self.token.setEchoMode(QLineEdit.EchoMode.Password)
        self.token.setPlaceholderText("fine-grained PAT, armazenado via DPAPI")
        form.addRow("Proprietário",self.owner); form.addRow("Repositório privado",self.repo); form.addRow("Token",self.token)
        form.addRow(QLabel("Crie um Fine-grained PAT limitado somente a este repositório: Metadata (read) e Contents (read/write). O token fica protegido pelo DPAPI neste computador."))
        buttons=QDialogButtonBox(QDialogButtonBox.StandardButton.Save | QDialogButtonBox.StandardButton.Cancel)
        buttons.accepted.connect(self.accept); buttons.rejected.connect(self.reject); form.addRow(buttons)

    def accept(self):
        if not all((self.owner.text().strip(),self.repo.text().strip(),self.token.text().strip())):
            QMessageBox.warning(self,"Configuração incompleta","Preencha proprietário, repositório e token."); return
        super().accept()

    def config(self):
        return self.owner.text().strip(),self.repo.text().strip(),self.token.text().strip()


class MainWindow(QMainWindow):
    def __init__(self, repository=None):
        super().__init__(); self.repo = repository or CredentialRepository()
        self.is_locked=False
        self.setWindowTitle("Cofre Universal"); self.resize(1040,680)
        if not self.repo.vault_exists():
            initial_credentials = []
            if self.repo.legacy_available():
                migrate = QMessageBox.question(self,"Migrar cofre local anterior?",
                    "Foi encontrado um cofre da versão anterior. Ele será mantido sem alterações após a migração. Migrar agora?",
                    QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.Cancel)
                if migrate != QMessageBox.StandardButton.Yes: raise SystemExit(0)
                old_password, ok = QInputDialog.getText(self,"Senha anterior","Digite a senha do cofre local anterior:",QLineEdit.EchoMode.Password)
                if not ok: raise SystemExit(0)
                try: initial_credentials = self.repo.read_legacy_credentials(old_password)
                except Exception:
                    QMessageBox.critical(self,"Falha na migração","Não foi possível abrir o cofre anterior. O banco original não foi alterado.")
                    raise SystemExit(1)
            password, ok = QInputDialog.getText(self, "Criar cofre", "Crie uma senha mestra (mínimo 12 caracteres):", QLineEdit.EchoMode.Password)
            if not ok or len(password) < 12:
                QMessageBox.critical(self, "Configuração necessária", "A senha mestra deve ter pelo menos 12 caracteres.")
                raise SystemExit(1)
            confirm, ok = QInputDialog.getText(self, "Confirmar senha mestra", "Digite novamente sua senha mestra:", QLineEdit.EchoMode.Password)
            if not ok or confirm != password:
                QMessageBox.critical(self, "Senha não confirmada", "As senhas não coincidem; o cofre não foi criado.")
                raise SystemExit(1)
            self.repo.create(password, initial_credentials)
        else:
            self._unlock_prompt()
        self.inactivity = QTimer(self); self.inactivity.setSingleShot(True)
        self.inactivity.timeout.connect(self.lock)
        central = QWidget(); layout = QVBoxLayout(central); layout.setContentsMargins(28,24,28,20); layout.setSpacing(16)
        header=QHBoxLayout(); title=QLineEdit(); title.setReadOnly(True); title.setText("COFRE UNIVERSAL  •  SUAS CREDENCIAIS, SOB SEU CONTROLE")
        title.setStyleSheet("font-size:17pt;font-weight:700;border:0;background:transparent;padding:0")
        header.addWidget(title); self.state=QLineEdit("●  Cofre local • sincronização configurável"); self.state.setReadOnly(True); self.state.setMaximumWidth(320); self.state.setStyleSheet("color:#75d6a0;border:0;background:transparent")
        header.addWidget(self.state); layout.addLayout(header)
        bar=QHBoxLayout(); self.search=QLineEdit(); self.search.setPlaceholderText("⌕  Pesquisar por chave, serviço, projeto ou ambiente")
        self.search.textChanged.connect(self.refresh); bar.addWidget(self.search,1)
        for label,fn,primary in [("＋  Nova credencial",self.add_credential,True),("Editar",self.edit_credential,False),("Excluir",self.delete_credential,False)]:
            b=QPushButton(label); b.clicked.connect(fn)
            if primary: b.setObjectName("primary")
            bar.addWidget(b)
        ai_help=QPushButton("Cadastro assistido por IA"); ai_help.clicked.connect(self.show_ai_enrollment_help); bar.addWidget(ai_help)
        layout.addLayout(bar)
        self.table=QTableWidget(0,6); self.table.setHorizontalHeaderLabels(["CHAVE","SERVIÇO","PROJETO","AMBIENTE","VALOR","AÇÃO"])
        self.table.setAlternatingRowColors(True); self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows); self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch); self.table.verticalHeader().setVisible(False); self.table.doubleClicked.connect(self.edit_credential)
        layout.addWidget(self.table,1)
        foot=QHBoxLayout(); foot.addWidget(QLabel("O Windows pode manter cópias no histórico ou na sincronização da área de transferência."))
        lock=QPushButton("Bloquear agora"); lock.clicked.connect(self.lock); foot.addWidget(lock); layout.addLayout(foot)
        settings=QHBoxLayout(); self.autostart=QCheckBox("Iniciar com o Windows")
        self.autostart.setChecked(self._autostart_enabled()); self.autostart.toggled.connect(self._set_autostart)
        settings.addWidget(self.autostart); settings.addStretch(1)
        self.mcp_access=QCheckBox("Permitir ao MCP consultar metadados")
        try: self.mcp_access.setChecked(AgentPolicyStore().enabled())
        except Exception: self.mcp_access.setChecked(False)
        self.mcp_access.toggled.connect(self._set_mcp_access); settings.addWidget(self.mcp_access)
        self.sync_button=QPushButton("Sincronizar agora"); self.sync_button.clicked.connect(lambda: self.sync_github(silent=False)); settings.addWidget(self.sync_button)
        self.github_settings_button=QPushButton("Configurar GitHub"); self.github_settings_button.clicked.connect(self.configure_github); settings.addWidget(self.github_settings_button)
        layout.addLayout(settings)
        ai_permissions=QHBoxLayout(); ai_permissions.addStretch(1)
        self.ai_draft_access=QCheckBox("Permitir à IA preparar rascunhos sem valores secretos")
        try: self.ai_draft_access.setChecked(AgentPolicyStore().drafts_enabled())
        except Exception: self.ai_draft_access.setChecked(False)
        self.ai_draft_access.toggled.connect(self._set_ai_draft_access)
        ai_permissions.addWidget(self.ai_draft_access); layout.addLayout(ai_permissions)
        self.tray=None
        self.setCentralWidget(central); self._setup_tray(); self.refresh(); self._reset_inactivity()
        QApplication.instance().installEventFilter(self)
        self.sync_timer=QTimer(self); self.sync_timer.setInterval(5*60*1000); self.sync_timer.timeout.connect(lambda: self.sync_github(silent=True)); self.sync_timer.start()
        QTimer.singleShot(5000,lambda: self.sync_github(silent=True))

    def _unlock_prompt(self):
        while True:
            password, ok = QInputDialog.getText(self, "Cofre bloqueado", "Digite sua senha para desbloquear:", QLineEdit.EchoMode.Password)
            if not ok:
                raise SystemExit(0)
            try:
                self.repo.unlock(password)
                self.is_locked=False
                return
            except InvalidMasterPassword:
                QMessageBox.warning(self, "Senha incorreta", "Não foi possível desbloquear o cofre.")

    def _reset_inactivity(self):
        if hasattr(self, "inactivity") and not self.is_locked:
            self.inactivity.start(10 * 60 * 1000)

    def eventFilter(self, watched, event):
        if event.type() in (QEvent.Type.KeyPress, QEvent.Type.MouseButtonPress, QEvent.Type.MouseMove, QEvent.Type.Wheel):
            self._reset_inactivity()
        return super().eventFilter(watched, event)

    @staticmethod
    def _autostart_enabled():
        if sys.platform != "win32": return False
        try:
            import winreg
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run") as key:
                winreg.QueryValueEx(key, "CofreUniversal"); return True
        except (OSError, ImportError): return False

    def _set_autostart(self, enabled):
        if sys.platform != "win32": return
        import winreg
        key_path = r"Software\Microsoft\Windows\CurrentVersion\Run"
        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, key_path) as key:
            if enabled:
                if getattr(sys, "frozen", False):
                    command = f'"{sys.executable}"'
                else:
                    executable = str(__import__("pathlib").Path(sys.executable).with_name("pythonw.exe"))
                    entry = str(__import__("pathlib").Path(sys.argv[0]).resolve())
                    command = f'"{executable}" "{entry}"'
                winreg.SetValueEx(key, "CofreUniversal", 0, winreg.REG_SZ, command)
            else:
                try: winreg.DeleteValue(key, "CofreUniversal")
                except FileNotFoundError: pass

    def _set_mcp_access(self, enabled):
        try: AgentPolicyStore().set_enabled(enabled)
        except Exception as exc:
            self.mcp_access.blockSignals(True); self.mcp_access.setChecked(False); self.mcp_access.blockSignals(False)
            QMessageBox.critical(self,"Permissão MCP não salva",str(exc))

    def _set_ai_draft_access(self, enabled):
        try: AgentPolicyStore().set_drafts_enabled(enabled)
        except Exception as exc:
            self.ai_draft_access.blockSignals(True); self.ai_draft_access.setChecked(False); self.ai_draft_access.blockSignals(False)
            QMessageBox.critical(self,"Permissão de cadastro por IA não salva",str(exc))

    def show_ai_enrollment_help(self):
        QMessageBox.information(
            self, "Cadastro assistido por IA",
            "Ative a permissão abaixo e conecte seu agente ao servidor MCP ‘cofre mcp’. "
            "Peça para preparar uma credencial informando provedor, tipo, projeto e ambiente. "
            "A IA cria somente um rascunho padronizado. Depois selecione-o e clique em Editar "
            "para digitar o valor secreto diretamente nesta interface. Nunca envie a chave ao agente.")

    def configure_github(self):
        store=GitHubConfigStore()
        try: config=store.load()
        except Exception as exc:
            QMessageBox.critical(self,"Configuração inacessível",str(exc)); return
        dialog=GitHubSettingsDialog(self,config)
        if dialog.exec()!=QDialog.DialogCode.Accepted: return
        owner,repo,token=dialog.config()
        try:
            GitHubContentsClient(owner,repo,token).verify_private_repository()
            store.save(owner,repo,token)
            self.state.setText("●  GitHub privado conectado"); self.state.setStyleSheet("color:#75d6a0;border:0;background:transparent")
            QTimer.singleShot(0,lambda: self.sync_github(silent=True))
        except Exception as exc:
            QMessageBox.critical(self,"Falha ao verificar GitHub",str(exc))

    def sync_github(self,silent=False):
        if not self.repo.is_unlocked(): return
        try: config=GitHubConfigStore().load()
        except Exception as exc:
            if not silent: QMessageBox.warning(self,"Sincronização indisponível",str(exc))
            return
        if not config:
            self.state.setText("●  Local • configure o GitHub para sincronizar"); return
        client=GitHubContentsClient(config["owner"],config["repo"],config["token"])
        service=GitHubSyncService(client)
        try:
            message=service.sync(self.repo)
            self.state.setText("●  Sincronizado com GitHub"); self.state.setStyleSheet("color:#75d6a0;border:0;background:transparent")
            if not silent: self.statusBar().showMessage(message,5000)
            self.refresh()
        except GitHubConflict as exc:
            self.state.setText("●  Conflito de sincronização")
            if silent: return
            answer=QMessageBox(self); answer.setWindowTitle("Conflito no cofre")
            answer.setText(f"{exc}\nUma cópia cifrada da versão substituída será preservada no repositório.")
            local=answer.addButton("Manter esta versão local",QMessageBox.ButtonRole.AcceptRole)
            remote=answer.addButton("Usar versão do GitHub",QMessageBox.ButtonRole.DestructiveRole)
            answer.addButton(QMessageBox.StandardButton.Cancel); answer.exec()
            if answer.clickedButton() not in (local,remote): return
            try:
                remote_password=None
                if answer.clickedButton()==remote:
                    remote_password, ok=QInputDialog.getText(self,"Desbloquear cofre remoto","Digite a senha mestra usada para criar o cofre remoto:",QLineEdit.EchoMode.Password)
                    if not ok: return
                outcome=service.resolve_conflict(self.repo,"local" if answer.clickedButton()==local else "remote",master_password=remote_password)
                self.state.setText("●  Sincronizado com GitHub"); self.refresh(); self.statusBar().showMessage(outcome,8000)
            except Exception as resolve_error:
                QMessageBox.critical(self,"Conflito não resolvido",str(resolve_error))
        except GitHubError as exc:
            self.state.setText("●  GitHub indisponível")
            if not silent: QMessageBox.warning(self,"Falha na sincronização",str(exc))
        except Exception as exc:
            self.state.setText("●  Sincronização indisponível")
            if not silent: QMessageBox.warning(self,"Falha na sincronização",str(exc))

    def _setup_tray(self):
        if not QSystemTrayIcon.isSystemTrayAvailable(): return
        icon=QApplication.style().standardIcon(QStyle.StandardPixmap.SP_DriveHDIcon)
        self.setWindowIcon(icon); self.tray=QSystemTrayIcon(icon,self); self.tray.setToolTip("Cofre Universal")
        menu=QMenu(); show=QAction("Abrir Cofre",self); show.triggered.connect(self.showNormal); menu.addAction(show)
        lock=QAction("Bloquear",self); lock.triggered.connect(self.lock); menu.addAction(lock)
        menu.addSeparator(); quit_action=QAction("Sair",self); quit_action.triggered.connect(QApplication.quit); menu.addAction(quit_action)
        self.tray.setContextMenu(menu); self.tray.show()

    def refresh(self,*_):
        try: items=self.repo.list_metadata(self.search.text())
        except Exception as exc:
            self.state.setText("●  Cofre indisponível"); QMessageBox.critical(self,"Erro ao abrir cofre",str(exc)); return
        pending_count=sum(bool(item.get("secret_pending")) for item in items)
        if pending_count:
            self.statusBar().showMessage(f"{pending_count} rascunho(s) aguardando preenchimento do valor na interface",0)
        else:
            self.statusBar().clearMessage()
        self.table.setRowCount(len(items))
        for r,c in enumerate(items):
            self.table.setItem(r,0,QTableWidgetItem(c["name"])); self.table.setItem(r,1,QTableWidgetItem(c["service"]))
            self.table.setItem(r,2,QTableWidgetItem(c["project"])); self.table.setItem(r,3,QTableWidgetItem(c["environment"]))
            pending=bool(c.get("secret_pending"))
            if pending:
                reveal=QPushButton("Preencher valor"); reveal.clicked.connect(lambda _,row=r: self._edit_row(row))
            else:
                reveal=QPushButton("Mostrar"); reveal.clicked.connect(lambda _,row=r: self.toggle_secret(row))
            self.table.setCellWidget(r,4,reveal)
            copy=QPushButton("Pendente" if pending else "Copiar"); copy.setEnabled(not pending)
            copy.clicked.connect(lambda _,row=r: self.copy_secret(row)); self.table.setCellWidget(r,5,copy)
            self.table.item(r,0).setData(Qt.ItemDataRole.UserRole,c["id"])

    def selected(self):
        row=self.table.currentRow()
        if row<0: return None
        return self.repo.get(self.table.item(row,0).data(Qt.ItemDataRole.UserRole))

    def add_credential(self):
        d=CredentialDialog(self)
        if d.exec()==QDialog.DialogCode.Accepted: self.repo.save(d.value()); self.refresh()

    def edit_credential(self):
        c=self.selected()
        if not c: return
        d=CredentialDialog(self,c)
        if d.exec()==QDialog.DialogCode.Accepted: self.repo.save(d.value()); self.refresh()

    def _edit_row(self,row):
        self.table.selectRow(row)
        self.edit_credential()

    def delete_credential(self):
        c=self.selected()
        if c and QMessageBox.question(self,"Excluir credencial",f"Excluir {c.name}?")==QMessageBox.StandardButton.Yes:
            self.repo.delete(c.id); self.refresh()

    def toggle_secret(self,row):
        c=self.repo.get(self.table.item(row,0).data(Qt.ItemDataRole.UserRole)); button=self.table.cellWidget(row,4)
        if c and button.text()=="Mostrar": button.setText(c.secret); button.setProperty("secret",c.secret); QTimer.singleShot(15000,lambda: self._hide_value(button))
        elif button: self._hide_value(button)

    @staticmethod
    def _hide_value(button):
        if button: button.setText("Mostrar"); button.setProperty("secret",None)

    def copy_secret(self,row):
        c=self.repo.get(self.table.item(row,0).data(Qt.ItemDataRole.UserRole))
        if not c: return
        QApplication.clipboard().setText(c.secret)
        digest=hashlib.sha256(c.secret.encode("utf-8")).digest()
        timer=QTimer(self); timer.setSingleShot(True)
        def clear_if_unchanged():
            current=QApplication.clipboard().text().encode("utf-8")
            if hashlib.sha256(current).digest()==digest: QApplication.clipboard().clear()
        timer.timeout.connect(clear_if_unchanged); timer.start(30_000)
        if self.tray: self.tray.showMessage("Cofre Universal","Chave copiada. A área de transferência será limpa em 30 segundos.")

    def lock(self):
        if self.is_locked: return
        self.inactivity.stop()
        active_modal=QApplication.activeModalWidget()
        if active_modal is not None and active_modal is not self:
            active_modal.reject()
        for row in range(self.table.rowCount()): self._hide_value(self.table.cellWidget(row,4))
        self.repo.lock(); self.is_locked=True; self.hide()
        try: self._unlock_prompt()
        except SystemExit:
            QApplication.quit(); return
        self.showNormal(); self.refresh(); self._reset_inactivity()


def main():
    app=QApplication(sys.argv); app.setApplicationName("Cofre Universal"); app.setStyleSheet(STYLE)
    window=MainWindow(); window.show(); sys.exit(app.exec())

if __name__=="__main__": main()
