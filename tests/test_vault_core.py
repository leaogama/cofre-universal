import unittest
from unittest.mock import patch
import json
import asyncio
import base64
import hashlib
import sqlite3
import tempfile
from contextlib import closing

from cofre_universal.crypto import InvalidMasterPassword, create_envelope, decrypt_payload
from cofre_universal.github_sync import GitHubConflict, GitHubSyncService, RemoteDocument, SyncBaseline
from cofre_universal.models import Credential
from cofre_universal.repository import CredentialRepository, VaultLocked


class MemoryStore:
    def __init__(self): self.document = None
    def load(self): return self.document
    def save(self, document): self.document = document


class MemorySyncState:
    def __init__(self): self.baseline = None
    def load(self): return self.baseline
    def save(self, baseline): self.baseline = baseline


class FakeGitHub:
    def __init__(self, remote=None): self.remote = remote; self.backups = []; self.private = True
    def verify_private_repository(self):
        if not self.private: raise RuntimeError("not private")
    def read_vault(self): return self.remote
    def write_document(self, path, content, sha, message):
        if path.startswith("backups/"):
            self.backups.append(content); return "backup-sha"
        self.remote = RemoteDocument(content, "next-sha")
        return "next-sha"


class VaultCoreTests(unittest.TestCase):
    def test_envelope_roundtrip_and_wrong_password(self):
        document, _ = create_envelope("senha mestra fictícia longa")
        payload, _, _ = decrypt_payload(document, password="senha mestra fictícia longa")
        self.assertEqual(payload, {"version": 1, "credentials": []})
        with self.assertRaises(InvalidMasterPassword):
            decrypt_payload(document, password="senha errada fictícia")

    def test_ciphertext_tampering_is_rejected(self):
        document, _ = create_envelope("outra senha fictícia suficientemente longa")
        envelope = json.loads(document)
        ciphertext = bytearray(__import__("base64").b64decode(envelope["aead"]["ciphertext"]))
        ciphertext[-1] ^= 1
        envelope["aead"]["ciphertext"] = __import__("base64").b64encode(ciphertext).decode("ascii")
        changed = json.dumps(envelope).encode()
        with self.assertRaises(InvalidMasterPassword):
            decrypt_payload(changed, password="outra senha fictícia suficientemente longa")

    def test_repository_crud_and_lock(self):
        store = MemoryStore(); repo = CredentialRepository(store=store)
        repo.create("senha mestra de teste 123")
        repo.save(Credential("", "Demo Key", "Demo", "demo", "Teste", "uso fictício", "FAKE_SECRET"))
        self.assertNotIn(b"FAKE_SECRET", store.document)
        self.assertEqual(repo.list_metadata()[0]["name"], "Demo Key")
        self.assertEqual(repo.list_credentials()[0].secret, "FAKE_SECRET")
        repo.lock()
        with self.assertRaises(VaultLocked): repo.list_credentials()
        with self.assertRaises(InvalidMasterPassword): repo.unlock("senha incorreta fictícia")
        repo.unlock("senha mestra de teste 123")
        self.assertEqual(repo.list_credentials()[0].secret, "FAKE_SECRET")

    def test_repository_create_migrates_in_memory_records(self):
        repo=CredentialRepository(store=MemoryStore())
        item={"id":"fake-id","name":"Fake","service":"Demo","project":"demo","environment":"Teste","usage_notes":"fake","secret":"FAKE_SECRET"}
        repo.create("senha de migração fictícia",[item])
        self.assertEqual(repo.list_credentials()[0].secret,"FAKE_SECRET")

    def test_sync_uploads_initial_local_envelope(self):
        repo = CredentialRepository(store=MemoryStore()); repo.create("senha teste fictícia 123")
        gh = FakeGitHub(); state = MemorySyncState()
        result = GitHubSyncService(gh, state).sync(repo)
        self.assertIn("Sincronizado", result)
        self.assertEqual(gh.remote.content, repo.store.document)
        self.assertEqual(state.baseline.content, repo.store.document)

    def test_sync_refuses_unrelated_remote_vault(self):
        repo = CredentialRepository(store=MemoryStore()); repo.create("senha teste fictícia 123")
        remote, _ = create_envelope("senha remota fictícia 123")
        gh = FakeGitHub(RemoteDocument(remote, "remote-sha"))
        with self.assertRaises(GitHubConflict): GitHubSyncService(gh, MemorySyncState()).sync(repo)

    def test_sync_preserves_and_resolves_concurrent_edits_as_ciphertext_backup(self):
        password="senha conflito fictícia 123"
        local_store=MemoryStore(); local=CredentialRepository(store=local_store); local.create(password)
        local.save(Credential("","Local Key","Demo","demo","Teste","local","FAKE_LOCAL_SECRET"))
        gh=FakeGitHub(); state=MemorySyncState(); sync=GitHubSyncService(gh,state)
        sync.sync(local)
        base=local.store.document
        remote_store=MemoryStore(); remote=CredentialRepository(store=remote_store); remote.unlock(password,base)
        remote.save(Credential("","Remote Key","Demo","demo","Teste","remoto","FAKE_REMOTE_SECRET"))
        gh.remote=RemoteDocument(remote.store.document,"remote-next")
        local.save(Credential("","Another Local Key","Demo","demo","Teste","local","FAKE_LOCAL_2"))
        with self.assertRaises(GitHubConflict): sync.sync(local)
        result=sync.resolve_conflict(local,"local")
        self.assertIn("backup cifrado",result)
        self.assertTrue(gh.backups)
        self.assertNotIn(b"FAKE_REMOTE_SECRET",gh.backups[0])
        self.assertEqual(gh.remote.content,local.store.document)

    def test_mcp_catalog_never_returns_secret(self):
        from cofre_universal.mcp_catalog import build_server, list_available_credentials
        repo=CredentialRepository(store=MemoryStore()); repo.create("senha mcp fictícia 123")
        repo.save(Credential("","Demo Key","Demo","demo","Teste","FAKE_SECRET","FAKE_SECRET"))
        listed=list_available_credentials(repo)
        self.assertNotIn("FAKE_SECRET",repr(listed))
        server = build_server(repo, allow_metadata=True)
        tools = asyncio.run(server.list_tools())
        self.assertIn("pesquisar_credenciais", {tool.name for tool in tools})
        result=asyncio.run(server.call_tool("instrucoes_de_uso",{"nome":"Demo Key"}))
        self.assertNotIn("FAKE_SECRET",repr(result))
        self.assertIn("DEMO_KEY",repr(result))
        with self.assertRaises(PermissionError): build_server(repo, allow_metadata=False)

    def test_windows_dpapi_roundtrip(self):
        import sys
        if sys.platform != "win32": self.skipTest("DPAPI é específico do Windows")
        from cofre_universal.security import protect, unprotect
        self.assertEqual(unprotect(protect(b"FAKE_DPAPI_TEST")), b"FAKE_DPAPI_TEST")

    def test_dpapi_cache_and_github_token_store(self):
        import sys
        if sys.platform != "win32": self.skipTest("DPAPI é específico do Windows")
        from pathlib import Path
        from cofre_universal.github_sync import GitHubConfigStore
        with tempfile.TemporaryDirectory() as folder:
            vault_path=Path(folder)/"vault.cache"
            repo=CredentialRepository(path=vault_path)
            repo.create("senha dpapi fictícia 123")
            repo.save(Credential("","Fake Key","Demo","demo","Teste","fake","FAKE_SECRET"))
            self.assertNotIn(b"FAKE_SECRET",vault_path.read_bytes())
            repo.lock(); repo.unlock("senha dpapi fictícia 123")
            self.assertEqual(repo.list_credentials()[0].secret,"FAKE_SECRET")
            config_path=Path(folder)/"github-config.dpapi"
            config=GitHubConfigStore(config_path)
            config.save("fake-owner","fake-repo","ghp_FAKE_TOKEN")
            self.assertNotIn(b"ghp_FAKE_TOKEN",config_path.read_bytes())
            self.assertEqual(config.load()["token"],"ghp_FAKE_TOKEN")

    def test_legacy_migration_reads_but_preserves_original_database(self):
        import cofre_universal.repository as repository_module
        import os
        if os.name != "nt": self.skipTest("O formato legado usa DPAPI")
        from cofre_universal.security import protect
        with tempfile.TemporaryDirectory() as folder:
            salt=b"0123456789abcdef"
            password="senha antiga fictícia"
            verifier=hashlib.pbkdf2_hmac("sha256",password.encode(),salt,310_000)
            db_path=f"{folder}/cofre.db"
            with closing(sqlite3.connect(db_path)) as db:
                db.execute("CREATE TABLE local_auth(id INTEGER PRIMARY KEY,salt BLOB,verifier BLOB)")
                db.execute("INSERT INTO local_auth VALUES(1,?,?)",(salt,verifier))
                db.execute("CREATE TABLE credentials(id TEXT,name TEXT,service TEXT,project TEXT,environment TEXT,usage_notes TEXT,secret BLOB)")
                db.execute("INSERT INTO credentials VALUES(?,?,?,?,?,?,?)",("id","Fake","Demo","demo","Test","fake",protect(b"FAKE_SECRET")))
                db.commit()
            with patch.object(repository_module,"app_data_dir",return_value=__import__("pathlib").Path(folder)):
                repo=CredentialRepository(store=MemoryStore())
                values=repo.read_legacy_credentials(password)
            self.assertEqual(values[0]["secret"],"FAKE_SECRET")
            self.assertTrue(__import__("pathlib").Path(db_path).exists())

    def test_github_contents_reads_envelope_with_auth_header(self):
        from cofre_universal.github_sync import GitHubContentsClient
        import json
        document=b'{"encrypted":"FAKE_CIPHERTEXT"}'
        response_body=json.dumps({"type":"file","content":base64.b64encode(document).decode(),"sha":"sha-fake"}).encode()
        class Response:
            status=200
            def __enter__(self): return self
            def __exit__(self,*args): pass
            def read(self): return response_body
        with patch("cofre_universal.github_sync.urllib.request.urlopen",return_value=Response()) as request:
            result=GitHubContentsClient("fake-owner","fake-repo","ghp_FAKE_TOKEN").read_vault()
        self.assertEqual(result.content,document)
        self.assertEqual(result.sha,"sha-fake")
        self.assertEqual(request.call_args.args[0].get_header("Authorization"),"Bearer ghp_FAKE_TOKEN")

    def test_run_injects_only_credentials_for_requested_project(self):
        from cofre_universal import cli
        class FakeCredential:
            project="demo"; name="OpenAI API Key"; secret="FAKE_SECRET"; environment_name="OPENAI_API_KEY"
        class FakeRepository:
            def __init__(self, path=None): pass
            def unlock(self, password): pass
            def list_credentials(self): return [FakeCredential()]
        with patch.object(cli,"CredentialRepository",FakeRepository), patch.object(cli.getpass,"getpass",return_value="senha fake"), patch.object(cli.subprocess,"run") as child:
            child.return_value.returncode=7
            result=cli.run_app("demo",["python","app.py"],"unused")
        self.assertEqual(result,7)
        self.assertEqual(child.call_args.kwargs["env"]["OPENAI_API_KEY"],"FAKE_SECRET")

    def test_env_example_outputs_names_only(self):
        from cofre_universal import cli
        class FakeCredential:
            project="demo"; name="OpenAI API Key"; secret="FAKE_SECRET"; environment_name="OPENAI_API_KEY"
        class FakeRepository:
            def __init__(self, path=None): pass
            def unlock(self, password): pass
            def list_credentials(self): return [FakeCredential()]
        with patch.object(cli,"CredentialRepository",FakeRepository), patch.object(cli.getpass,"getpass",return_value="fake"):
            names=cli.env_example("demo")
        self.assertEqual(names,["OPENAI_API_KEY"])
        self.assertNotIn("FAKE_SECRET",repr(names))


if __name__ == "__main__": unittest.main()
