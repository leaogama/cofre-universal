"""Windows DPAPI para blobs locais como cache cifrado e token GitHub."""
from __future__ import annotations

import sys


class SecurityUnavailable(RuntimeError):
    """A proteção de plataforma solicitada não está disponível."""


def protect(data: bytes) -> bytes:
    """Protege bytes com DPAPI no perfil Windows atual."""
    if sys.platform != "win32":
        raise SecurityUnavailable("A proteção DPAPI só está disponível no Windows.")
    try:
        import win32crypt
    except ImportError as exc:
        raise SecurityUnavailable("Instale pywin32 para habilitar DPAPI.") from exc
    return win32crypt.CryptProtectData(data, "Cofre Universal", None, None, None, 0)


def unprotect(data: bytes) -> bytes:
    """Desprotege bytes DPAPI no perfil Windows que os protegeu."""
    if sys.platform != "win32":
        raise SecurityUnavailable("A proteção DPAPI só está disponível no Windows.")
    try:
        import win32crypt
    except ImportError as exc:
        raise SecurityUnavailable("Instale pywin32 para habilitar DPAPI.") from exc
    return win32crypt.CryptUnprotectData(data, None, None, None, 0)[1]
