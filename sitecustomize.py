"""Runtime compatibility patches for the bundled/minimal CipherBridge launcher.

Python automatically imports ``sitecustomize`` during interpreter startup when
this project directory is present in PYTHONPATH.  The GUI already sets
PYTHONPATH to the project root before launching mitmdump, so this patch is
applied only to CipherBridge's mitmdump child processes.

Why this exists:
Some current Windows/Python 3.13 environments install a bcrypt version whose
API no longer matches passlib's legacy backend probing code. mitmproxy imports
passlib.apache on startup, passlib probes bcrypt, and startup may abort with:

    AttributeError: module 'bcrypt' has no attribute '__about__'
    ValueError: password cannot be longer than 72 bytes

CipherBridge does not use mitmproxy proxy-auth here, so normalising bcrypt's
legacy metadata and truncation behaviour during passlib's backend probe is
sufficient to keep mitmdump startup stable.
"""

from __future__ import annotations


def _patch_bcrypt_for_passlib_probe() -> None:
    try:
        import bcrypt  # type: ignore
    except Exception:
        return

    if not hasattr(bcrypt, "__about__"):
        class _About:
            __version__ = getattr(bcrypt, "__version__", "0")

        bcrypt.__about__ = _About()  # type: ignore[attr-defined]

    original_hashpw = getattr(bcrypt, "hashpw", None)
    if original_hashpw is None or getattr(original_hashpw, "_cipherbridge_patched", False):
        return

    def _hashpw_compat(password, salt):  # type: ignore[no-untyped-def]
        if isinstance(password, (bytes, bytearray)) and len(password) > 72:
            password = bytes(password[:72])
        return original_hashpw(password, salt)

    _hashpw_compat._cipherbridge_patched = True  # type: ignore[attr-defined]
    bcrypt.hashpw = _hashpw_compat  # type: ignore[assignment]


_patch_bcrypt_for_passlib_probe()
