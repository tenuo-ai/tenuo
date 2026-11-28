"""Unit tests for tenuo._native_patch (extension methods on shared native classes)."""

import pytest

from tenuo import _native_patch
from tenuo._native_patch import native_original, patch_native
from tenuo.bound_warrant import BoundWarrant


class _Native:
    def native_method(self):
        return "native"


@pytest.fixture
def cls():
    return type("Native", (_Native,), {})


def _host(f):
    return f


def test_sandbox_copy_never_replaces_existing_patch(cls, monkeypatch):
    patch_native(cls, "bind", _host)
    monkeypatch.setattr(_native_patch, "_in_workflow_sandbox", lambda: True)
    patch_native(cls, "bind", lambda f: "sandbox")
    assert cls.bind is _host


def test_host_replaces_patch_installed_by_sandbox_copy(cls, monkeypatch):
    monkeypatch.setattr(_native_patch, "_in_workflow_sandbox", lambda: True)
    patch_native(cls, "bind", lambda f: "sandbox")
    monkeypatch.setattr(_native_patch, "_in_workflow_sandbox", lambda: False)
    patch_native(cls, "bind", _host)
    assert cls.bind is _host


def test_sandbox_first_bind_keeps_public_signature(cls, monkeypatch):
    """The first patch must accept every public ``Warrant.bind`` argument."""
    monkeypatch.setattr(_native_patch, "_in_workflow_sandbox", lambda: True)
    patch_native(cls, "bind", BoundWarrant.bind_warrant, if_missing=True)

    roots = [object()]
    bound = cls().bind(object(), trusted_roots=roots)

    assert isinstance(bound, BoundWarrant)
    assert bound._trusted_roots is roots


def test_if_missing_keeps_native_attribute(cls):
    patch_native(cls, "native_method", lambda self: "patched", if_missing=True)
    assert cls().native_method() == "native"


def test_native_original_survives_rewrapping(cls):
    original = native_original(cls, "native_method")
    patch_native(cls, "native_method", lambda self: "wrapped:" + original(self))
    again = native_original(cls, "native_method")
    patch_native(cls, "native_method", lambda self: "wrapped:" + again(self))
    assert cls().native_method() == "wrapped:native"


def test_not_in_sandbox_on_host_thread():
    assert _native_patch._in_workflow_sandbox() is False
