import tenuo


def test_import():
    """Verify that tenuo can be imported and exposes version."""
    assert tenuo.__version__ is not None
    assert isinstance(tenuo.__version__, str)


def test_core_types_exposed():
    """Verify that core types are exposed at the top level."""
    assert tenuo.SigningKey is not None
    assert tenuo.Warrant is not None
