"""The default FastAPI argument view matches what the handler receives."""

from typing import List

import pytest

pytest.importorskip("fastapi")

from fastapi import Depends, FastAPI, Query, Request  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from tenuo.fastapi import _default_extract_args  # noqa: E402

app = FastAPI()


def tag_filter(tags: List[str] = Query(default=[])) -> List[str]:
    return tags


@app.get("/files/{name}")
def read_file(name: str, request: Request):
    return {"handler": name, "authorized": _default_extract_args(request)}


@app.get("/items/{item_id}")
def read_item(item_id: int, request: Request, limit: int = 10):
    return {"handler": [item_id, limit], "authorized": _default_extract_args(request)}


@app.get("/search")
def search(request: Request, tags: List[str] = Depends(tag_filter)):
    return {"handler": tags, "authorized": _default_extract_args(request)}


client = TestClient(app)


def scalar_tag(tags: str = Query()):
    return tags


@app.get("/ambiguous-query")
def ambiguous_query(request: Request, scalar=Depends(scalar_tag), tags=Depends(tag_filter)):
    return _default_extract_args(request)


def query_name(value: str = Query(alias="name")):
    return value


@app.get("/ambiguous-path/{name}")
def ambiguous_path(name: str, request: Request, query=Depends(query_name)):
    return _default_extract_args(request)


def shared_limit(limit: int = 10):
    return limit


@app.get("/shared-query")
def shared_query(request: Request, limit: int = 10, same=Depends(shared_limit)):
    return _default_extract_args(request)


@pytest.mark.parametrize("path,params", [
    ("/ambiguous-query", [("tags", "secret"), ("tags", "public")]),
    ("/ambiguous-path/public", {"name": "secret"}),
])
def test_conflicting_argument_views_require_an_explicit_extractor(path, params):
    response = client.get(path, params=params)
    assert response.status_code == 400
    assert "Ambiguous argument" in response.json()["detail"]


def test_identical_dependency_argument_views_remain_supported():
    response = client.get("/shared-query", params={"limit": "5"})
    assert response.status_code == 200
    assert response.json() == {"limit": 5}


def test_query_param_cannot_shadow_a_path_param():
    body = client.get("/files/secret-keys", params={"name": "public-x"}).json()
    assert body["handler"] == "secret-keys"
    assert body["authorized"] == {"name": "secret-keys"}


def test_typed_path_param_keeps_its_value_and_type_when_the_query_repeats_it():
    body = client.get("/items/7", params={"item_id": "1", "limit": "5"}).json()
    assert body["handler"] == [7, 5]
    assert body["authorized"] == {"item_id": 7, "limit": 5}


def test_list_query_param_in_a_dependency_is_checked_with_every_value():
    body = client.get("/search", params=[("tags", "secret-hr"), ("tags", "public-x")]).json()
    assert body["handler"] == ["secret-hr", "public-x"]
    assert body["authorized"] == {"tags": ["secret-hr", "public-x"]}
