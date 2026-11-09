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
