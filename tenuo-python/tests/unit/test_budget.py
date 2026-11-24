"""Token budgets: the stores, the meter, and what the core does with the constraint."""

import threading
import time
from types import SimpleNamespace

import pytest

from tenuo import SigningKey, Warrant
from tenuo._enforcement import enforce_tool_call
from tenuo.budget import (
    BudgetExceeded,
    BudgetStore,
    InMemoryBudgetBackend,
    ModelCallDenied,
    SqliteBudgetBackend,
    TokenMeter,
    estimate_input_tokens,
    llm_capability,
    usage_counts,
)

MODEL = "gpt-4o-mini"
REQUEST = {"model": MODEL, "messages": [{"role": "user", "content": "hello there"}]}


def fixed_estimate(tokens):
    return lambda request: tokens


@pytest.fixture
def keys():
    return SimpleNamespace(issuer=SigningKey.generate(), lead=SigningKey.generate(), worker=SigningKey.generate())


def mint_root(keys, **caps):
    return (
        Warrant.mint_builder()
        .capability("llm.chat", llm_capability(**caps))
        .holder(keys.lead.public_key)
        .ttl(3600)
        .mint(keys.issuer)
    )


def grant(parent, keys, holder=None, **caps):
    return (
        parent.grant_builder()
        .capability("llm.chat", llm_capability(**caps))
        .holder((holder or keys.worker).public_key)
        .ttl(600)
        .grant(keys.lead)
    )


def authorizer(warrant, key, issuer, chain=None):
    """The check an adapter runs for the caller's own warrant."""

    def authorize(tool, args):
        return enforce_tool_call(
            tool_name=tool,
            tool_args=args,
            bound_warrant=warrant.bind(key),
            trusted_roots=[issuer.public_key],
            warrant_chain=chain,
        )

    return authorize


# ---------------------------------------------------------------------------
# The constraint is an ordinary one: the core narrows it on delegation
# ---------------------------------------------------------------------------


class TestWarrantSide:
    def test_capability_fields(self):
        caps = llm_capability(total_tokens=1000, max_tokens=100, models=[MODEL])
        assert set(caps) == {"total_tokens", "max_tokens", "model"}
        assert llm_capability() == {}

    @pytest.mark.parametrize("bad", [0, -5, 1.5, True, "100"])
    def test_rejects_non_positive_integers(self, bad):
        with pytest.raises(ValueError):
            llm_capability(total_tokens=bad)

    def test_child_cannot_widen_the_total(self, keys):
        root = mint_root(keys, total_tokens=1000)
        with pytest.raises(Exception, match="(?i)range|monoton"):
            grant(root, keys, total_tokens=1001)

    def test_child_cannot_drop_the_total(self, keys):
        root = mint_root(keys, total_tokens=1000, max_tokens=100)
        with pytest.raises(Exception, match="(?i)missing|monoton"):
            grant(root, keys, max_tokens=100)

    def test_ranges_start_at_zero_so_a_zero_based_parent_can_be_narrowed(self, keys):
        from tenuo import Range

        caps = llm_capability(total_tokens=1000, max_tokens=100)
        assert (caps["total_tokens"].min, caps["total_tokens"].max) == (0, 1000)
        assert (caps["max_tokens"].min, caps["max_tokens"].max) == (0, 100)
        # A parent whose budget is written "0..N", as Tenuo Cloud issues it.
        parent = (
            Warrant.mint_builder()
            .capability("llm.chat", {"total_tokens": Range(min=0, max=1000)})
            .holder(keys.lead.public_key).ttl(3600).mint(keys.issuer)
        )
        child = grant(parent, keys, total_tokens=400)
        assert child.capabilities["llm.chat"]["total_tokens"].max == 400
        # And one written with no lower bound at all.
        open_below = (
            Warrant.mint_builder()
            .capability("llm.chat", {"total_tokens": Range(max=1000)})
            .holder(keys.lead.public_key).ttl(3600).mint(keys.issuer)
        )
        assert grant(open_below, keys, total_tokens=400).capabilities["llm.chat"]["total_tokens"].max == 400

    def test_child_can_narrow_the_total(self, keys):
        root = mint_root(keys, total_tokens=1000)
        child = grant(root, keys, total_tokens=200)
        assert child.capabilities["llm.chat"]["total_tokens"].max == 200


# ---------------------------------------------------------------------------
# Stores
# ---------------------------------------------------------------------------


@pytest.fixture(params=["memory", "sqlite"])
def backend(request, tmp_path):
    if request.param == "memory":
        return InMemoryBudgetBackend()
    return SqliteBudgetBackend(str(tmp_path / "budgets.db"))


class TestBackends:
    def test_add_returns_new_totals(self, backend):
        assert backend.add({"a": 10, "b": 3}, {}) == {"a": 10, "b": 3}
        assert backend.add({"a": 5}, {}) == {"a": 15}
        assert backend.used(["a", "b", "never"]) == {"a": 15, "b": 3, "never": 0}

    def test_total_never_goes_below_zero(self, backend):
        backend.add({"a": 10}, {})
        assert backend.add({"a": -25}, {}) == {"a": 0}
        assert backend.add({"new": -5}, {}) == {"new": 0}

    def test_expired_rows_are_dropped(self, backend):
        backend.add({"old": 10}, {"old": time.time() - 1})
        backend.add({"live": 1}, {"live": time.time() + 600})
        assert backend.used(["old", "live"]) == {"old": 0, "live": 1}

    def test_concurrent_adds_are_all_counted(self, backend):
        errors = []

        def spend():
            try:
                for _ in range(25):
                    backend.add({"a": 1, "b": 2}, {})
            except Exception as e:  # a thread's exception would otherwise be lost
                errors.append(e)

        threads = [threading.Thread(target=spend) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert errors == []
        assert backend.used(["a", "b"]) == {"a": 200, "b": 400}

    def test_busy_file_is_retried_until_it_frees_up(self, tmp_path):
        import sqlite3

        path = str(tmp_path / "budgets.db")
        backend = SqliteBudgetBackend(path, timeout_seconds=10)
        holder = sqlite3.connect(path, isolation_level=None, check_same_thread=False)
        holder.execute("BEGIN IMMEDIATE")  # another writer holds the file

        def let_go():
            time.sleep(0.3)
            holder.execute("COMMIT")
            holder.close()

        releaser = threading.Thread(target=let_go)
        releaser.start()
        try:
            assert backend.add({"a": 7}, {}) == {"a": 7}
        finally:
            releaser.join()

    def test_file_that_stays_busy_raises(self, tmp_path):
        import sqlite3

        path = str(tmp_path / "budgets.db")
        backend = SqliteBudgetBackend(path, timeout_seconds=0.2)
        holder = sqlite3.connect(path, isolation_level=None)
        holder.execute("BEGIN IMMEDIATE")
        try:
            with pytest.raises(sqlite3.OperationalError):
                backend.add({"a": 1}, {})
        finally:
            holder.execute("ROLLBACK")
            holder.close()
        assert backend.used(["a"]) == {"a": 0}


class TestBudgetStore:
    def test_path_makes_a_file_shared_between_instances(self, tmp_path):
        path = str(tmp_path / "budgets.db")
        BudgetStore(path).add({"w": 40})
        assert BudgetStore(path).used("w") == {"w": 40}

    def test_path_and_backend_together_are_refused(self, tmp_path):
        with pytest.raises(ValueError):
            BudgetStore(str(tmp_path / "x.db"), backend=InMemoryBudgetBackend())

    def test_unusable_file_raises(self, tmp_path):
        with pytest.raises(Exception):
            BudgetStore(str(tmp_path / "missing-dir" / "budgets.db"))

    def test_totals_from_a_write_include_usage_owed_meanwhile(self):
        class Meanwhile(InMemoryBudgetBackend):
            def add(self, deltas, expires_at):
                store.owe({"w": 50})  # another call's usage fails to be written during this write
                return super().add(deltas, expires_at)

        store = BudgetStore(backend=Meanwhile())
        assert store.add({"w": 10}) == {"w": 60} and store.used("w") == {"w": 60}

    def test_owed_usage_is_written_once_by_concurrent_writers(self):
        entered, go = threading.Event(), threading.Event()

        class Slow(InMemoryBudgetBackend):
            def add(self, deltas, expires_at):
                if not entered.is_set():
                    entered.set()
                    go.wait(5)  # the first writer is held inside its write
                return super().add(deltas, expires_at)

        store = BudgetStore(backend=Slow())
        store.owe({"w": 100})
        first = threading.Thread(target=store.add, args=({"w": 1},))
        second = threading.Thread(target=store.add, args=({"w": 1},))
        first.start()
        assert entered.wait(5)
        second.start()
        time.sleep(0.05)  # the second writer arrives while the first is still writing
        go.set()
        first.join(5)
        second.join(5)
        assert store.used("w") == {"w": 102}


# ---------------------------------------------------------------------------
# Usage shapes and the estimate
# ---------------------------------------------------------------------------


class TestUsage:
    def test_chat_completions_shape(self):
        usage = SimpleNamespace(prompt_tokens=10, completion_tokens=5, total_tokens=15)
        assert usage_counts(usage) == {"input_tokens": 10, "output_tokens": 5, "total_tokens": 15}

    def test_responses_shape_as_dict(self):
        assert usage_counts({"input_tokens": 7, "output_tokens": 2}) == {
            "input_tokens": 7, "output_tokens": 2, "total_tokens": 9,
        }

    def test_thinking_left_out_of_the_completion_count_is_output(self):
        usage = {"prompt_tokens": 9, "completion_tokens": 3, "total_tokens": 58}
        assert usage_counts(usage) == {"input_tokens": 9, "output_tokens": 49, "total_tokens": 58}

    @pytest.mark.parametrize("usage", [None, {}, SimpleNamespace(), {"total_tokens": -1}, {"total_tokens": True}])
    def test_no_usable_count(self, usage):
        assert usage_counts(usage) is None

    def test_estimate_grows_with_the_prompt(self):
        short = estimate_input_tokens(REQUEST)
        long = estimate_input_tokens({"messages": [{"role": "user", "content": "word " * 400}]})
        assert 0 < short < long
        assert long >= 400  # at least one token per word here
        assert estimate_input_tokens({"model": MODEL}) == 0


# ---------------------------------------------------------------------------
# The meter
# ---------------------------------------------------------------------------


class TestMeter:
    def test_reserves_then_settles_to_the_real_count(self, keys):
        root = mint_root(keys, total_tokens=1000, max_tokens=200, models=[MODEL])
        meter = TokenMeter(input_estimator=fixed_estimate(30))
        call = meter.begin(root, None, REQUEST, requested_output=None,
                           authorize=authorizer(root, keys.lead, keys.issuer))
        assert call.max_output == 200  # the warrant's per-call cap
        assert call.reserved == 230
        assert meter.store.used(root.id) == {root.id: 230}

        record = call.settle(SimpleNamespace(prompt_tokens=25, completion_tokens=40, total_tokens=65))
        assert meter.store.used(root.id) == {root.id: 65}
        assert record["total_tokens"] == 65
        assert record["budget"] == [{"warrant_id": root.id, "used": 65, "limit": 1000}]
        assert "estimated" not in record and "over_budget" not in record

    def test_output_cap_is_lowered_to_what_is_left(self, keys):
        root = mint_root(keys, total_tokens=500)
        meter = TokenMeter(input_estimator=fixed_estimate(20))
        meter.store.add({root.id: 400})
        call = meter.begin(root, None, REQUEST, requested_output=300,
                           authorize=authorizer(root, keys.lead, keys.issuer))
        assert call.max_output == 80
        assert call.clamped
        assert call.settle({"total_tokens": 100})["clamped"] is True

    def test_choices_share_the_room(self, keys):
        root = mint_root(keys, total_tokens=320)
        meter = TokenMeter(input_estimator=fixed_estimate(20))
        call = meter.begin(root, None, REQUEST, requested_output=500, choices=3,
                           authorize=authorizer(root, keys.lead, keys.issuer))
        assert call.max_output == 100
        assert call.reserved == 320

    def test_refused_when_the_total_is_reached_and_nothing_stays_reserved(self, keys):
        root = mint_root(keys, total_tokens=500)
        meter = TokenMeter(input_estimator=fixed_estimate(20))
        meter.store.add({root.id: 490})
        with pytest.raises(BudgetExceeded) as err:
            meter.begin(root, None, REQUEST, requested_output=None,
                        authorize=authorizer(root, keys.lead, keys.issuer))
        assert err.value.own and err.value.limit == 500 and err.value.used == 490
        assert "this warrant allows 500 tokens" in str(err.value)
        assert meter.store.used(root.id) == {root.id: 490}

    def test_the_core_makes_the_decision(self, keys):
        """The meter refuses only what the warrant check refuses."""
        root = mint_root(keys, total_tokens=500)
        meter = TokenMeter(input_estimator=fixed_estimate(20))
        meter.store.add({root.id: 490})
        seen = []

        def always_allow(tool, args):
            seen.append(args)
            return SimpleNamespace(allowed=True)

        call = meter.begin(root, None, REQUEST, requested_output=None, authorize=always_allow)
        assert seen == [{"total_tokens": 511}]  # only the constrained field is passed
        assert call.reserved == 21

    def test_workers_share_the_parent_total(self, keys):
        other = SigningKey.generate()
        root = mint_root(keys, total_tokens=300)
        one = grant(root, keys, total_tokens=250)
        two = grant(root, keys, holder=other, total_tokens=250)
        meter = TokenMeter(input_estimator=fixed_estimate(10))

        first = meter.begin(one, [root], REQUEST, requested_output=190,
                            authorize=authorizer(one, keys.worker, keys.issuer, [root]))
        first.settle({"total_tokens": 200})
        second = meter.begin(two, [root], REQUEST, requested_output=190,
                             authorize=authorizer(two, other, keys.issuer, [root]))
        assert second.max_output == 90  # 300 - 200 already spent by the other worker - 10 input
        second.settle({"total_tokens": 100})
        assert meter.store.used(root.id, one.id, two.id) == {root.id: 300, one.id: 200, two.id: 100}

        with pytest.raises(BudgetExceeded) as err:
            meter.begin(two, [root], REQUEST, requested_output=None,
                        authorize=authorizer(two, other, keys.issuer, [root]))
        assert not err.value.own and err.value.warrant_id == root.id
        assert "delegated from" in str(err.value)
        assert meter.store.used(root.id, two.id) == {root.id: 300, two.id: 100}

    def test_without_the_parents_only_the_own_total_holds(self, keys):
        root = mint_root(keys, total_tokens=100)
        child = grant(root, keys, total_tokens=100)
        meter = TokenMeter(input_estimator=fixed_estimate(10))
        meter.store.add({root.id: 100})
        call = meter.begin(child, None, REQUEST, requested_output=50, authorize=lambda t, a: SimpleNamespace(allowed=True))
        assert [lv.warrant_id for lv in call.levels] == [child.id]

    def test_other_refusals_are_not_budget_errors(self, keys):
        root = mint_root(keys, total_tokens=1000, models=[MODEL])
        meter = TokenMeter(input_estimator=fixed_estimate(10))
        with pytest.raises(ModelCallDenied) as err:
            meter.begin(root, None, {**REQUEST, "model": "gpt-4o"}, requested_output=None,
                        authorize=authorizer(root, keys.lead, keys.issuer))
        assert err.value.result.constraint_violated == "model"
        assert meter.store.used(root.id) == {root.id: 0}

    @pytest.mark.parametrize("label", ["starts above zero", "exactly N", "no upper bound", "not a range"])
    def test_a_budget_that_cannot_be_metered_is_refused_outright(self, keys, label):
        from tenuo import OneOf, Range

        constraint = {
            "starts above zero": Range(min=500, max=2000),
            "exactly N": Range(min=800, max=800),
            "no upper bound": Range(min=0),
            "not a range": OneOf([100, 200]),
        }[label]
        warrant = (
            Warrant.mint_builder()
            .capability("llm.chat", {"total_tokens": constraint})
            .holder(keys.lead.public_key).ttl(3600).mint(keys.issuer)
        )
        meter = TokenMeter(input_estimator=fixed_estimate(10))

        def must_not_run(tool, args):
            raise AssertionError("an unusable budget must be refused before the warrant check")

        with pytest.raises(ModelCallDenied, match="not usable") as err:
            meter.begin(warrant, None, REQUEST, requested_output=None, authorize=must_not_run)
        assert err.value.result.constraint_violated == "total_tokens"
        assert meter.store.used(warrant.id) == {warrant.id: 0}

    def test_a_parents_unusable_budget_refuses_the_child_too(self, keys):
        from tenuo import Range

        parent = (
            Warrant.mint_builder()
            .capability("llm.chat", {"total_tokens": Range(min=100, max=1000)})
            .holder(keys.lead.public_key).ttl(3600).mint(keys.issuer)
        )
        child = (
            parent.grant_builder().capability("llm.chat", {"total_tokens": Range(min=100, max=500)})
            .holder(keys.worker.public_key).ttl(600).grant(keys.lead)
        )
        with pytest.raises(ModelCallDenied, match="start at 0"):
            TokenMeter().begin(child, [parent], REQUEST, requested_output=None, authorize=lambda t, a: None)

    def test_monitor_only_counts_even_an_unusable_budget(self, keys):
        from tenuo import Range

        warrant = (
            Warrant.mint_builder()
            .capability("llm.chat", {"total_tokens": Range(min=500, max=2000)})
            .holder(keys.lead.public_key).ttl(3600).mint(keys.issuer)
        )
        meter = TokenMeter(enforce=False)
        meter.begin(warrant, None, REQUEST, requested_output=None, authorize=lambda t, a: None).settle({"total_tokens": 40})
        assert meter.store.used(warrant.id) == {warrant.id: 40}

    def test_warrant_without_the_capability_is_refused(self, keys):
        other = Warrant.mint_builder().capability("search").holder(keys.lead.public_key).ttl(600).mint(keys.issuer)
        meter = TokenMeter()
        with pytest.raises(ModelCallDenied) as err:
            meter.begin(other, None, REQUEST, requested_output=None,
                        authorize=authorizer(other, keys.lead, keys.issuer))
        assert err.value.result.error_type == "tool_not_allowed"

    def test_capability_without_a_total_is_counted_but_not_limited(self, keys):
        root = mint_root(keys)
        meter = TokenMeter(input_estimator=fixed_estimate(10))
        call = meter.begin(root, None, REQUEST, requested_output=None,
                           authorize=authorizer(root, keys.lead, keys.issuer))
        assert call.max_output == 4096
        record = call.settle({"total_tokens": 1234})
        assert record["budget"] == [{"warrant_id": root.id, "used": 1234}]

    def test_release_gives_the_reservation_back(self, keys):
        root = mint_root(keys, total_tokens=1000)
        meter = TokenMeter(input_estimator=fixed_estimate(10))
        call = meter.begin(root, None, REQUEST, requested_output=100,
                           authorize=authorizer(root, keys.lead, keys.issuer))
        call.release()
        call.settle({"total_tokens": 999})  # ignored: the first outcome stands
        assert meter.store.used(root.id) == {root.id: 0}

    def test_settle_without_usage_keeps_the_reservation(self, keys):
        root = mint_root(keys, total_tokens=1000)
        meter = TokenMeter(input_estimator=fixed_estimate(10))
        call = meter.begin(root, None, REQUEST, requested_output=100,
                           authorize=authorizer(root, keys.lead, keys.issuer))
        record = call.settle(None)
        assert record["estimated"] is True and record["total_tokens"] == 110
        assert meter.store.used(root.id) == {root.id: 110}

    def test_low_estimate_can_pass_the_total_and_the_record_says_so(self, keys):
        root = mint_root(keys, total_tokens=100)
        meter = TokenMeter(input_estimator=fixed_estimate(10))
        call = meter.begin(root, None, REQUEST, requested_output=90,
                           authorize=authorizer(root, keys.lead, keys.issuer))
        record = call.settle({"prompt_tokens": 40, "completion_tokens": 90, "total_tokens": 130})
        assert record["over_budget"] == [root.id]
        with pytest.raises(BudgetExceeded):
            meter.begin(root, None, REQUEST, requested_output=None,
                        authorize=authorizer(root, keys.lead, keys.issuer))

    def test_monitor_only_counts_and_flags(self, keys):
        root = mint_root(keys, total_tokens=100)
        meter = TokenMeter(enforce=False)

        def must_not_run(tool, args):
            raise AssertionError("monitor mode must not authorize")

        for _ in range(2):
            call = meter.begin(root, None, REQUEST, requested_output=None, authorize=must_not_run)
            assert call.max_output is None and call.reserved == 0
            record = call.settle({"total_tokens": 80})
        assert record["over_budget"] == [root.id]
        assert meter.store.used(root.id) == {root.id: 160}

    def test_store_failure_blocks_the_call(self, keys):
        class Broken:
            def add(self, deltas, expires_at):
                raise OSError("disk gone")

            def used(self, keys):
                return {k: 0 for k in keys}

        root = mint_root(keys, total_tokens=100)
        meter = TokenMeter(BudgetStore(backend=Broken()))
        with pytest.raises(OSError):
            meter.begin(root, None, REQUEST, requested_output=None, authorize=lambda t, a: SimpleNamespace(allowed=True))

    def test_concurrent_calls_cannot_spend_past_the_total(self, keys, tmp_path):
        root = mint_root(keys, total_tokens=500)
        meter = TokenMeter(str(tmp_path / "budgets.db"), input_estimator=fixed_estimate(0))
        allowed, refused = [], []

        def one_call():
            try:
                call = meter.begin(root, None, REQUEST, requested_output=100,
                                   authorize=authorizer(root, keys.lead, keys.issuer))
            except BudgetExceeded:
                refused.append(1)
                return
            allowed.append(call.max_output)
            call.settle({"total_tokens": call.max_output})

        threads = [threading.Thread(target=one_call) for _ in range(20)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert len(allowed) + len(refused) == 20
        assert sum(allowed) <= 500
        assert meter.store.used(root.id)[root.id] == sum(allowed)

    def test_coerce(self, tmp_path):
        meter = TokenMeter()
        assert TokenMeter.coerce(meter) is meter
        assert TokenMeter.coerce(None) is None
        assert isinstance(TokenMeter.coerce(BudgetStore()), TokenMeter)
        assert isinstance(TokenMeter.coerce(str(tmp_path / "b.db")), TokenMeter)
        with pytest.raises(TypeError):
            TokenMeter.coerce(42)


class TestMediaEstimate:
    BLOB = "A" * 300_000  # a picture or a clip, as base64
    TEXT = {"type": "text", "text": "what is this?"}

    def plain(self):
        return estimate_input_tokens({"messages": [{"role": "user", "content": [self.TEXT]}]})

    @pytest.mark.parametrize("part", [
        {"type": "image_url", "image_url": {"url": "data:image/png;base64," + BLOB}},
        {"type": "image_url", "image_url": {"url": "https://example.test/cat.png"}},
        {"type": "input_image", "image_url": "data:image/jpeg;base64," + BLOB},
        {"type": "input_image", "file_id": "file_123"},
        {"type": "image", "source": {"type": "base64", "media_type": "image/png", "data": BLOB}},
        {"inlineData": {"mimeType": "image/png", "data": BLOB}},
        {"inline_data": {"mime_type": "image/png", "data": BLOB}},
        {"fileData": {"mimeType": "image/png", "fileUri": "gs://bucket/cat.png"}},
    ])
    def test_an_image_is_reserved_at_one_figure_whatever_its_bytes(self, part):
        from tenuo.budget import IMAGE_TOKEN_ESTIMATE

        estimate = estimate_input_tokens({"messages": [{"role": "user", "content": [self.TEXT, part]}]})
        assert IMAGE_TOKEN_ESTIMATE <= estimate <= IMAGE_TOKEN_ESTIMATE + self.plain() + 40

    @pytest.mark.parametrize("part", [
        {"type": "input_audio", "input_audio": {"data": BLOB, "format": "wav"}},
        {"inlineData": {"mimeType": "audio/mp3", "data": BLOB}},
    ])
    def test_inline_audio_is_reserved_by_its_length(self, part):
        estimate = estimate_input_tokens({"messages": [{"role": "user", "content": [self.TEXT, part]}]})
        assert 300 <= estimate - self.plain() <= 340

    def test_text_and_documents_are_still_estimated_from_their_bytes(self):
        text = {"messages": [{"role": "user", "content": "x" * 3000}]}
        assert 1000 <= estimate_input_tokens(text) <= 1040
        # A word that only looks like a part type does not make its neighbours free.
        tool_call = {"messages": [{"role": "assistant", "content": [{"type": "tool_use", "input": {"type": "image", "note": "y" * 3000}}]}]}
        assert estimate_input_tokens(tool_call) > 1000
        document = {"messages": [{"role": "user", "content": [
            {"type": "document", "source": {"type": "base64", "media_type": "application/pdf", "data": self.BLOB}}]}]}
        assert estimate_input_tokens(document) > 100_000


class TestStatus:
    def test_status_and_remaining_follow_the_chain(self, keys):
        root = mint_root(keys, total_tokens=5000)
        worker = grant(root, keys, total_tokens=2000)
        meter = TokenMeter()
        assert meter.remaining(root) == 5000 and meter.remaining(worker, [root]) == 2000
        meter.store.add({root.id: 1200, worker.id: 1200})
        assert meter.status(worker, [root]) == [
            {"warrant_id": root.id, "used": 1200, "limit": 5000, "remaining": 3800, "delegated_from": True},
            {"warrant_id": worker.id, "used": 1200, "limit": 2000, "remaining": 800},
        ]
        meter.store.add({root.id: 3500})  # another delegate spends from the parent
        assert meter.remaining(worker, [root]) == 300
        meter.store.add({root.id: 900})
        assert meter.remaining(worker, [root]) == 0

    def test_a_warrant_without_a_total_has_no_remaining_figure(self, keys):
        warrant = (Warrant.mint_builder().capability("llm.chat", {})
                   .holder(keys.lead.public_key).ttl(600).mint(keys.issuer))
        meter = TokenMeter()
        assert meter.remaining(warrant) is None and "remaining" not in meter.status(warrant)[0]
