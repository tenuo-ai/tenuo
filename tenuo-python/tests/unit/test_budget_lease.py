"""Token budgets handed out in leases, with a stand-in issuer and no network."""

import asyncio
import base64
import gc
import json
import os
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from types import SimpleNamespace

import httpx
import pytest

from tenuo import SigningKey, Warrant, warrant_scope
from tenuo.budget import TokenMeter, llm_capability
from tenuo.budget_http import install, uninstall
import tenuo.budget_http
from tenuo.budget_lease import CloudLeases, Lease, LeasedBudget, LeaseUnavailable, lease_return_message

MODEL = "gpt-4o-mini"
INPUT = 30
URL = "https://api.openai.com/v1/chat/completions"
BODY = {"model": MODEL, "messages": [{"role": "user", "content": "hello"}], "max_completion_tokens": 100}


class Provider:
    """A chat endpoint that generates up to 100 tokens and reports its usage."""

    def __init__(self):
        self.caps, self.billed = [], 0

    def __call__(self, request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        cap = body.get("max_completion_tokens") or 10**9
        self.caps.append(cap)
        out = min(100, cap)
        self.billed += INPUT + out
        return httpx.Response(200, json={
            "choices": [{"message": {"content": "ok"}}],
            "usage": {"prompt_tokens": INPUT, "completion_tokens": out, "total_tokens": INPUT + out},
        })


class Pool:
    """An issuer with one budget, handed out in slices. A lease is charged in
    full until it is returned, then for what it used."""

    def __init__(self, keys, limit, slice_, clock=None, ttl=600.0):
        self.keys, self.limit, self.slice, self.ttl = keys, limit, slice_, ttl
        self.clock = clock or time.time
        self.out, self.spent = {}, 0   # warrant id -> granted
        self.asked, self.returned = 0, []
        self.down = False
        self.retry_in = 3600
        self.info = {}  # what the issuer says about the budget with each lease

    def charged(self):
        return self.spent + sum(self.out.values())

    def acquire(self) -> Lease:
        self.asked += 1
        if self.down:
            raise LeaseUnavailable("the issuer is unreachable")
        grant = min(self.slice, self.limit - self.charged())
        if grant < 1:
            raise LeaseUnavailable("the budget for this period is spent", exhausted=True, retry_at=self.clock() + self.retry_in)
        warrant = (Warrant.mint_builder()
                   .capability("llm.chat", llm_capability(total_tokens=grant, models=[MODEL]))
                   .holder(self.keys.agent.public_key).ttl(3600).mint(self.keys.issuer))
        self.out[str(warrant.id)] = grant
        return Lease(warrant, str(warrant.id), self.clock() + self.ttl, grant, dict(self.info))

    def release(self, warrant_id, usage):
        if self.down:
            raise OSError("the issuer is unreachable")
        del self.out[warrant_id]
        used = sum(u["input_tokens"] + u["output_tokens"] for u in usage)
        self.spent += used
        self.returned.append((warrant_id, used))


@pytest.fixture
def keys():
    return SimpleNamespace(issuer=SigningKey.generate(), agent=SigningKey.generate())


@pytest.fixture
def leased(keys):
    made = []

    def do(pool, **options):
        budget = LeasedBudget(pool, **options)
        meter = install(lease=budget, signing_key=keys.agent, trusted_roots=[keys.issuer.public_key],
                        budget_store=TokenMeter(input_estimator=lambda request: INPUT))
        made.append(budget)
        return budget, meter

    yield do
    uninstall()


def call(provider, body=BODY):
    return httpx.Client(transport=httpx.MockTransport(provider)).post(URL, json=body)


def refused(response):
    return response.status_code == 403 and response.json()["error"]["code"] == "token_budget_exceeded"


class TestLeasedBudget:
    def test_calls_run_across_leases_and_the_budget_is_spent_exactly(self, keys, leased):
        pool = Pool(keys, limit=1000, slice_=400)
        budget, _ = leased(pool)
        provider = Provider()
        results = [call(provider) for _ in range(9)]

        # 130 tokens a call: three fit a 400 lease, twice; then the 220 left
        # take one whole call and one cut to what remains.
        assert [r.status_code for r in results[:8]] == [200] * 8 and refused(results[8])
        assert provider.caps == [100] * 7 + [60]
        assert "spent" in results[8].json()["error"]["message"]
        budget.close()
        assert provider.billed == pool.spent == 1000 and not pool.out
        assert [used for _, used in pool.returned] == [390, 390, 130, 90]

    def test_a_call_moves_to_the_next_lease_instead_of_being_cut_short(self, keys, leased):
        pool = Pool(keys, limit=10_000, slice_=300)
        leased(pool)
        provider = Provider()
        for _ in range(6):
            assert call(provider).status_code == 200
        # 300 holds two calls of 130; the 40 left over go back, not into a 10-token answer.
        assert provider.caps == [100] * 6 and [used for _, used in pool.returned] == [260, 260]

    def test_a_fresh_lease_too_small_for_the_call_is_not_swapped_for_another(self, keys, leased):
        pool = Pool(keys, limit=10_000, slice_=80)
        leased(pool)
        provider = Provider()
        assert call(provider).status_code == 200
        assert provider.caps == [50] and pool.asked == 1  # cut to the lease, no second lease taken

    def test_a_lease_about_to_expire_is_replaced_and_returned(self, keys, leased):
        now = [1_000_000.0]
        pool = Pool(keys, limit=10_000, slice_=1000, clock=lambda: now[0], ttl=60)
        budget, _ = leased(pool, renew_before=15, clock=lambda: now[0])
        provider = Provider()
        call(provider)
        first = budget.current.warrant_id
        now[0] += 40
        call(provider)
        assert budget.current.warrant_id == first
        now[0] += 10  # 10 seconds of life left: not enough to start a call on
        call(provider)
        assert budget.current.warrant_id != first and pool.returned == [(first, 260)]

    def test_a_spent_budget_is_not_asked_about_on_every_call(self, keys, leased):
        now = [1_000_000.0]
        pool = Pool(keys, limit=130, slice_=130, clock=lambda: now[0])
        leased(pool, recheck_after=30, clock=lambda: now[0])
        provider = Provider()
        assert call(provider).status_code == 200
        assert all(refused(call(provider)) for _ in range(5))
        assert pool.asked == 2 and len(provider.caps) == 1  # one lease, one "no"; refusals never reach the provider
        pool.limit = 1000  # the budget was raised, or the period turned over
        assert refused(call(provider))
        now[0] += 31
        assert call(provider).status_code == 200

    def test_no_lease_no_call(self, keys, leased):
        pool = Pool(keys, limit=1000, slice_=400)
        pool.down = True
        leased(pool)
        provider = Provider()
        response = call(provider)
        assert refused(response) and "unreachable" in response.json()["error"]["message"] and not provider.caps

    def test_a_lease_that_cannot_be_returned_is_kept_and_used(self, keys, leased):
        pool = Pool(keys, limit=10_000, slice_=300)
        budget, _ = leased(pool, recheck_after=0)
        provider = Provider()
        call(provider), call(provider)
        held = budget.current.warrant_id
        pool.down = True
        # 40 tokens are left on the lease and the issuer is away: the call runs on them.
        assert call(provider).status_code == 200 and provider.caps[-1] == 10
        assert budget.current.warrant_id == held and held in pool.out
        pool.down = False
        assert call(provider).status_code == 200  # returned at last, with all it used
        assert pool.returned == [(held, 300)]

    def test_a_call_in_flight_keeps_its_lease_out_until_it_ends(self, keys):
        pool = Pool(keys, limit=10_000, slice_=300)
        budget = LeasedBudget(pool)
        budget.warrant()
        first = budget.current.warrant_id
        budget.enter([first])
        assert budget.renew(first) is True and budget.current.warrant_id != first
        assert first in pool.out  # still charged in full: its call has not finished
        budget.exit([first], MODEL, {"input_tokens": 30, "output_tokens": 70})
        assert pool.returned == [(first, 100)]
        budget.exit([first], MODEL, {"input_tokens": 1, "output_tokens": 1})  # a stray second exit
        assert pool.returned == [(first, 100)]

    def test_nothing_starts_on_a_lease_that_is_being_returned(self, keys):
        # A thread can take the lease's warrant and lose the processor before
        # its call is admitted. If the lease is returned meanwhile, the call
        # must not run under it: its tokens would never be reported.
        pool = Pool(keys, limit=10_000, slice_=300)
        budget = LeasedBudget(pool)
        budget.warrant()
        first = budget.current.warrant_id
        assert budget.enter([first]) is True
        budget.exit([first], MODEL, {"input_tokens": 30, "output_tokens": 100})
        budget.renew(first)  # idle, so it goes back at once
        assert pool.returned == [(first, 130)]
        assert budget.enter([first]) is False
        assert budget.enter(["some-other-warrant", first]) is False  # also as a parent of a delegated warrant
        assert budget.enter([budget.current.warrant_id]) is True

    def test_many_threads_share_the_leases_and_never_pass_the_budget(self, keys, leased):
        pool = Pool(keys, limit=5000, slice_=500)
        lock = threading.Lock()
        acquire, release = pool.acquire, pool.release
        pool.acquire = lambda: _locked(lock, acquire)
        pool.release = lambda *a: _locked(lock, release, *a)
        budget, _ = leased(pool)
        provider = Provider()
        outcomes = []

        def work():
            for _ in range(6):
                outcomes.append(call(provider).status_code)

        threads = [threading.Thread(target=work) for _ in range(10)]
        [t.start() for t in threads]
        [t.join() for t in threads]
        budget.close()
        assert provider.billed == pool.spent <= 5000 and not pool.out
        assert outcomes.count(200) == len(provider.caps) and set(outcomes) <= {200, 403}
        assert pool.spent >= 4500  # the budget is used, not stranded in half-spent leases

    def test_a_warrant_in_scope_is_used_instead_of_the_lease(self, keys, leased):
        pool = Pool(keys, limit=1000, slice_=400)
        leased(pool)
        own = (Warrant.mint_builder().capability("llm.chat", llm_capability(total_tokens=500, models=[MODEL]))
               .holder(keys.agent.public_key).ttl(600).mint(keys.issuer))
        provider = Provider()
        with warrant_scope(own):
            assert call(provider).status_code == 200
        assert pool.asked == 0

    def test_endpoints_the_meter_cannot_count_are_refused_as_without_a_lease(self, keys, leased):
        pool = Pool(keys, limit=1000, slice_=400)
        leased(pool)
        seen = []
        http = httpx.Client(transport=httpx.MockTransport(lambda r: (seen.append(r.url.path), httpx.Response(200, json={}))[1]))
        for path in ("/v1/embeddings", "/v1/batches", "/v1/threads/t/runs", "/v1/messages/batches"):
            refused_ = http.post("https://api.openai.com" + path, json={"model": MODEL, "input": "x"})
            assert refused_.status_code == 403 and refused_.json()["error"]["code"] == "unmetered_endpoint", path
        assert not seen and pool.asked == 0

    def test_a_lease_stays_closed_long_after_it_was_returned(self, keys, leased):
        # A warrant delegated from a lease must not come back to life when the
        # process has taken many leases since and forgotten the old one.
        pool = Pool(keys, limit=10**9, slice_=300)
        budget, _ = leased(pool)
        provider = Provider()
        call(provider)
        first = budget.current.warrant_id
        for _ in range(200):
            call(provider)
        assert len(pool.returned) > 70 and first not in budget._held
        assert budget.enter(["a-delegated-warrant", first]) is False and budget.knows(first)

    def test_a_call_planned_on_a_lease_the_process_left_is_planned_again(self, keys, leased):
        pool = Pool(keys, limit=10_000, slice_=300)
        budget, _ = leased(pool)
        provider = Provider()
        call(provider), call(provider)  # 260 of 300 used
        request = httpx.Request("POST", URL, json=BODY)
        stale, _ = tenuo.budget_http._INSTALLED.core_for(httpx, request)  # a thread that already has the old lease
        assert budget.renew(budget.current.warrant_id) is True              # another thread moves the process on
        plan = stale.plan(request, renew=True)
        assert plan.retry and plan.refusal is None                          # not a final 403: the issuer has budget
        assert call(provider).status_code == 200

    def test_a_fresh_lease_too_small_is_swapped_once_it_has_been_held_a_while(self, keys, leased):
        now = [1_000_000.0]
        pool = Pool(keys, limit=20, slice_=400, clock=lambda: now[0])
        leased(pool, recheck_after=30, clock=lambda: now[0])
        provider = Provider()
        assert refused(call(provider))  # 20 tokens: no call fits
        pool.limit = 10_000              # the issuer has budget again
        assert refused(call(provider)) and pool.asked == 1
        now[0] += 31
        assert call(provider).status_code == 200 and pool.asked == 2

    def test_a_return_that_failed_is_tried_again_without_waiting_for_close(self, keys, leased):
        now = [1_000_000.0]
        pool = Pool(keys, limit=10**6, slice_=300, clock=lambda: now[0])
        budget, _ = leased(pool, recheck_after=30, clock=lambda: now[0])
        provider = Provider()
        call(provider), call(provider)
        first = budget.current.warrant_id
        real, fails = pool.release, [1]

        def flaky(warrant_id, usage):
            if fails:
                fails.pop()
                raise OSError("503")
            real(warrant_id, usage)

        pool.release = flaky
        call(provider)  # 40 left: the process moves on, but telling the issuer fails
        assert first in pool.out and budget.current.warrant_id != first
        call(provider)
        assert first in pool.out  # not hammered: asked again only after a while
        now[0] += 31
        call(provider)
        assert (first, 260) in pool.returned and first not in pool.out

    def test_every_refusal_is_its_own_exception(self, keys):
        pool = Pool(keys, limit=0, slice_=100)
        budget = LeasedBudget(pool)
        caught = []
        for _ in range(3):
            with pytest.raises(LeaseUnavailable) as e:
                budget.warrant()
            caught.append(e.value)
        assert len({id(e) for e in caught}) == 3 and pool.asked == 1 and all(e.exhausted for e in caught)

    def test_a_retry_time_already_past_does_not_mean_ask_every_time(self, keys):
        now = [1_000_000.0]
        pool = Pool(keys, limit=0, slice_=100, clock=lambda: now[0])
        pool.retry_in = -5
        budget = LeasedBudget(pool, clock=lambda: now[0])
        for _ in range(50):
            with pytest.raises(LeaseUnavailable):
                budget.warrant()
        assert pool.asked == 1

    def test_a_long_renew_before_does_not_mean_a_lease_per_call(self, keys, leased):
        pool = Pool(keys, limit=10**6, slice_=5000, ttl=20)
        leased(pool, renew_before=60)
        provider = Provider()
        for _ in range(20):
            call(provider)
        assert pool.asked == 1

    def test_an_issuer_that_raises_something_else_is_still_no_lease(self, keys, leased):
        pool = Pool(keys, limit=1000, slice_=400)
        pool.acquire = lambda: (_ for _ in ()).throw(ValueError("garbled reply"))
        leased(pool)
        provider = Provider()
        response = call(provider)
        assert refused(response) and "garbled reply" in response.json()["error"]["message"] and not provider.caps

    def test_an_interrupt_during_a_return_leaves_the_lease_out(self, keys):
        pool = Pool(keys, limit=1000, slice_=400)
        budget = LeasedBudget(pool)
        budget.warrant()
        first = budget.current.warrant_id
        real = pool.release
        pool.release = lambda *a: (_ for _ in ()).throw(KeyboardInterrupt())
        with pytest.raises(KeyboardInterrupt):
            budget.close()
        pool.release = real
        budget.close()
        assert pool.returned == [(first, 0)]

    @pytest.mark.skipif(not hasattr(os, "fork"), reason="needs fork")
    def test_a_forked_child_leaves_the_parents_lease_alone(self, keys):
        pool = Pool(keys, limit=1000, slice_=400)
        budget = LeasedBudget(pool)
        budget.warrant()
        first = budget.current.warrant_id
        read, write = os.pipe()
        pid = os.fork()
        if pid == 0:  # the child: must neither spend from nor return what the parent holds
            try:
                verdict = budget.current is None and budget.enter([first]) is False
                budget.close()
                os.write(write, b"ok" if verdict and not pool.returned else b"no")
            finally:
                os._exit(0)
        os.waitpid(pid, 0)
        assert os.read(read, 2) == b"ok"
        assert budget.current.warrant_id == first and budget.enter([first]) is True

    def test_taking_a_lease_does_not_hold_the_event_loop(self, keys, leased):
        pool = Pool(keys, limit=10_000, slice_=400)
        slow = pool.acquire
        pool.acquire = lambda: (time.sleep(0.4), slow())[1]
        leased(pool)
        provider = Provider()

        async def main():
            stalls, last = [], time.monotonic()

            async def ticker():
                nonlocal last
                while True:
                    await asyncio.sleep(0.01)
                    stalls.append(time.monotonic() - last)
                    last = time.monotonic()

            task = asyncio.ensure_future(ticker())
            async with httpx.AsyncClient(transport=httpx.MockTransport(provider)) as http:
                response = await http.post(URL, json=BODY)
            task.cancel()
            return response.status_code, max(stalls)

        status, longest = asyncio.run(main())
        assert status == 200 and longest < 0.2, f"the loop stalled for {longest:.2f}s"

    def test_a_stream_dropped_unread_does_not_pin_its_lease(self, keys, leased):
        pool = Pool(keys, limit=10_000, slice_=1000)
        budget, _ = leased(pool)
        sse = b'data: {"choices": [{"index": 0, "delta": {"content": "hi"}}]}\n\ndata: [DONE]\n\n'
        http = httpx.Client(transport=httpx.MockTransport(
            lambda request: httpx.Response(200, headers={"content-type": "text/event-stream"}, content=sse)))
        response = http.send(http.build_request("POST", URL, json={**BODY, "stream": True}), stream=True)
        first = budget.current.warrant_id
        del response
        gc.collect()
        budget.close()
        assert not pool.out and pool.returned == [(first, INPUT + 100)]  # charged its reservation, and returned

    def test_a_refusal_is_said_in_the_budgets_terms(self, keys, leased):
        # What the issuer said with the lease: the period, when it resets, and what the pool has left.
        pool = Pool(keys, limit=10_000, slice_=20)
        pool.info = {"period": "day", "resets_at": "2030-01-02T00:00:00Z", "pool": {"limit": 20, "remaining": 0}}
        leased(pool)
        message = call(Provider()).json()["error"]["message"]
        assert message == ("tenuo: token budget reached: 20 tokens are left in today's budget and this call needs at least 31. "
                           "It resets at 2030-01-02T00:00:00Z.")
        uninstall()

        # The period has plenty, but one lease is smaller than the call.
        pool = Pool(keys, limit=10_000, slice_=20)
        pool.info = {"period": "month", "resets_at": "2030-02-01T00:00:00Z", "pool": {"limit": 10_000, "remaining": 9_980}}
        leased(pool)
        message = call(Provider()).json()["error"]["message"]
        assert "needs at least 31 tokens and 20 are left of the 20 this budget hands out at a time" in message
        assert "Raise the lease size" in message and "2030-02-01" in message
        uninstall()

        # A budget that never resets, and an issuer that says nothing about it.
        pool = Pool(keys, limit=10_000, slice_=20)
        pool.info = {"period": "total", "pool": {"remaining": 0}}
        leased(pool)
        assert call(Provider()).json()["error"]["message"].endswith("this call needs at least 31. It does not reset.")
        uninstall()
        pool = Pool(keys, limit=10_000, slice_=20)
        leased(pool)
        assert "this warrant allows 20 tokens" in call(Provider()).json()["error"]["message"]

    def test_uninstall_returns_what_is_held(self, keys, leased):
        pool = Pool(keys, limit=1000, slice_=400)
        leased(pool)
        call(Provider())
        uninstall()
        assert not pool.out and pool.spent == 130

    def test_requests_that_are_not_model_calls_take_no_lease(self, keys, leased):
        pool = Pool(keys, limit=1000, slice_=400)
        leased(pool)
        http = httpx.Client(transport=httpx.MockTransport(lambda request: httpx.Response(200, json={"data": []})))
        assert http.get("https://api.openai.com/v1/models").status_code == 200
        assert pool.asked == 0


def _locked(lock, fn, *args):
    with lock:
        return fn(*args)


class TestCloudLeases:
    @pytest.fixture
    def cloud(self, keys):
        state = SimpleNamespace(requests=[], exhausted=False, raw=None, granted=2500, redirect=False)
        warrant = (Warrant.mint_builder().capability("llm.chat", llm_capability(total_tokens=2500, models=[MODEL]))
                   .holder(keys.agent.public_key).ttl(600).mint(keys.issuer))

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_POST(self):
                body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                state.requests.append((self.path, self.headers["Authorization"], body))
                if state.redirect:
                    self.send_response(302)
                    self.send_header("Location", f"http://127.0.0.1:{self.server.server_address[1]}/stolen")
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                if state.raw is not None:
                    data = state.raw.encode()
                    self.send_response(200)
                    self.send_header("Content-Length", str(len(data)))
                    self.end_headers()
                    self.wfile.write(data)
                    return
                if self.path.endswith("/fire") and state.exhausted:
                    status, payload = 409, {"error": {"code": "token_budget_exhausted", "message": "all leased out",
                                                      "retry_at": "2030-01-01T00:00:00Z"}}
                elif self.path.endswith("/fire") and "plain" in self.path:
                    status, payload = 200, {"warrant": warrant.to_base64(), "expires_at": "2030-01-01T00:10:00Z"}
                elif self.path.endswith("/fire"):
                    status, payload = 200, {"warrant": warrant.to_base64(), "expires_at": "2030-01-01T00:10:00Z",
                                            "lease": {"unit": "usd", "granted_tokens": state.granted, "granted_usd_micros": 100000}}
                else:
                    status, payload = 200, {"warrant_id": body["warrant_id"]}
                data = json.dumps(payload).encode()
                self.send_response(status)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        state.url, state.warrant = f"http://127.0.0.1:{server.server_address[1]}", warrant
        yield state
        server.shutdown()

    def test_a_lease_is_a_fire_and_a_return_is_a_signed_release(self, cloud, keys):
        source = CloudLeases("trg_budget", signing_key=keys.agent, url=cloud.url, api_key="tc_test", event_data={"team": "research"})
        lease = source.acquire()
        assert lease.warrant_id == str(cloud.warrant.id) and lease.granted_tokens == 2500
        assert lease.expires_at == 1893456600.0 and lease.info["unit"] == "usd"
        usage = [{"model": MODEL, "input_tokens": 10, "output_tokens": 20}]
        source.release(lease.warrant_id, usage)
        assert cloud.requests[0] == ("/v1/triggers/trg_budget/fire", "Bearer tc_test", {"event_data": {"team": "research"}})
        path, auth, body = cloud.requests[1]
        assert (path, auth, body["warrant_id"], body["usage"]) == ("/v1/metrics/tokens/leases/release", "Bearer tc_test", lease.warrant_id, usage)
        # Signed by the agent over the warrant id and the figures: plain Ed25519.
        message = lease_return_message(lease.warrant_id, usage)
        assert message == f"tenuo-lease-return-v1\n{lease.warrant_id}\n11:gpt-4o-mini:10:20\n".encode()
        assert base64.b64decode(body["signature"]) == bytes(keys.agent.sign_raw(message))

    def test_no_key_no_return(self, cloud):
        source = CloudLeases("trg_budget", url=cloud.url, api_key="tc_test")
        lease = source.acquire()
        with pytest.raises(OSError, match="signing_key"):
            source.release(lease.warrant_id, [])

    def test_install_gives_the_source_the_agents_key(self, cloud, keys):
        source = CloudLeases("trg_budget", url=cloud.url, api_key="tc_test")
        install(lease=LeasedBudget(source), signing_key=keys.agent, trusted_roots=[keys.issuer.public_key])
        try:
            assert source.signing_key is keys.agent
        finally:
            uninstall()

    @pytest.mark.parametrize("reply", ["[]", "null", "{not json", '{"warrant": "AAAA", "lease": {"granted_tokens": 5}}',
                                        '{"lease": {"granted_tokens": "many"}}', ""])
    def test_a_reply_that_is_not_a_lease_is_no_lease(self, cloud, reply):
        cloud.raw = reply
        with pytest.raises(LeaseUnavailable):
            CloudLeases("trg_budget", url=cloud.url, api_key="tc_test").acquire()

    def test_a_lease_must_be_carried_by_its_warrant(self, cloud):
        cloud.granted = 9999  # the reply says more than the warrant carries
        with pytest.raises(LeaseUnavailable, match="not a usable lease"):
            CloudLeases("trg_budget", url=cloud.url, api_key="tc_test").acquire()

    def test_the_api_key_does_not_follow_a_redirect(self, cloud):
        cloud.redirect = True
        with pytest.raises(LeaseUnavailable, match="HTTP 302"):
            CloudLeases("trg_budget", url=cloud.url, api_key="tc_test").acquire()
        assert [path for path, _, _ in cloud.requests] == ["/v1/triggers/trg_budget/fire"]

    def test_a_spent_budget_says_when_to_ask_again(self, cloud):
        cloud.exhausted = True
        with pytest.raises(LeaseUnavailable) as e:
            CloudLeases("trg_budget", url=cloud.url, api_key="tc_test").acquire()
        assert e.value.exhausted and e.value.retry_at == 1893456000.0 and "leased out" in str(e.value)

    def test_a_trigger_without_a_budget_is_not_a_lease_source(self, cloud):
        with pytest.raises(LeaseUnavailable, match="no token_budget"):
            CloudLeases("trg_plain", url=cloud.url, api_key="tc_test").acquire()

    def test_an_unreachable_control_plane_is_no_lease(self):
        with pytest.raises(LeaseUnavailable, match="no lease from the control plane"):
            CloudLeases("trg_budget", url="http://127.0.0.1:9", api_key="tc_test", timeout=1).acquire()

    def test_it_needs_a_control_plane_and_a_key(self, monkeypatch):
        monkeypatch.delenv("TENUO_CONTROL_PLANE_URL", raising=False)
        monkeypatch.delenv("TENUO_API_KEY", raising=False)
        with pytest.raises(ValueError):
            CloudLeases("trg_budget")
