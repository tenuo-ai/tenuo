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
import tenuo.budget
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

    def __init__(self, keys, limit, slice_, clock=None, ttl=600.0, warrant_ttl=3600):
        self.keys, self.limit, self.slice, self.ttl = keys, limit, slice_, ttl
        self.warrant_ttl = warrant_ttl
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
                   .holder(self.keys.agent.public_key).ttl(self.warrant_ttl).mint(self.keys.issuer))
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


def no_lease(response):
    """Refused because no lease could be taken: not a spent budget."""
    return response.status_code == 403 and response.json()["error"]["code"] == "lease_unavailable"


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
        assert no_lease(response) and "unreachable" in response.json()["error"]["message"] and not provider.caps

    def test_a_lease_whose_return_did_not_get_through_stays_closed(self, keys, leased):
        pool = Pool(keys, limit=10_000, slice_=300)
        budget, _ = leased(pool, recheck_after=0)
        provider = Provider()
        call(provider), call(provider)
        held = budget.current.warrant_id
        pool.down = True
        # 40 tokens are left on the lease and the issuer is away. Whether the
        # return got through cannot be known, so nothing more is spent under it.
        assert no_lease(call(provider)) and len(provider.caps) == 2
        assert budget.enter([held]) is False and held in pool.out
        pool.down = False
        assert call(provider).status_code == 200  # on a new lease; the old one is returned at last
        assert budget.current.warrant_id != held and pool.returned == [(held, 260)]

    def test_a_return_the_issuer_took_but_could_not_confirm_is_not_spent_again(self, keys, leased):
        pool = Pool(keys, limit=600, slice_=300)
        budget, _ = leased(pool, recheck_after=0)
        provider = Provider()
        call(provider), call(provider)
        first = budget.current.warrant_id
        real, lost = pool.release, [True]

        def release(warrant_id, usage):
            if warrant_id in dict(pool.returned):
                return  # the issuer already has it: a repeat changes nothing
            real(warrant_id, usage)
            if lost:
                lost.pop()
                pool.down = True  # and it cannot be reached for a new lease either
                raise OSError("the reply was lost")

        pool.release = release
        # The issuer took the return and can hand the 40 unused tokens to someone
        # else. The holder never heard, so it must not go on spending them.
        assert no_lease(call(provider)) and len(provider.caps) == 2
        assert budget.enter([first]) is False
        pool.down = False
        for _ in range(6):
            call(provider)
        assert provider.billed <= 600 and pool.charged() <= 600
        assert [w for w, _ in pool.returned].count(first) == 1

    def test_a_return_in_progress_is_not_forgotten_when_it_fails(self, keys):
        pool = Pool(keys, limit=1000, slice_=400)
        budget = LeasedBudget(pool)
        budget.warrant()
        first = budget.current.warrant_id
        real, fails = pool.release, [True]

        def release(warrant_id, usage):
            if fails:
                fails.pop()
                with budget._lock:
                    budget._forget()  # another thread tidies up while this return is on its way
                raise OSError("503")
            real(warrant_id, usage)

        pool.release = release
        budget.close()
        assert first in pool.out and not pool.returned
        budget.close()
        assert pool.returned == [(first, 0)]

    def test_a_retired_lease_stays_closed_for_as_long_as_its_warrant_is_valid(self, keys):
        now = [time.time()]
        # The issuer says the lease lasts ten minutes; the warrant it signed lasts an hour.
        pool = Pool(keys, limit=10**6, slice_=300, clock=lambda: now[0], ttl=600.0)
        budget = LeasedBudget(pool, clock=lambda: now[0])
        budget.warrant()
        first = budget.current.warrant_id
        budget.close()
        now[0] += 700  # past what the issuer said, well inside what the warrant says
        budget.warrant()
        with budget._lock:
            budget._forget()
        assert budget.enter([first]) is False
        now[0] += 3600
        with budget._lock:
            budget._forget()
        assert budget.knows(first) is False

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
        assert no_lease(response) and "garbled reply" in response.json()["error"]["message"] and not provider.caps

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

    @pytest.mark.skipif(not hasattr(os, "fork"), reason="needs fork")
    @pytest.mark.filterwarnings("ignore:This process:DeprecationWarning")
    def test_a_child_forked_while_the_locks_are_held_is_not_stuck(self, keys):
        import signal

        pool = Pool(keys, limit=1000, slice_=400)
        budget = LeasedBudget(pool)
        budget.warrant()
        first = budget.current.warrant_id
        holding, let_go = threading.Event(), threading.Event()

        def hold():
            with budget._renewing, budget._lock:
                holding.set()
                let_go.wait(10)

        thread = threading.Thread(target=hold)
        thread.start()
        assert holding.wait(5)
        read, write = os.pipe()
        pid = os.fork()
        if pid == 0:  # the child inherits both locks held by a thread it does not have
            try:
                signal.alarm(5)  # were it stuck, this ends it without an answer
                verdict = budget.current is None and budget.enter([first]) is False
                try:
                    budget.warrant()  # takes its own lease: the renewal lock is usable too
                except Exception:
                    verdict = False
                os.write(write, b"ok" if verdict else b"no")
            finally:
                os._exit(0)
        os.close(write)
        os.waitpid(pid, 0)
        let_go.set()
        thread.join(5)
        assert os.read(read, 2) == b"ok"

    def test_ending_a_call_under_a_lease_does_not_hold_the_event_loop(self, keys, leased):
        pool = Pool(keys, limit=10_000, slice_=300)
        budget, _ = leased(pool)
        provider = Provider()
        seen = []
        real = budget.exit
        budget.exit = lambda *a, **k: (seen.append(threading.get_ident()), real(*a, **k))[1]

        async def main():
            async with httpx.AsyncClient(transport=httpx.MockTransport(provider)) as http:
                response = await http.post(URL, json=BODY)
            return response.status_code, threading.get_ident()

        status, loop_thread = asyncio.run(main())
        assert status == 200 and seen and loop_thread not in seen

    def test_a_plan_made_for_a_caller_that_went_away_is_given_back(self, keys, leased):
        pool = Pool(keys, limit=10_000, slice_=300)
        started, go = threading.Event(), threading.Event()
        take = pool.acquire
        pool.acquire = lambda: (started.set(), go.wait(10), take())[2]
        budget, meter = leased(pool)
        provider = Provider()

        async def main():
            async with httpx.AsyncClient(transport=httpx.MockTransport(provider)) as http:
                task = asyncio.ensure_future(http.post(URL, json=BODY))
                while not started.is_set():
                    await asyncio.sleep(0.01)
                task.cancel()  # the caller leaves while its lease is still being taken
                with pytest.raises(asyncio.CancelledError):
                    await task
                go.set()
                for _ in range(200):  # the abandoned plan finishes and is given back
                    await asyncio.sleep(0.01)
                    lease = budget.current
                    if lease is not None and meter.store.used(lease.warrant_id).get(lease.warrant_id, 0) == 0 \
                            and budget._held[lease.warrant_id].inflight == 0:
                        return lease.warrant_id
                return None

        lease_id = asyncio.run(main())
        assert lease_id is not None and not provider.caps
        budget.close()
        assert pool.returned == [(lease_id, 0)]

    def test_an_abandoned_plan_is_given_back_even_when_the_loops_executor_is_gone(self, keys, leased):
        pool = Pool(keys, limit=10_000, slice_=300)
        started, go = threading.Event(), threading.Event()
        take = pool.acquire
        pool.acquire = lambda: (started.set(), go.wait(10), take())[2]
        budget, meter = leased(pool)
        provider = Provider()

        def gone(*args, **kwargs):
            raise RuntimeError("cannot schedule new futures after shutdown")

        async def main():
            loop = asyncio.get_running_loop()
            async with httpx.AsyncClient(transport=httpx.MockTransport(provider)) as http:
                task = asyncio.ensure_future(http.post(URL, json=BODY))
                while not started.is_set():
                    await asyncio.sleep(0.01)
                task.cancel()
                with pytest.raises(asyncio.CancelledError):
                    await task
                loop.run_in_executor = gone  # nothing more can be handed to the loop's executor
                go.set()
                for _ in range(200):
                    await asyncio.sleep(0.01)
                    lease = budget.current
                    if lease is not None and meter.store.used(lease.warrant_id).get(lease.warrant_id, 0) == 0 \
                            and budget._held[lease.warrant_id].inflight == 0:
                        return lease.warrant_id
                return None

        lease_id = asyncio.run(main())
        assert lease_id is not None and not provider.caps
        budget.close()
        assert pool.returned == [(lease_id, 0)]

    def test_a_plan_that_was_ready_when_its_caller_left_is_given_back_once(self, keys, leased):
        from concurrent.futures import ThreadPoolExecutor

        class Recording(ThreadPoolExecutor):
            """The loop's executor, keeping each job with the function it runs."""

            def __init__(self):
                super().__init__(max_workers=2)
                self.handed = []

            def submit(self, fn, *args, **kwargs):
                future = super().submit(fn, *args, **kwargs)
                self.handed.append((fn, future))
                return future

        pool = Pool(keys, limit=10_000, slice_=300)
        started, go = threading.Event(), threading.Event()
        take = pool.acquire
        pool.acquire = lambda: (started.set(), go.wait(10), take())[2]
        budget, meter = leased(pool)
        installed = tenuo.budget_http._INSTALLED
        exits, threads = [], []
        leave = budget.exit
        budget.exit = lambda ids, model, usage: (exits.append(usage), threads.append(threading.current_thread().name),
                                                 leave(ids, model, usage))[2]

        def gone(*args, **kwargs):
            raise RuntimeError("cannot schedule new futures after shutdown")

        async def main():
            loop = asyncio.get_running_loop()
            executor = Recording()
            loop.set_default_executor(executor)
            request = httpx.Request("POST", URL, json=BODY)
            task = asyncio.ensure_future(tenuo.budget_http._plan_for_off_loop(installed, httpx, request))
            for _ in range(500):
                if started.is_set():
                    break
                await asyncio.sleep(0.01)
            jobs = [f for fn, f in executor.handed if fn.__qualname__.endswith("_plan_in_worker.<locals>.work")]
            assert len(jobs) == 1, "the plan was not made on a worker thread"
            # From here to cancel() nothing awaits, so the loop cannot tell the task its
            # plan is ready: the worker finishes it, and then the task is cancelled.
            go.set()
            jobs[0].result(5)
            task.cancel()
            loop.run_in_executor = gone  # nothing more can be handed to the loop's executor
            with pytest.raises(asyncio.CancelledError):
                await task
            for _ in range(300):  # the plan is given back on a thread of its own
                if exits:
                    break
                await asyncio.sleep(0.01)
            await asyncio.sleep(0.1)  # and only once
            return budget.current.warrant_id

        lease_id = asyncio.run(main())
        assert exits == [None] and threads == ["tenuo-plan-release"]
        assert meter.store.used(lease_id).get(lease_id, 0) == 0 and budget._held[lease_id].inflight == 0
        budget.close()
        assert pool.returned == [(lease_id, 0)]

    def test_a_call_is_planned_and_settled_even_when_the_loops_executor_is_gone(self, keys, leased):
        pool = Pool(keys, limit=10_000, slice_=300)
        budget, meter = leased(pool)
        provider = Provider()

        def gone(*args, **kwargs):
            raise RuntimeError("cannot schedule new futures after shutdown")

        async def main():
            asyncio.get_running_loop().run_in_executor = gone
            async with httpx.AsyncClient(transport=httpx.MockTransport(provider)) as http:
                return (await http.post(URL, json=BODY)).status_code

        assert asyncio.run(main()) == 200
        lease_id = budget.current.warrant_id
        assert meter.store.used(lease_id)[lease_id] == INPUT + 100 and budget._held[lease_id].inflight == 0

    def test_usage_above_the_reservation_is_reported_even_when_the_store_fails(self, keys):
        from tenuo.budget import BudgetStore, InMemoryBudgetBackend

        class Failing(InMemoryBudgetBackend):
            down = False

            def add(self, deltas, expires_at):
                if self.down and any(delta > 0 for delta in deltas.values()):
                    raise OSError("the store is away")
                return super().add(deltas, expires_at)

        backend = Failing()
        pool = Pool(keys, limit=10_000, slice_=1000)
        budget = LeasedBudget(pool)
        install(lease=budget, signing_key=keys.agent, trusted_roots=[keys.issuer.public_key],
                budget_store=TokenMeter(BudgetStore(backend=backend), input_estimator=lambda request: INPUT))

        def generous(request):  # generates five times the cap it was given, and bills it
            backend.down = True
            return httpx.Response(200, json={"usage": {"prompt_tokens": INPUT, "completion_tokens": 500, "total_tokens": INPUT + 500}})

        try:
            assert call(generous).status_code == 200
            lease_id = budget.current.warrant_id
        finally:
            uninstall()
        assert pool.returned == [(lease_id, INPUT + 500)]

    def test_a_refusal_for_want_of_a_lease_reaches_the_control_plane(self, keys, leased, monkeypatch):
        sent = []
        fake = SimpleNamespace(emit_for_enforcement=lambda result, chain_result=None: sent.append(result))
        monkeypatch.setattr(tenuo.budget_http, "_control_plane", lambda: fake)
        pool = Pool(keys, limit=0, slice_=300)
        leased(pool)
        provider = Provider()
        assert refused(call(provider)) and refused(call(provider))  # the second is answered from memory
        assert pool.asked == 1 and len(sent) == 2
        assert all(not r.allowed and r.tool == "llm.chat" and r.arguments == {"model": MODEL}
                   and r.constraint_violated == "total_tokens" for r in sent)

    def test_a_lease_is_replaced_when_its_warrant_expires_before_the_issuer_said(self, keys):
        now = [time.time()]
        # The issuer says ten minutes; the warrant it signed is good for one.
        pool = Pool(keys, limit=10**6, slice_=300, clock=lambda: now[0], ttl=600.0, warrant_ttl=60)
        budget = LeasedBudget(pool, clock=lambda: now[0], renew_before=5)
        first = budget.warrant()
        now[0] += 30
        assert budget.warrant() is first and pool.asked == 1
        now[0] += 40  # the warrant has lapsed; what the issuer said has not
        assert budget.warrant() is not first and pool.asked == 2

    def test_a_return_that_failed_is_tried_again_before_asking_for_the_last_of_the_budget(self, keys, leased):
        now = [time.time()]
        pool = Pool(keys, limit=300, slice_=300, clock=lambda: now[0])
        budget, _ = leased(pool, recheck_after=30, clock=lambda: now[0])
        provider = Provider()
        call(provider), call(provider)
        first = budget.current.warrant_id
        real, fails = pool.release, [True]

        def release(warrant_id, usage):
            if fails:
                fails.pop()
                raise OSError("503")
            real(warrant_id, usage)

        pool.release = release
        # The return fails once. Until it gets through, the issuer has nothing left to hand out.
        assert refused(call(provider)) and first in pool.out
        now[0] += 31
        # The next call sends the return again first, which frees the 40 the lease did not use.
        assert call(provider).status_code == 200 and pool.returned[0] == (first, 260)
        assert provider.billed <= 300

    def test_a_lease_that_arrives_after_close_goes_straight_back(self, keys):
        pool = Pool(keys, limit=1000, slice_=400)
        asked, answer = threading.Event(), threading.Event()
        take = pool.acquire
        pool.acquire = lambda: (asked.set(), answer.wait(10), take())[2]
        budget = LeasedBudget(pool)
        outcome = []

        def waiting():
            try:
                outcome.append(budget.warrant())
            except LeaseUnavailable as e:
                outcome.append(e)

        thread = threading.Thread(target=waiting)
        thread.start()
        assert asked.wait(5)
        budget.close()  # nothing is held yet: the issuer is still answering
        answer.set()
        thread.join(5)
        assert isinstance(outcome[0], LeaseUnavailable) and budget.current is None
        assert not pool.out and [used for _, used in pool.returned] == [0]

    def test_a_planner_still_running_after_uninstall_takes_no_lease(self, keys, leased):
        pool = Pool(keys, limit=1000, slice_=400)
        leased(pool)
        installed = tenuo.budget_http._INSTALLED
        uninstall()
        request = httpx.Request("POST", URL, json=BODY)
        core, plan, refusal = installed.plan_for(httpx, request)
        assert core is None and refusal.status_code == 403 and pool.asked == 0

    def test_a_count_that_cannot_be_read_does_not_break_a_call_that_ran(self, keys, leased, monkeypatch):
        from tenuo.budget import usage_counts

        assert usage_counts({"prompt_tokens": 5, "completion_tokens": 5, "total_tokens": float("inf")}) is None
        pool = Pool(keys, limit=10_000, slice_=1000)
        budget, meter = leased(pool)
        # The provider's total is not a number a count can hold.
        answer = b'{"choices":[{"message":{"content":"ok"}}],"usage":{"prompt_tokens":30,"completion_tokens":5,"total_tokens":1e400}}'
        response = call(lambda r: httpx.Response(200, content=answer, headers={"content-type": "application/json"}))
        lease_id = budget.current.warrant_id
        assert response.status_code == 200 and meter.store.used(lease_id)[lease_id] == INPUT + 100
        assert budget._held[lease_id].inflight == 0

        # And when reading it fails outright while the store is failing too, the call still ends cleanly.
        def broken(usage):
            raise OverflowError("cannot convert float infinity to integer")

        monkeypatch.setattr(tenuo.budget_http, "usage_counts", broken)
        monkeypatch.setattr(tenuo.budget.MeteredCall, "settle", lambda self, usage=None: (_ for _ in ()).throw(OSError("store")))
        assert call(Provider()).status_code == 200 and budget._held[lease_id].inflight == 0

    def test_a_call_whose_usage_could_not_be_stored_is_still_reported(self, keys, monkeypatch):
        from tenuo.budget import BudgetStore, InMemoryBudgetBackend

        class Failing(InMemoryBudgetBackend):
            down = False

            def add(self, deltas, expires_at):
                if self.down and any(delta > 0 for delta in deltas.values()):
                    raise OSError("the store is away")
                return super().add(deltas, expires_at)

        sent, events = [], []
        fake = SimpleNamespace(emit_for_enforcement=lambda result, chain_result=None: sent.append(result))
        monkeypatch.setattr(tenuo.budget_http, "_control_plane", lambda: fake)
        backend = Failing()
        pool = Pool(keys, limit=10_000, slice_=1000)
        install(lease=LeasedBudget(pool), signing_key=keys.agent, trusted_roots=[keys.issuer.public_key],
                audit_callback=events.append,
                budget_store=TokenMeter(BudgetStore(backend=backend), input_estimator=lambda request: INPUT))

        def generous(request):
            backend.down = True
            return httpx.Response(200, json={"usage": {"prompt_tokens": INPUT, "completion_tokens": 500, "total_tokens": INPUT + 500}})

        try:
            assert call(generous).status_code == 200
        finally:
            uninstall()
        assert [e.decision for e in events] == ["ALLOW"]
        usage = sent[0].arguments["llm_usage"]
        assert sent[0].allowed and usage["total_tokens"] == INPUT + 500 and usage["unrecorded"] is True
        assert "budget" not in usage and "estimated" not in usage

    def test_a_decision_sent_on_keeps_the_mark_that_its_receipt_was_collected(self, keys):
        from tenuo._enforcement import enforce_tool_call
        from tenuo.budget_http import _send_cloud

        warrant = (Warrant.mint_builder().capability("llm.chat", {})
                   .holder(keys.agent.public_key).ttl(600).mint(keys.issuer))
        sent = []
        fake = SimpleNamespace(emit_for_enforcement=lambda result, chain_result=None: sent.append(result))
        for collected in (True, False):
            decision = enforce_tool_call(tool_name="llm.chat", tool_args={}, bound_warrant=warrant.bind(keys.agent),
                                         trusted_roots=[keys.issuer.public_key])
            if collected:
                decision._tenuo_runtime_receipt = True
            elif hasattr(decision, "_tenuo_runtime_receipt"):
                del decision._tenuo_runtime_receipt
            _send_cloud(fake, tool="llm.chat", warrant_id=str(warrant.id), decision="ALLOW", model=MODEL,
                        reason="model call metered", usage={"total_tokens": 5}, authorization=decision)
        assert sent[0] is not None and getattr(sent[0], "_tenuo_runtime_receipt", False) is True
        assert getattr(sent[1], "_tenuo_runtime_receipt", False) is False
        assert sent[0].arguments["llm_usage"] == {"total_tokens": 5}

    def test_nothing_starts_on_a_lease_past_its_deadline(self, keys):
        now = [time.time()]
        pool = Pool(keys, limit=10**6, slice_=300, clock=lambda: now[0], ttl=600.0)
        budget = LeasedBudget(pool, clock=lambda: now[0])
        budget.warrant()
        first = budget.current.warrant_id
        assert budget.enter([first]) is True
        budget.exit([first], MODEL, {"input_tokens": 30, "output_tokens": 10})
        now[0] += 601  # the issuer's deadline has passed; the signed warrant is good for an hour
        # A warrant delegated from the lease comes in without asking for the current one.
        assert budget.enter(["a-delegated-warrant", first]) is False and budget.current is None
        assert budget.warrant() is not None and budget.current.warrant_id != first
        assert pool.returned == [(first, 40)]

    def test_after_close_the_last_call_to_end_returns_its_lease_at_once(self, keys):
        pool = Pool(keys, limit=1000, slice_=400)
        budget = LeasedBudget(pool, recheck_after=30)
        budget.warrant()
        first = budget.current.warrant_id
        assert budget.enter([first]) is True
        budget._retry_returns_at = budget._mono() + 1000  # an earlier return failed a moment ago
        budget.close()  # a call is still running on the lease
        assert first in pool.out
        budget.exit([first], MODEL, {"input_tokens": 30, "output_tokens": 10})
        assert pool.returned == [(first, 40)]

    def test_locks_held_at_a_fork_are_replaced_in_the_child(self, keys, leased):
        from tenuo.budget import BudgetStore, InMemoryBudgetBackend

        backend = InMemoryBudgetBackend()
        store = BudgetStore(backend=backend)
        pool = Pool(keys, limit=10_000, slice_=400)
        leased(pool)
        installed = tenuo.budget_http._INSTALLED
        held = [backend._lock, store._owed_lock, store._flush_lock, installed.lock, tenuo.budget_http._SHARED_LOCK]
        for lock in held:
            assert lock.acquire(timeout=1)  # as if other threads held them at the fork
        try:
            tenuo.budget._reset_locks_in_child()
            tenuo.budget_http._reset_locks_in_child()
            store.owe({"w": 5})
            assert store.add({"w": 1}) == {"w": 6}
            assert tenuo.budget_http._shared_meter() is not None
            assert call(Provider()).status_code == 200
        finally:
            for lock in held:
                lock.release()

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
        state = SimpleNamespace(requests=[], exhausted=False, raw=None, granted=2500, redirect=False, reply=None)
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
                if self.path.endswith("/fire") and state.reply is not None:
                    status, payload = state.reply
                elif self.path.endswith("/fire") and state.exhausted:
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

    @pytest.mark.parametrize("status, body, says", [
        (404, {"error": {"code": "trigger_not_found", "message": "Trigger not found"}}, "was not found; check the trigger id"),
        (401, {"error": {"code": "invalid_api_key", "message": "API key format is invalid"}}, "did not accept the API key"),
        (403, {"error": {"code": "forbidden", "message": "not allowed"}}, "may not fire trigger"),
        (400, {"error": {"code": "trigger_inactive", "message": "Trigger is not active"}}, "is paused"),
    ])
    def test_a_setup_mistake_says_what_to_fix(self, cloud, status, body, says):
        cloud.reply = (status, body)
        with pytest.raises(LeaseUnavailable) as caught:
            CloudLeases("trg_budget", url=cloud.url, api_key="tc_test").acquire()
        assert says in str(caught.value) and f"HTTP {status}" in str(caught.value) and not caught.value.exhausted

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
