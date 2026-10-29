import json
import types

from tools import workflow_tracer as wt
from tools.workflow_tracer import (
    StateProbe,
    StepRole,
    TraceStep,
    WorkflowDeviator,
    WorkflowTrace,
    WorkflowTracer,
    check,
    trace_workflow,
)


class FakeResp:
    def __init__(self, status_code=200, text="", headers=None):
        self.status_code = status_code
        self.text = text
        self.headers = headers or {}


class FakeSession:
    def __init__(self, handler=None):
        self.handler = handler
        self.calls = []
        self.verify = True

    def _do(self, method, url, kwargs):
        self.calls.append((method, url, kwargs))
        if self.handler is None:
            return FakeResp()
        return self.handler(method, url, kwargs)

    def get(self, url, **kwargs):
        return self._do("GET", url, kwargs)

    def post(self, url, **kwargs):
        return self._do("POST", url, kwargs)

    def put(self, url, **kwargs):
        return self._do("PUT", url, kwargs)

    def patch(self, url, **kwargs):
        return self._do("PATCH", url, kwargs)

    def delete(self, url, **kwargs):
        return self._do("DELETE", url, kwargs)


def _step(
    index,
    method="GET",
    url="http://t.test/a",
    status=200,
    body="",
    role=StepRole.READ,
    extract=None,
):
    return TraceStep(
        index=index,
        method=method,
        url=url,
        params={},
        body=None,
        response_status=status,
        response_body=body,
        response_headers={},
        role=role,
        extract=extract or {},
    )


class TestTraceStepSignature:
    def test_signature_stable(self):
        a = _step(0, url="http://t.test/a?x=1", status=200)
        b = _step(0, url="http://t.test/a?x=2", status=200)
        assert a.signature == b.signature
        assert len(a.signature) == 12

    def test_signature_differs_by_status(self):
        assert _step(0, status=200).signature != _step(0, status=500).signature


class TestWorkflowTrace:
    def test_add_and_to_dict(self):
        trace = WorkflowTrace(name="flow", identity_label="user", base_url="http://t.test")
        trace.add_step(_step(0, url="http://t.test/a?x=1", extract={"id": "1"}))
        trace.add_step(_step(1, method="POST", url="http://t.test/b", status=201))
        data = trace.to_dict()
        assert data["name"] == "flow"
        assert data["identity"] == "user"
        assert data["total_steps"] == 2
        assert data["urls"] == ["http://t.test/a", "http://t.test/b"]
        assert data["steps"][0]["role"] == "READ"
        assert data["steps"][0]["extract"] == {"id": "1"}


class TestWorkflowTracerFlow:
    def test_record_without_active_trace(self):
        tracer = WorkflowTracer("http://t.test/")
        assert tracer.record("GET", "http://t.test/a") is None

    def test_record_and_end(self):
        tracer = WorkflowTracer("http://t.test/")
        assert tracer.base_url == "http://t.test"
        tracer.start_trace("flow", identity_label="admin")
        step = tracer.record(
            "get",
            "http://t.test/a",
            params={"x": "1"},
            response_status=200,
            response_body="ok",
            response_headers={"Server": "t"},
            role=StepRole.READ,
        )
        assert step.index == 0
        assert step.method == "GET"
        assert step.timestamp > 0
        trace = tracer.end_trace()
        assert trace.name == "flow"
        assert tracer.active_trace is None
        assert tracer.get_trace("flow") is trace
        assert tracer.list_traces() == {"flow": 1}
        assert tracer.end_trace() is None

    def test_end_trace_renames(self):
        tracer = WorkflowTracer("http://t.test")
        tracer.start_trace("old")
        tracer.record("GET", "http://t.test/a")
        trace = tracer.end_trace("new")
        assert trace.name == "new"
        assert tracer.get_trace("new") is trace


class TestWorkflowDeviator:
    def _trace(self):
        return WorkflowTrace(
            name="t",
            steps=[
                _step(0, status=200, extract={"id": "1", "token": "t0"}),
                _step(1, status=200, body='{"id": 7, "ref": "r1"}'),
                _step(2, status=200, body='[{"id": "a"}, {"uuid": "u"}]'),
                _step(3, status=200, body='zzz "id": "abc"'),
                _step(4, status=201, body="x" * 60000),
                _step(5, status=500, body='{"id": "ignored"}'),
                _step(6, status=200, body="[1, 2]"),
            ],
        )

    def test_find_resource_ids(self):
        found = WorkflowDeviator(self._trace()).find_resource_ids()
        assert ("id", "1", 0) in found
        assert ("token", "t0", 0) in found
        assert ("id", "7", 1) in found
        assert ("ref", "r1", 1) in found
        assert ("id", "a", 2) in found
        assert ("uuid", "u", 2) in found
        assert ("id", "abc", 3) in found
        assert not [f for f in found if f[2] in (4, 5, 6)]

    def test_generate_skip_steps(self):
        deviator = WorkflowDeviator(self._trace())
        tests = deviator.generate_skip_steps(2)
        assert len(tests) == 3
        assert tests[2]["target_url"] == "http://t.test/a"
        assert tests[0]["expected_auth"] is True
        first = deviator.generate_skip_steps(0)
        assert first[0]["expected_auth"] is False

    def test_generate_role_swap(self):
        trace = WorkflowTrace(
            name="t",
            steps=[
                _step(0, status=200, extract={"id": "12"}),
                _step(1, status=200, url="http://t.test/user/12?account_id=7&user=abc&name=alice"),
            ],
        )
        tests = WorkflowDeviator(trace).generate_role_swap(1, "owner")
        idor = [t for t in tests if t["technique"] == "role_swap_idor"]
        swaps = [t for t in tests if t["technique"] == "role_swap_param"]
        assert idor[0]["swapped_url"].startswith("http://t.test/user/12_other")
        assert idor[0]["resource_owner"] == "owner"
        params = {t["param"]: t["suggested_swap"] for t in swaps}
        assert params == {"account_id": "8", "user": "abc_other"}

    def test_generate_replay(self):
        trace = WorkflowTrace(
            name="t",
            steps=[
                _step(0, role=StepRole.READ),
                _step(1, method="POST", role=StepRole.AUTH),
                _step(2, method="POST", role=StepRole.CREATE),
                _step(3, method="PUT", role=StepRole.UPDATE),
                _step(4, method="DELETE", role=StepRole.DELETE),
            ],
        )
        tests = WorkflowDeviator(trace).generate_replay()
        assert len(tests) == 6
        assert tests[0]["technique"] == "replay_old_step"
        assert tests[0]["old_step_index"] == 1
        assert tests[0]["current_step_index"] == 2


class TestStateProbe:
    def test_snapshot_and_compare(self):
        sess = FakeSession(lambda m, u, k: FakeResp(200, "page", {"Server": "t"}))
        probe = StateProbe(sess)
        assert probe.snapshot("before", "http://t.test/a") == 4
        assert probe.snapshot("after", "http://t.test/a") == 4
        result = probe.compare("before", "after")
        assert result["identical"] is True
        assert result["len_a"] == 4
        assert probe.assert_state_unchanged("before", "after") is True

    def test_snapshot_exception(self):
        def handler(method, url, kwargs):
            raise RuntimeError("boom")

        probe = StateProbe(FakeSession(handler))
        assert probe.snapshot("k", "http://t.test/a") is None

    def test_compare_missing(self):
        probe = StateProbe(FakeSession())
        result = probe.compare("a", "b")
        assert result["error"] == "snapshot not found"
        assert result["identical"] is False

    def test_state_changed(self):
        sess = FakeSession(lambda m, u, k: FakeResp(200, "x" * (1 if "a" in u else 2)))
        probe = StateProbe(sess)
        probe.snapshot("before", "http://t.test/a")
        probe.snapshot("after", "http://t.test/b")
        assert probe.assert_state_unchanged("before", "after") is False


class TestTraceWorkflow:
    def _patch_time(self, monkeypatch):
        monkeypatch.setattr(
            wt, "time", types.SimpleNamespace(time=lambda: 1.0, sleep=lambda s: None)
        )

    def test_trace_steps(self, monkeypatch):
        self._patch_time(monkeypatch)
        sess = FakeSession(lambda m, u, k: FakeResp(200, "body", {"Server": "test"}))
        steps = [
            {"method": "GET", "url": "/a?x=1"},
            {"method": "POST", "url": "http://t.test/b", "data": {"k": "v"}},
            {"method": "PUT", "url": "/c", "data": "raw"},
            {"method": "DELETE", "url": "/d"},
        ]
        trace = trace_workflow(sess, "http://t.test", steps)
        assert trace.name == "manual"
        assert len(trace.steps) == 4
        assert trace.steps[0].params == {"x": "1"}
        assert trace.steps[0].url == "http://t.test/a?x=1"
        assert trace.steps[1].body == json.dumps({"k": "v"})
        assert trace.steps[1].role == StepRole.CREATE
        assert trace.steps[2].body == json.dumps("raw")
        assert trace.steps[3].role == StepRole.DELETE
        assert trace.steps[0].response_headers == {"Server": "test"}

    def test_trace_step_exception_continues(self, monkeypatch):
        self._patch_time(monkeypatch)

        def handler(method, url, kwargs):
            if "/b" in url:
                raise RuntimeError("boom")
            return FakeResp(200, "body")

        sess = FakeSession(handler)
        steps = [
            {"method": "GET", "url": "/a"},
            {"method": "POST", "url": "/b", "data": {"k": "v"}},
            {"method": "DELETE", "url": "/d"},
        ]
        trace = trace_workflow(sess, "http://t.test", steps)
        assert len(trace.steps) == 2


class TestCheck:
    def test_check_returns_shape(self):
        result = check("http://t.test", sess=FakeSession())
        assert result == {"vulnerable": False, "findings": [], "traces": []}

    def test_check_creates_session(self):
        result = check("http://t.test")
        assert "vulnerable" in result
