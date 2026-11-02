"""OpenTelemetry: spans, logs and metrics, and what reaches ot.ezlo.com."""

from __future__ import annotations

import asyncio
import json
import logging

import pytest

from custom_components.quicharc import otel
from custom_components.quicharc.const import (
    CONF_TELEMETRY,
    SERVICE_NAME,
    TELEMETRY_ENDPOINT,
)
from custom_components.quicharc.otel import (
    NOOP,
    SpanContext,
    async_get_telemetry,
    child_span,
    trace_headers,
)
from custom_components.quicharc.otel.metrics import PAIRING_OUTCOMES
from custom_components.quicharc.otel.scrub import scrub
from homeassistant.core import HomeAssistant

from .harness import AiohttpClientMocker
from .test_init import (  # mock_service and setup_entry are fixtures
    API,
    HOME_ID,
    OWNER,
    _data_dir,
    _emit,
    _grant,
    _home,
    _requests,
    _wait_for,
    entry_minor_version,  # noqa: F401
    entry_options,  # noqa: F401
    mock_service,  # noqa: F401
    setup_entry,  # noqa: F401
)


def mock_ingest(aioclient_mock: AiohttpClientMocker, status: int = 200) -> None:
    """Accept OTLP posts the way ot.ezlo.com does."""
    for signal in ("traces", "logs", "metrics"):
        aioclient_mock.post(f"{TELEMETRY_ENDPOINT}/{signal}", status=status, json={})


def posted(aioclient_mock: AiohttpClientMocker, signal: str) -> list[dict]:
    """Return the OTLP JSON bodies posted for a signal."""
    return [
        json.loads(call[2])
        for call in aioclient_mock.mock_calls
        if str(call[1]) == f"{TELEMETRY_ENDPOINT}/{signal}"
    ]


def spans(aioclient_mock: AiohttpClientMocker) -> list[dict]:
    """Return every exported span."""
    return [
        span
        for body in posted(aioclient_mock, "traces")
        for resource_spans in body["resourceSpans"]
        for scope in resource_spans["scopeSpans"]
        for span in scope["spans"]
    ]


def attrs(item: dict) -> dict:
    """Decode OTLP attributes."""
    return {a["key"]: next(iter(a["value"].values())) for a in item["attributes"]}


def by_name(items: list[dict], name: str) -> dict:
    return next(span for span in items if span["name"] == name)


def test_scrub_removes_secrets_and_personal_data() -> None:
    """Tokens, emails and full IP addresses never leave the home."""
    text = scrub(
        "Bearer abc.def token=s3cret refresh_token: ezlo_rt_xyz "
        "'access_token': 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.sig' "
        "alice@example.com from 198.51.100.53 and 2001:db8:85a3:0:0:8a2e:370:7334 "
        "via fe80::a1b2:c3d4:e5f6:1234 at 12:04:31, agent exited with code 1, "
        "device dev-1"
    )
    for secret in ("abc.def", "s3cret", "ezlo_rt_xyz", "eyJhbGci", "alice@"):
        assert secret not in text
    assert "198.51.100.0" in text
    assert "2001:db8:85a3::" in text
    assert "fe80::" in text and "a1b2" not in text
    assert "12:04:31" in text
    assert "code 1" in text
    assert "dev-1" in text


def test_traceparent_parsing() -> None:
    """Only well-formed, non-zero W3C trace contexts are accepted."""
    context = SpanContext.from_traceparent(
        "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
    )
    assert context == SpanContext(
        "4bf92f3577b34da6a3ce929d0e0e4736", "00f067aa0ba902b7"
    )
    assert context.traceparent.endswith("-01")
    for bad in (None, 7, "", "00-xyz-00f067aa0ba902b7-01", "00-" + "0" * 32 + "-1-01"):
        assert SpanContext.from_traceparent(bad) is None


def test_child_span_outside_a_trace_does_nothing() -> None:
    """The service client's spans only exist inside some operation."""
    with child_span("GET /x") as span:
        assert span is NOOP
        assert trace_headers() == {}


async def test_spans_are_sent_with_the_resource(
    hass: HomeAssistant, aioclient_mock: AiohttpClientMocker
) -> None:
    """Telemetry is always on: spans go out with the resource attributes."""
    mock_ingest(aioclient_mock)
    telemetry = await async_get_telemetry(hass)
    telemetry.async_configure(environment="stg")
    telemetry.attributes["quicharc.home_id"] = HOME_ID
    with telemetry.span("outer") as outer:
        with child_span("inner") as inner:
            assert trace_headers() == {"traceparent": inner.context.traceparent}
        assert inner.parent == outer.context
    await telemetry.async_flush()
    (body,) = posted(aioclient_mock, "traces")
    resource = attrs(body["resourceSpans"][0]["resource"])
    assert resource["service.name"] == SERVICE_NAME
    assert resource["deployment.environment"] == "stg"
    assert resource["quicharc.home_id"] == HOME_ID
    assert resource["service.instance.id"] == telemetry.install_id
    assert resource["homeassistant.version"]
    exported = spans(aioclient_mock)
    assert {s["name"] for s in exported} == {"outer", "inner"}
    assert (
        by_name(exported, "inner")["traceId"] == by_name(exported, "outer")["traceId"]
    )
    assert (
        by_name(exported, "inner")["parentSpanId"]
        == by_name(exported, "outer")["spanId"]
    )


async def test_logs_carry_trace_ids_and_are_scrubbed(
    hass: HomeAssistant, aioclient_mock: AiohttpClientMocker
) -> None:
    """INFO and above are exported with the current span, secrets removed."""
    mock_ingest(aioclient_mock)
    telemetry = await async_get_telemetry(hass)
    telemetry.async_configure(environment="stg")
    logger = logging.getLogger("custom_components.quicharc.test")
    with telemetry.span("work") as span:
        logger.info("Sent token=abc123 to bob@example.com")
    logger.debug("debug isn't exported")
    try:
        raise ValueError("refresh_token=ezlo_rt_secret")
    except ValueError:
        logger.exception("Failed")
    await telemetry.async_flush()
    records = [
        record
        for body in posted(aioclient_mock, "logs")
        for scope in body["resourceLogs"][0]["scopeLogs"]
        for record in scope["logRecords"]
    ]
    assert [r["body"]["stringValue"] for r in records] == [
        "Sent token=<redacted> to <email>",
        "Failed",
    ]
    assert records[0]["traceId"] == span.context.trace_id
    assert records[0]["spanId"] == span.context.span_id
    assert records[0]["severityText"] == "INFO"
    assert "traceId" not in records[1]
    failure = attrs(records[1])
    assert failure["exception.type"] == "ValueError"
    assert "ezlo_rt_secret" not in json.dumps(records)


async def test_configuration_quotes_stay_local(
    hass: HomeAssistant, aioclient_mock: AiohttpClientMocker
) -> None:
    """Records marked NOT_EXPORTED reach Home Assistant's log only."""
    from custom_components.quicharc.otel.logs import NOT_EXPORTED

    telemetry = await async_get_telemetry(hass)
    telemetry.async_configure(environment="stg")
    logging.getLogger("custom_components.quicharc.test").warning(
        "check said: light.kitchen invalid", extra=NOT_EXPORTED
    )
    assert telemetry.queued["logs"] == 0


async def test_unload_stops_telemetry(
    hass: HomeAssistant,
    setup_entry,  # noqa: F811 - fixture from test_init
    mock_service: AiohttpClientMocker,  # noqa: F811
) -> None:
    """Unloading sends what is queued and detaches the log handler."""
    mock_ingest(mock_service)
    telemetry = setup_entry.runtime_data.telemetry
    handler = telemetry._capture._handler
    logger = logging.getLogger("custom_components.quicharc")
    assert handler in logger.handlers
    assert await hass.config_entries.async_unload(setup_entry.entry_id)
    assert handler not in logger.handlers
    assert telemetry.queued == {"spans": 0, "logs": 0}
    assert spans(mock_service)


async def test_agent_restart_is_its_own_trace(
    hass: HomeAssistant,
    setup_entry,  # noqa: F811 - fixture from test_init
    mock_service: AiohttpClientMocker,  # noqa: F811
) -> None:
    """The first start is part of setup; a restart, and what follows, isn't."""
    mock_ingest(mock_service)
    runtime = setup_entry.runtime_data
    telemetry = runtime.telemetry
    first_pid = runtime.supervisor.pid
    with pytest.raises(Exception):  # noqa: B017 - the fake agent exits mid-request
        await runtime.supervisor.async_request("test.crash")
    await _wait_for(
        lambda: runtime.supervisor.connected and runtime.supervisor.pid != first_pid,
        timeout=20,
    )

    # The restart's span ends once the agent is configured again.
    async def two_starts() -> bool:
        await telemetry.async_flush()
        return [s["name"] for s in spans(mock_service)].count("agent.start") == 2

    for _ in range(100):
        if await two_starts():
            break
        await asyncio.sleep(0.1)
    exported = spans(mock_service)
    setup = by_name(exported, "integration.setup")
    starts = [s for s in exported if s["name"] == "agent.start"]
    assert len(starts) == 2
    first, restart = sorted(starts, key=lambda s: int(s["startTimeUnixNano"]))
    assert first["traceId"] == setup["traceId"]
    assert "parentSpanId" not in restart
    assert restart["traceId"] != setup["traceId"]
    assert attrs(restart)["quicharc.agent.attempt"] == "1"
    # Nothing that happened after setup ended up in setup's trace, apart
    # from the first start and what it did.
    late = [
        s
        for s in exported
        if s["traceId"] == setup["traceId"]
        and int(s["startTimeUnixNano"]) > int(restart["startTimeUnixNano"])
    ]
    assert late == []


async def test_queue_is_bounded_and_failures_dropped(
    hass: HomeAssistant,
    aioclient_mock: AiohttpClientMocker,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A full queue drops new records; a failed export drops its batch."""
    monkeypatch.setattr(otel, "MAX_QUEUE", 3)
    mock_ingest(aioclient_mock, status=503)
    telemetry = await async_get_telemetry(hass)
    telemetry.async_configure(environment="stg")
    logging.getLogger("custom_components.quicharc").removeHandler(
        telemetry._capture._handler
    )
    for name in range(5):
        with telemetry.span(str(name)):
            pass
    assert telemetry.dropped == 2
    await telemetry.async_flush()
    assert telemetry.dropped == 5
    assert telemetry.last_export_error == "traces: HTTP 503"
    assert telemetry.queued["spans"] == 0


async def test_metrics_exported(
    hass: HomeAssistant, aioclient_mock: AiohttpClientMocker
) -> None:
    """Counters go out as cumulative sums, with the dropped count."""
    mock_ingest(aioclient_mock)
    telemetry = await async_get_telemetry(hass)
    telemetry.async_configure(environment="stg")
    telemetry.metrics.add(PAIRING_OUTCOMES, outcome="approved")
    telemetry.metrics.add(PAIRING_OUTCOMES, outcome="approved")
    await telemetry.async_export_metrics()
    (body,) = posted(aioclient_mock, "metrics")
    metrics = {
        m["name"]: m for m in body["resourceMetrics"][0]["scopeMetrics"][0]["metrics"]
    }
    outcomes = metrics["quicharc.pairing.outcomes"]["sum"]
    assert outcomes["isMonotonic"] is True
    assert outcomes["dataPoints"][0]["asInt"] == "2"
    assert attrs(outcomes["dataPoints"][0]) == {"outcome": "approved"}
    assert "quicharc.telemetry.dropped" in metrics


async def test_pairing_approval_is_one_trace(
    hass: HomeAssistant,
    setup_entry,  # noqa: F811 - fixture from test_init
    mock_service: AiohttpClientMocker,  # noqa: F811
) -> None:
    """Request, approval, minting, delivery and the cloud report share a trace."""
    mock_ingest(mock_service)
    telemetry = setup_entry.runtime_data.telemetry
    await telemetry.async_flush()
    mock_service.mock_calls.clear()

    await _emit(
        setup_entry,
        "pairing_request",
        {
            "device_id": "dev-1",
            "device_name": "Owner's iPhone",
            "platform": "ios",
            "ezlo_user_uuid": OWNER,
        },
    )
    await _wait_for(lambda: "dev-1" in setup_entry.runtime_data.pairing.devices)
    await hass.async_block_till_done()
    await telemetry.async_flush()

    exported = spans(mock_service)
    request = by_name(exported, "pairing.request")
    approve = by_name(exported, "pairing.approve")
    trace_id = request["traceId"]
    assert approve["parentSpanId"] == request["spanId"]
    assert attrs(approve)["quicharc.pairing.auto"] is True
    assert attrs(approve)["quicharc.device_id"] == "dev-1"
    names = {s["name"] for s in exported if s["traceId"] == trace_id}
    assert {
        "pairing.request",
        "pairing.approve",
        "token.mint",
        "agent device.approve",
        "PUT /homes/{id}/devices/{device_id}",
    } <= names
    assert {e["name"] for e in approve["events"]} >= {"token.delivered"}
    assert telemetry.metrics.counter_value(PAIRING_OUTCOMES, outcome="auto_approved")

    # The trace continues into the quicharc service and the agent.
    put = next(
        c
        for c in mock_service.mock_calls
        if c[0] == "PUT" and str(c[1]).endswith("/devices/dev-1")
    )
    assert put[3]["traceparent"].split("-")[1] == trace_id
    approve_request = next(
        r for r in _requests(_data_dir(hass)) if r["method"] == "device.approve"
    )
    assert approve_request["traceparent"].split("-")[1] == trace_id

    # The token the device got appears nowhere in what was exported.
    token = approve_request["params"]["token"]["refresh_token"]
    for signal in ("traces", "logs"):
        assert token not in json.dumps(posted(mock_service, signal))


async def test_web_access_toggle_is_one_trace(
    hass: HomeAssistant,
    setup_entry,  # noqa: F811 - fixture from test_init
    mock_service: AiohttpClientMocker,  # noqa: F811
) -> None:
    """The switch, the PATCH, the new grant and the agent update share a trace."""
    mock_service.clear_requests()
    mock_ingest(mock_service)
    mock_service.patch(f"{API}/homes/{HOME_ID}", json=_home(web_access=True))
    mock_service.post(f"{API}/homes/{HOME_ID}/grant", json=_grant(web_access=True))
    mock_service.get(
        f"{API}/homes/{HOME_ID}/devices?state=pending", json={"pairings": []}
    )
    mock_service.get(f"{API}/homes/{HOME_ID}/enrollments", json={"enrollments": []})
    telemetry = setup_entry.runtime_data.telemetry
    await telemetry.async_flush()
    mock_service.mock_calls.clear()

    await hass.services.async_call(
        "switch", "turn_on", {"entity_id": "switch.quicharc_web_access"}, blocking=True
    )
    await telemetry.async_flush()

    exported = spans(mock_service)
    root = by_name(exported, "web_access.set")
    assert "parentSpanId" not in root
    assert attrs(root)["quicharc.web_access"] is True
    names = {s["name"] for s in exported if s["traceId"] == root["traceId"]}
    assert {
        "PATCH /homes/{id}",
        "grant.refresh",
        "POST /homes/{id}/grant",
        "agent config.set",
    } <= names
    patch_call = next(c for c in mock_service.mock_calls if c[0] == "PATCH")
    assert patch_call[3]["traceparent"].split("-")[1] == root["traceId"]


async def test_diagnostics_say_what_is_sent(
    hass: HomeAssistant,
    setup_entry,  # noqa: F811 - fixture from test_init
) -> None:
    """Diagnostics show where telemetry goes and what it holds."""
    from custom_components.quicharc.diagnostics import (
        async_get_config_entry_diagnostics,
    )

    diagnostics = await async_get_config_entry_diagnostics(hass, setup_entry)
    telemetry = diagnostics["telemetry"]
    assert telemetry["endpoint"] == TELEMETRY_ENDPOINT
    assert telemetry["resource"]["service.name"] == SERVICE_NAME
    assert telemetry["resource"]["quicharc.home_id"] == HOME_ID
    assert "Never tokens" in telemetry["content"]


@pytest.mark.parametrize(
    ("entry_minor_version", "entry_options"),
    [
        (1, {"web_access": False, CONF_TELEMETRY: True}),
        (1, {"web_access": False, CONF_TELEMETRY: False}),
        (1, {"web_access": False}),  # set up before 0.2.0
        (2, {"web_access": False}),
    ],
    ids=["old-on", "old-off", "old-missing", "current"],
)
async def test_telemetry_is_always_on(
    hass: HomeAssistant,
    setup_entry,  # noqa: F811 - fixture from test_init
    mock_service: AiohttpClientMocker,  # noqa: F811
) -> None:
    """Whatever an old entry stored, it loads, the option is dropped, and both
    the integration and the agent send telemetry."""
    mock_ingest(mock_service)
    runtime = setup_entry.runtime_data
    assert setup_entry.minor_version == 2
    assert CONF_TELEMETRY not in setup_entry.options
    assert setup_entry.options["web_access"] is False
    (launch,) = [
        json.loads(line)
        for line in (_data_dir(hass) / "launches.jsonl").read_text().splitlines()
    ]
    assert launch["otel_disabled"] is None
    # The agent labels its telemetry with the same environment.
    assert launch["otel_environment"] == runtime.telemetry.environment == "stg"
    await runtime.telemetry.async_flush()
    assert "integration.setup" in {s["name"] for s in spans(mock_service)}


@pytest.fixture
def off_switch_in_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    """Home Assistant itself runs with the agent's off switch set."""
    monkeypatch.setenv("QUICHARC_OTEL_DISABLED", "true")


async def test_agent_never_inherits_the_off_switch(
    hass: HomeAssistant,
    off_switch_in_environment: None,
    setup_entry,  # noqa: F811 - fixture from test_init
) -> None:
    """QUICHARC_OTEL_DISABLED in Home Assistant's environment isn't passed on."""
    (launch,) = [
        json.loads(line)
        for line in (_data_dir(hass) / "launches.jsonl").read_text().splitlines()
    ]
    assert launch["otel_disabled"] is None
