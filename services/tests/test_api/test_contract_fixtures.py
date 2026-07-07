"""Cross-language contract guards.

The golden fixtures under ``services/tests/contracts/`` are shared with the Go
consumer tests (``cmd/bamf/cmd/contract_test.go``). The same committed file is
validated by both sides, so neither can silently encode a contract the peer
never honored — the failure mode behind the ``bamf agents`` / ``bamf tokens
list`` envelope-drift bug (#120), where the Go struct decoded ``agents`` while
the API returned ``items`` and both test suites stayed green.

If the API model drifts, the producer assertions here fail. If the CLI consumer
drifts, the Go test fails. Updating one side forces updating the shared golden,
which re-checks the other.
"""

import json
from pathlib import Path

from bamf.api.models.agents import AgentResponse
from bamf.api.models.common import CursorPage

CONTRACTS = Path(__file__).resolve().parents[1] / "contracts"


def test_agents_list_envelope_contract():
    raw = (CONTRACTS / "agents_list.json").read_text()

    # Producer honors the shape: the golden validates against the real response
    # model the endpoint returns (CursorPage[AgentResponse]).
    page = CursorPage[AgentResponse].model_validate_json(raw)
    assert len(page.items) == 1

    data = json.loads(raw)
    # The envelope is exactly the CursorPage shape the Go CLI decodes.
    assert set(data) == {"items", "next_cursor", "has_more"}

    # A fresh model instance must serialize to exactly the golden's item keys, so
    # a producer-side field rename/removal breaks here and forces the golden (and
    # thus the Go consumer test) to be updated in lockstep.
    item = data["items"][0]
    dumped = json.loads(AgentResponse.model_validate(item).model_dump_json())
    assert set(dumped) == set(item)
