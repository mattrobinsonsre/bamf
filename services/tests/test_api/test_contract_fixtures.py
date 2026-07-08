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
from bamf.api.models.tokens import JoinTokenResponse
from bamf.api.models.users import UserResponse
from bamf.api.routers.resources import ResourceListResponse, ResourceResponse

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


def test_tokens_list_envelope_contract():
    """`bamf tokens list` (cmd/bamf/cmd/tokens.go) decodes the CursorPage
    ``items`` envelope of JoinTokenResponse — the surface #120 explicitly named.
    Same both-sides guard as agents: the golden is validated here against the
    real response model and in Go against the CLI's decode struct.
    """
    raw = (CONTRACTS / "tokens_list.json").read_text()

    page = CursorPage[JoinTokenResponse].model_validate_json(raw)
    assert len(page.items) == 1

    data = json.loads(raw)
    assert set(data) == {"items", "next_cursor", "has_more"}

    item = data["items"][0]
    dumped = json.loads(JoinTokenResponse.model_validate(item).model_dump_json())
    assert set(dumped) == set(item)


def test_users_list_envelope_contract():
    """`bamf users list` (cmd/bamf/cmd/users.go) decodes the CursorPage ``items``
    envelope of UserResponse — a new consumer, pinned like agents/tokens."""
    raw = (CONTRACTS / "users_list.json").read_text()

    page = CursorPage[UserResponse].model_validate_json(raw)
    assert len(page.items) == 1

    data = json.loads(raw)
    assert set(data) == {"items", "next_cursor", "has_more"}

    item = data["items"][0]
    dumped = json.loads(UserResponse.model_validate(item).model_dump_json())
    assert set(dumped) == set(item)


def test_resources_list_envelope_contract():
    """`bamf resources`/`bamf ls` (cmd/bamf/cmd/resources.go) decodes the custom
    ``resources`` envelope (ResourceListResponse), not the CursorPage ``items``
    shape. Pinning it here + in Go stops a producer-side key rename from
    silently emptying the CLI the way #120 emptied ``bamf agents``.
    """
    raw = (CONTRACTS / "resources_list.json").read_text()

    page = ResourceListResponse.model_validate_json(raw)
    assert len(page.resources) == 1

    data = json.loads(raw)
    # The custom envelope key is exactly what the Go CLI decodes.
    assert set(data) == {"resources"}

    item = data["resources"][0]
    dumped = json.loads(ResourceResponse.model_validate(item).model_dump_json())
    assert set(dumped) == set(item)


def _san_uris(cert) -> set[str]:
    from cryptography import x509

    ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    return set(ext.get_values_for_type(x509.UniformResourceIdentifier))


def test_session_cert_san_contract():
    """The session-cert SAN URIs are the bridge's sole authorization input
    (parsed by pkg/bridge/server.go extractSessionInfo). The committed cert
    services/tests/contracts/session_cert.pem is a REAL issued cert the Go test
    parses; this asserts its 5 SANs and that CURRENT issuance still produces the
    same set — so a SAN-format drift fails here and forces regenerating the
    fixture, which the Go parser test then re-validates.
    """
    from cryptography import x509

    from bamf.auth.ca import CertificateAuthority

    cert = x509.load_pem_x509_certificate((CONTRACTS / "session_cert.pem").read_bytes())
    fixture_sans = _san_uris(cert)
    assert fixture_sans == {
        "bamf://session/sess-fixture-0001",
        "bamf://resource/web-01",
        "bamf://bridge/bamf-bridge-0",
        "bamf://role/client",
        "bamf://type/ssh-audit",
    }

    ca = CertificateAuthority.generate()
    fresh, _key = ca.issue_session_certificate(
        session_id="sess-fixture-0001",
        resource_name="web-01",
        bridge_id="bamf-bridge-0",
        subject_cn="alice@example.com",
        role="client",
        resource_type="ssh-audit",
    )
    assert _san_uris(fresh) == fixture_sans


def test_tunnel_command_contract():
    """The dial/redial command payload is read off an untyped map by the Go agent
    (pkg/agent/agent.go handleTunnelRequest). Current producer output must match
    the committed golden the Go test reads — a key rename on either side breaks
    its assertions.
    """
    from bamf.api.agent_commands import build_tunnel_command

    golden = json.loads((CONTRACTS / "dial_command.json").read_text())
    produced = build_tunnel_command(
        command="dial",
        session_id="s",
        bridge_host="h",
        bridge_port=8443,
        resource_name="r",
        resource_type="ssh-audit",
        session_cert="c",
        session_key="k",
        ca_certificate="ca",
    )
    assert set(produced) == set(golden)
    # bridge_port is a number — the agent decodes it as a JSON number (float64).
    assert isinstance(golden["bridge_port"], int)
