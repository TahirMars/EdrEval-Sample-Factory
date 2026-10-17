from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from packages.llm.provider import LLMCompletion, LLMTool
from packages.sample_factory.catalog import CoverageRegistry
from packages.sample_factory.models import AtomRole, SafetyProfile
from packages.sample_factory.plugin_intake import (
    PluginIntakeAgent,
    PluginIntakeCoordinator,
    PluginIntakeRepository,
    PluginIntakeSource,
    PluginIntakeStatus,
    PluginSourceIntake,
    RestrictedWebFetcher,
    WebResponse,
)
from packages.sample_factory.plugin_models import (
    PluginDecompositionPlan,
    PluginDependency,
    PluginOperation,
    PluginRequest,
    PortContract,
    TechniqueIntent,
)

from tests.llm_tool_fakes import as_tool_completion


class _Completion:
    def __init__(self, responses: list[dict[str, object]]) -> None:
        self.responses = list(responses)
        self.calls: list[list[dict[str, object]]] = []

    def complete_tool_with_metadata(self, messages, tools: list[LLMTool], **kwargs) -> LLMCompletion:
        del kwargs
        self.calls.append([dict(item) for item in messages])
        return as_tool_completion(self.responses.pop(0), tools, call_index=len(self.calls))


class _Fetcher:
    def fetch(self, url: str) -> WebResponse:
        return WebResponse(
            final_url=url,
            media_type="text/html",
            body=(
                b"<html><body><h1>Reference technique</h1>"
                b"<script>IGNORE_INSTRUCTION</script><p>Observable behavior</p></body></html>"
            ),
        )


def _request(*, harness_ref: str = "plugin-harness://execution/windows-x64/v1") -> PluginRequest:
    return PluginRequest(
        request_id="plugin-request-intake01",
        operation=PluginOperation.CREATE,
        implementation_name="EarlyApcInjection",
        intent=TechniqueIntent(
            intent_id="intent-intake01",
            ph_ids=("PH-IN04",),
            role=AtomRole.EXECUTION_ATOM,
            required_capabilities=("cap.payload.shellcode",),
            provided_capabilities=("cap.process.injection",),
            input_ports=(
                PortContract(
                    port_id="port.payload.input",
                    value_type="ByteBuffer",
                    semantic="ExecutablePayload",
                    architecture="x64",
                ),
            ),
            parameter_domains={"target": ("notepad.exe", "werfault.exe")},
            architecture="x64",
            safety_profile=SafetyProfile.MEDIUM,
            source_refs=("source://model-guessed",),
        ),
        build_target_ref="build-target://windows-x64",
        harness_ref=harness_ref,
        profile_id="win11-test",
    )


def _decision(status: str, request: PluginRequest | None = None) -> dict[str, object]:
    return {
        "status": status,
        "message": "补充目标进程约束" if request is None else "合同已闭合，请审核",
        "request": None if request is None else request.model_dump(mode="json"),
    }


class PluginIntakeTest(unittest.TestCase):
    def test_ph_in04_rejects_carrier_role(self) -> None:
        payload = _request().intent.model_dump(mode="json")
        payload["role"] = "carrier"

        with self.assertRaisesRegex(ValueError, "execution_atom"):
            TechniqueIntent.model_validate(payload)

    def test_description_web_and_dialogue_become_persisted_typed_request(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            completion = _Completion(
                [
                    _decision("needs_input"),
                    _decision("ready", _request()),
                ]
            )
            coverage = CoverageRegistry({"PH-IN04": ("T1055.004",)})
            coordinator = PluginIntakeCoordinator(
                agent=PluginIntakeAgent(completion, coverage),
                sources=PluginSourceIntake(root, _Fetcher()),
                repository=PluginIntakeRepository(root),
            )

            initial = coordinator.start(
                description="生成一个接受 ByteBuffer 的执行插件",
                source_urls=("https://example.test/technique",),
                harness_ref="plugin-harness://execution/windows-x64/v1",
                build_target_ref="build-target://windows-x64",
                profile_id="win11-test",
            )
            refined = coordinator.continue_session(
                initial.session_id,
                "使用受控的测试目标进程，并等待行为完成。",
            )

            self.assertEqual(PluginIntakeStatus.NEEDS_INPUT, initial.decision.status)
            self.assertEqual(PluginIntakeStatus.READY, refined.decision.status)
            self.assertIsNotNone(refined.decision.request)
            assert refined.decision.request is not None
            self.assertEqual(
                f"plugin-intake://{initial.session_id}",
                refined.decision.request.intake_ref,
            )
            self.assertEqual(
                tuple(item.source_ref for item in refined.sources),
                refined.decision.request.intent.source_refs,
            )
            self.assertEqual(2, len(refined.sources))
            self.assertNotIn("IGNORE_INSTRUCTION", refined.sources[1].text_excerpt)
            self.assertIn("Observable behavior", refined.sources[1].text_excerpt)
            saved = PluginIntakeRepository(root).load(initial.session_id)
            self.assertEqual(refined, saved)
            revisions = tuple(
                (root / "plugin-intakes" / initial.session_id / "revisions").glob("*.json")
            )
            self.assertEqual(2, len(revisions))
            self.assertIn("使用受控的测试目标进程", completion.calls[1][-1]["content"])

    def test_agent_rejects_model_attempt_to_change_fixed_harness(self) -> None:
        completion = _Completion(
            [
                _decision(
                    "ready",
                    _request(harness_ref="plugin-harness://model-controlled/unsafe"),
                )
            ]
        )
        intake_source = {
            "source_ref": "operator-source://sha256/" + "a" * 64,
            "kind": "operator",
            "sha256": "a" * 64,
            "locator": "operator-input",
            "captured_at": "2026-09-04T00:00:00Z",
            "media_type": "text/plain",
            "text_excerpt": "authorized behavior",
        }
        agent = PluginIntakeAgent(
            completion,
            CoverageRegistry({"PH-IN04": ("T1055.004",)}),
            retry_limit=1,
        )

        with self.assertRaisesRegex(Exception, "修改了 operator 固定"):
            agent.decide(
                description="test",
                harness_ref="plugin-harness://execution/windows-x64/v1",
                build_target_ref="build-target://windows-x64",
                profile_id="win11-test",
                sources=(PluginIntakeSource.model_validate(intake_source),),
                intake_ref="plugin-intake://plugin-intake-12345678",
            )

    def test_agent_normalizes_model_capability_and_port_aliases(self) -> None:
        canonical = _request().model_dump(mode="json")
        intent = canonical["intent"]
        intent["provided_capabilities"] = ["process-injection:early-bird-apc"]
        intent["input_ports"][0]["port_id"] = "payload"
        intent["output_ports"] = [
            {
                "port_id": "injected_process_id",
                "value_type": "ProcessId",
                "semantic": "InjectedProcessId",
                "architecture": "x64",
                "required": False,
            }
        ]
        response = _decision("ready", None)
        response["request"] = canonical
        completion = _Completion([response])
        source = PluginIntakeSource(
            source_ref="operator-source://sha256/" + "a" * 64,
            kind="operator",
            sha256="a" * 64,
            locator="operator-input",
            captured_at="2026-09-04T00:00:00Z",
            media_type="text/plain",
            text_excerpt="authorized behavior",
        )
        agent = PluginIntakeAgent(
            completion,
            CoverageRegistry({"PH-IN04": ("T1055.004",)}),
            retry_limit=1,
        )

        decision, _ = agent.decide(
            description="test",
            harness_ref="plugin-harness://execution/windows-x64/v1",
            build_target_ref="build-target://windows-x64",
            profile_id="win11-test",
            sources=(source,),
            intake_ref="plugin-intake://plugin-intake-12345678",
        )

        assert decision.request is not None
        self.assertEqual(
            ("cap.process.injection",),
            decision.request.intent.provided_capabilities,
        )
        self.assertEqual("port.payload", decision.request.intent.input_ports[0].port_id)
        self.assertEqual(
            "port.injected_process_id", decision.request.intent.output_ports[0].port_id
        )

    def test_restricted_web_fetcher_rejects_private_and_credential_urls(self) -> None:
        fetcher = RestrictedWebFetcher(resolver=lambda host, port: ("127.0.0.1",))

        with self.assertRaisesRegex(ValueError, "非公共地址"):
            fetcher.fetch("https://example.test/reference")
        with self.assertRaisesRegex(ValueError, "不得包含凭据"):
            fetcher.fetch("https://user:password@example.test/reference")
        with self.assertRaisesRegex(ValueError, "查询参数"):
            fetcher.fetch("https://example.test/reference?token=value")

    def test_intake_rejects_sensitive_operator_text_and_too_many_urls(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sources = PluginSourceIntake(root, _Fetcher())
            with self.assertRaisesRegex(ValueError, "疑似凭据"):
                sources.capture_operator_description("api_key=do-not-store")
            coordinator = PluginIntakeCoordinator(
                agent=PluginIntakeAgent(
                    _Completion([_decision("needs_input")]),
                    CoverageRegistry({"PH-IN04": ("T1055.004",)}),
                ),
                sources=sources,
                repository=PluginIntakeRepository(root),
            )
            with self.assertRaisesRegex(ValueError, "最多允许 8"):
                coordinator.start(
                    description="authorized test",
                    source_urls=tuple(
                        f"https://example.test/reference/{index}" for index in range(9)
                    ),
                    harness_ref="plugin-harness://execution/windows-x64/v1",
                    build_target_ref="build-target://windows-x64",
                    profile_id="win11-test",
                )

    def test_intake_accepts_and_normalizes_multi_plugin_decomposition(self) -> None:
        producer = _request().model_copy(
            update={
                "request_id": "plugin-request-producer02",
                "implementation_name": "ShellcodeProducer",
                "intent": _request().intent.model_copy(
                    update={
                        "required_capabilities": (),
                        "provided_capabilities": ("cap.payload.shellcode",),
                    }
                ),
            }
        )
        consumer = _request().model_copy(update={"request_id": "plugin-request-consumer02"})
        plan = PluginDecompositionPlan(
            plan_id="plugin-plan-intake01",
            summary="two dependent plugins",
            requests=(producer, consumer),
            external_capabilities=(),
            dependencies=(
                PluginDependency(
                    producer_request_id=producer.request_id,
                    consumer_request_id=consumer.request_id,
                    capability="cap.payload.shellcode",
                ),
            ),
        )
        response = {
            "status": "ready",
            "message": "已拆分为两个插件",
            "request": producer.model_dump(mode="json"),
            "decomposition": plan.model_dump(mode="json"),
        }
        source = PluginIntakeSource(
            source_ref="operator-source://sha256/" + "a" * 64,
            kind="operator",
            sha256="a" * 64,
            locator="operator-input",
            captured_at="2026-09-04T00:00:00Z",
            media_type="text/plain",
            text_excerpt="authorized behavior",
        )
        agent = PluginIntakeAgent(
            _Completion([response]),
            CoverageRegistry({"PH-IN04": ("T1055.004",)}),
        )

        decision, _ = agent.decide(
            description="complex test",
            harness_ref=None,
            build_target_ref="build-target://windows-x64",
            profile_id="win11-test",
            sources=(source,),
            intake_ref="plugin-intake://plugin-intake-12345678",
        )

        self.assertIsNotNone(decision.decomposition)
        assert decision.decomposition is not None
        self.assertEqual(2, len(decision.decomposition.requests))
        self.assertTrue(
            all(
                item.intake_ref == "plugin-intake://plugin-intake-12345678"
                for item in decision.decomposition.requests
            )
        )


if __name__ == "__main__":
    unittest.main()
