"""Phase 5 regressions. All findings are synthetic, redacted data."""

from dataclasses import asdict, replace
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from security_auditor.core.config import CorrelationLimits, load_config
from security_auditor.core.models import (Confidence, DependencyArtifact, Evidence,
                                          Finding, Location, Remediation,
                                          ScannerMetadata, ScannerResult,
                                          ScannerSummary, Severity,
                                          VulnerabilityReference)
from security_auditor.correlation import CorrelationEngine, Completeness, RelationshipType
from security_auditor.correlation.models import DependencyRelevance, FindingRole, RiskPriority


def finding(rule: str, scanner: str, path: str, line: int, severity=Severity.INFO,
            confidence=Confidence.HIGH, structured=(), category="behavior") -> Finding:
    fingerprint = hashlib.sha256(f"{rule}|{path}|{line}".encode()).hexdigest()
    return Finding(fingerprint[:16], rule, scanner, category, "Synthetic finding",
                   "Static synthetic evidence only.", severity, confidence,
                   Location(path, line, 1), Evidence("synthetic", "[REDACTED]", structured),
                   "Synthetic rationale.", Remediation("Review safely."), fingerprint,
                   datetime(2026, 1, 1, tzinfo=timezone.utc), "0.5.0")


def result(scanner: str, *findings: Finding, status="completed", completeness="complete"):
    return ScannerResult(ScannerMetadata(scanner, "test", scanner, True), findings, status,
                         summary=ScannerSummary(completeness=completeness))


class CorrelationTests(unittest.TestCase):
    def test_same_sink_support_and_no_double_count(self):
        sast = finding("SAST.PYTHON.COMMAND_INJECTION", "sast", "app.py", 37,
                       Severity.HIGH, structured=(("sink_kind", "command"),
                                                  ("source_category", "HTTP_INPUT"),
                                                  ("source_line", "33")), category="sast")
        shell = finding("BEHAVIOR.SHELL_EXEC", "behavior", "app.py", 37, Severity.MEDIUM)
        process = finding("BEHAVIOR.PROCESS_EXEC", "behavior", "app.py", 37)
        source = result("sast", sast)
        behaviors = result("behavior", shell, process)
        before = asdict(sast)
        output = CorrelationEngine().correlate((source, behaviors))
        self.assertEqual(asdict(sast), before)
        self.assertEqual(output.summary.completeness, Completeness.COMPLETE)
        self.assertEqual(len(output.groups), 1)
        self.assertEqual(output.groups[0].primary, sast.fingerprint)
        self.assertEqual({role for _, role in output.groups[0].members},
                         {FindingRole.PRIMARY, FindingRole.SUPPORTING})
        self.assertEqual(output.assessments[0].base_severity, Severity.HIGH)
        self.assertEqual(output.assessments[0].priority, RiskPriority.HIGH)
        self.assertEqual(sum(e.relationship_type is RelationshipType.SUPPORTS
                             for e in output.graph.edges), 3)
        self.assertTrue(any(e.rule_id == "CORRELATION.BEHAVIOR.SAME_SINK_SPECIFIC"
                            for e in output.graph.edges))
        self.assertTrue(any(e.relationship_type is RelationshipType.SOURCE_TO_SINK
                            for e in output.graph.edges))
        self.assertEqual(output.assessments[0].exposure_signal.value, "external_input")

    def test_specific_command_groups_same_sink_but_not_different_call(self):
        process = finding("BEHAVIOR.PROCESS_EXEC", "behavior.static", "tests/unit/test_runtime.py", 3)
        command = finding("BEHAVIOR.CMD_EXEC", "behavior.static", "tests/unit/test_runtime.py", 3,
                          Severity.MEDIUM)
        grouped = CorrelationEngine().correlate((result("behavior.static", process, command),))
        self.assertEqual(len(grouped.groups), 1)
        self.assertEqual(grouped.groups[0].primary, command.fingerprint)
        self.assertIn((process.fingerprint, FindingRole.SUPPORTING), grouped.groups[0].members)
        separate = replace(command, location=Location(command.location.path, 3, 20))
        ungrouped = CorrelationEngine().correlate((result("behavior.static", process, separate),))
        self.assertEqual(len(ungrouped.groups), 2)
        self.assertTrue(all(len(group.members) == 1 for group in ungrouped.groups))

    def test_false_cross_file_download_chain_and_local_pattern(self):
        network = finding("BEHAVIOR.NETWORK_REQUEST", "behavior", "a.py", 10)
        process = finding("BEHAVIOR.PROCESS_EXEC", "behavior", "b.py", 20)
        output = CorrelationEngine().correlate((result("behavior", network, process),))
        self.assertEqual(output.attack_paths, ())
        self.assertFalse(any(e.relationship_type is RelationshipType.POSSIBLE_SEQUENCE
                             for e in output.graph.edges))
        pattern = finding("BEHAVIOR.DOWNLOAD_EXECUTE", "behavior", "a.py", 20,
                          Severity.MEDIUM, Confidence.MEDIUM)
        output = CorrelationEngine().correlate((result("behavior", network, pattern),))
        self.assertEqual(len(output.attack_paths), 1)
        self.assertEqual(output.attack_paths[0].confidence, Confidence.MEDIUM)
        self.assertIn("No runtime", output.attack_paths[0].limitations[0])

    def test_secret_network_context_is_weak_and_raw_free(self):
        secret = finding("SECRET.API", "secrets", "app.py", 8, Severity.HIGH,
                         category="secret")
        network = finding("BEHAVIOR.NETWORK_REQUEST", "behavior", "app.py", 11)
        output = CorrelationEngine().correlate((result("secrets", secret),
                                                 result("behavior", network)))
        context = [e for e in output.graph.edges
                   if e.relationship_type is RelationshipType.RELATED_BEHAVIOR]
        self.assertEqual(len(context), 1)
        self.assertEqual(context[0].confidence, Confidence.LOW)
        self.assertNotIn("exfiltration", json.dumps(asdict(output)).lower())
        far = replace(network, location=Location("app.py", 100, 1))
        output = CorrelationEngine().correlate((result("secrets", secret),
                                                 result("behavior", far)))
        self.assertFalse(any(e.relationship_type is RelationshipType.RELATED_BEHAVIOR
                             for e in output.graph.edges))

    def test_dependency_reference_only_exact_structured_import(self):
        dependency = finding("DEPENDENCY.KNOWN_VULNERABILITY", "dependencies",
                             "requirements.txt", 1, Severity.HIGH, category="dependency")
        dependency = replace(dependency,
                             dependency=DependencyArtifact("PyPI", "urllib3", "1.0", "requirements.txt"),
                             vulnerability=VulnerabilityReference("OSV-TEST", "OSV"))
        imported = finding("IMPORT.PYTHON.REFERENCE", "imports", "app.py", 2,
                           structured=(("import_name", "urllib3"),), category="import_reference")
        output = CorrelationEngine().correlate((result("dependencies", dependency),
                                                 result("imports", imported)))
        self.assertTrue(any(e.relationship_type is RelationshipType.POSSIBLE_DEPENDENCY_USE
                            for e in output.graph.edges))
        assessment = next(a for a in output.assessments
                          if dependency.fingerprint in a.contributing_findings)
        self.assertEqual(assessment.dependency_relevance, DependencyRelevance.REFERENCED)
        self.assertEqual(assessment.priority, RiskPriority.HIGH)
        self.assertIn("does not prove", assessment.limitations[0])
        unrelated = replace(imported, evidence=Evidence("synthetic", "[REDACTED]",
                                                          (("import_name", "other"),)))
        output = CorrelationEngine().correlate((result("dependencies", dependency),
                                                 result("imports", unrelated)))
        self.assertFalse(any(e.relationship_type is RelationshipType.POSSIBLE_DEPENDENCY_USE
                             for e in output.graph.edges))

    def test_partial_coverage_caps_confidence_and_invalid_finding(self):
        good = finding("BEHAVIOR.PROCESS_EXEC", "behavior", "app.py", 4)
        invalid = replace(good, fingerprint="bad", location=Location("../outside", 1))
        output = CorrelationEngine().correlate((result("behavior", good, invalid,
                                                       completeness="partial"),))
        self.assertEqual(output.summary.completeness, Completeness.PARTIAL)
        self.assertEqual(output.summary.admitted_findings, 1)
        self.assertEqual(output.assessments[0].confidence, Confidence.MEDIUM)
        self.assertIn("CORRELATION_INVALID_FINDING",
                      {d.code for d in output.summary.diagnostics})

    def test_budget_and_deterministic_order(self):
        items = tuple(finding("BEHAVIOR.PROCESS_EXEC", "behavior", f"file{n}.py", 1)
                      for n in range(5))
        engine = CorrelationEngine(CorrelationLimits(max_nodes=3))
        limited = engine.correlate((result("behavior", *items),))
        self.assertEqual(limited.summary.completeness, Completeness.ABORTED)
        self.assertLessEqual(limited.summary.nodes, 3)
        engine = CorrelationEngine()
        first = engine.correlate((result("behavior", *items),))
        second = engine.correlate((result("behavior", *reversed(items)),))
        self.assertEqual(first, second)

    def test_function_sequence_and_context_candidates_stay_weak(self):
        scope = (("function_id", "handler"),)
        network = finding("BEHAVIOR.NETWORK_REQUEST", "behavior", "app.py", 10,
                          structured=scope)
        process = finding("BEHAVIOR.PROCESS_EXEC", "behavior", "app.py", 13,
                          structured=scope)
        persistence = finding("BEHAVIOR.STARTUP_PERSISTENCE", "behavior", "app.py", 12,
                              structured=scope)
        credential = finding("BEHAVIOR.CREDENTIAL_ACCESS", "behavior", "app.py", 11,
                             structured=scope)
        output = CorrelationEngine().correlate((result("behavior", network, process,
                                                         persistence, credential),))
        self.assertEqual(len(output.attack_paths), 2)
        self.assertTrue(all(path.confidence is Confidence.LOW for path in output.attack_paths))
        self.assertTrue(any(edge.relationship_type is RelationshipType.POSSIBLE_SEQUENCE
                            for edge in output.graph.edges))
        unrelated = replace(process, evidence=Evidence("synthetic", "[REDACTED]",
                                                       (("function_id", "other"),)))
        output = CorrelationEngine().correlate((result("behavior", network, unrelated,
                                                         persistence, credential),))
        self.assertEqual(output.attack_paths, ())

    def test_untrusted_text_is_not_copied_into_correlation_output(self):
        fake = "FAKE_SECRET_DO_NOT_EXPOSE_123456789"
        unsafe = finding("BEHAVIOR.NETWORK_REQUEST", "behavior", "app.py", 3)
        unsafe = replace(unsafe, title=fake, description=fake,
                         evidence=Evidence("synthetic", fake, (("payload", fake),)))
        output = CorrelationEngine().correlate((result("behavior", unsafe),))
        self.assertNotIn(fake, json.dumps(asdict(output)))

    def test_invalid_source_line_does_not_crash(self):
        sast = finding("SAST.PYTHON.COMMAND_INJECTION", "sast", "app.py", 9,
                       Severity.HIGH, structured=(("source_category", "HTTP_INPUT"),
                                                  ("source_line", "bad"),
                                                  ("sink_kind", "command")), category="sast")
        output = CorrelationEngine().correlate((result("sast", sast),))
        self.assertEqual(output.summary.completeness, Completeness.COMPLETE)
        self.assertFalse(any(e.relationship_type is RelationshipType.SOURCE_TO_SINK
                             for e in output.graph.edges))

    def test_malformed_structured_dependency_is_skipped(self):
        dependency = finding("DEPENDENCY.KNOWN_VULNERABILITY", "dependencies",
                             "requirements.txt", 1, category="dependency")
        malformed = replace(dependency, dependency=DependencyArtifact("PyPI", None,
                                                                        "1.0", "requirements.txt"))
        output = CorrelationEngine().correlate((result("dependencies", malformed),))
        self.assertEqual(output.summary.completeness, Completeness.PARTIAL)
        self.assertEqual(output.summary.admitted_findings, 0)

    def test_priority_bonus_needs_external_input_and_direct_support(self):
        sast = finding("SAST.PYTHON.COMMAND_INJECTION", "sast", "app.py", 20,
                       Severity.MEDIUM, structured=(("source_category", "HTTP_INPUT"),
                                                    ("source_line", "15"),
                                                    ("sink_kind", "command")), category="sast")
        behavior = finding("BEHAVIOR.SHELL_EXEC", "behavior", "app.py", 20,
                           Severity.MEDIUM)
        engine = CorrelationEngine()
        paired = engine.correlate((result("sast", sast), result("behavior", behavior)))
        self.assertEqual(paired.assessments[0].priority, RiskPriority.HIGH)
        no_source = replace(sast, evidence=Evidence("synthetic", "[REDACTED]",
                                                      (("sink_kind", "command"),)))
        paired = engine.correlate((result("sast", no_source), result("behavior", behavior)))
        self.assertEqual(paired.assessments[0].priority, RiskPriority.MEDIUM)

    def test_config_hard_caps(self):
        config = load_config(Path(__file__).resolve().parents[1] / "security-auditor.example.toml")
        self.assertTrue(config.correlation.enabled)
        with self.assertRaises(ValueError):
            CorrelationLimits(max_edges=999999999)


if __name__ == "__main__":
    unittest.main()
