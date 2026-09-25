"""Conservative deterministic relationship and candidate rules."""

from __future__ import annotations

from security_auditor.core.config import CorrelationLimits
from security_auditor.core.models import Confidence
from .graph import (_COMMAND_BEHAVIOR, _MAX_LOCAL_BUCKET, _NETWORK, _PERSISTENCE, _PROCESS, _SEVERITIES, _TOKEN, _State, _id, _metadata, _minimum, _node)
from .models import AttackPathCandidate, RelationshipType


def apply_rules(state: _State, limits: CorrelationLimits, locations, files, functions, imports,
                 paths: list[AttackPathCandidate]) -> None:
    for bucket in locations.values():
        if not state.time_ok() or state.aborted:
            return
        if len(bucket) > _MAX_LOCAL_BUCKET:
            state.notes["CORRELATION_LOCAL_BUCKET_LIMIT"] += 1
            state.aborted = True
            return
        sasts = [f for f in bucket if f.scanner_id in {"sast", "sast.python"}]
        behaviors = [f for f in bucket if f.scanner_id in {"behavior", "behavior.static"}]
        for sast in sasts:
            accepted = (_COMMAND_BEHAVIOR if sast.rule_id == "SAST.PYTHON.COMMAND_INJECTION"
                        else {"BEHAVIOR.DYNAMIC_CODE"} if sast.rule_id == "SAST.PYTHON.DYNAMIC_CODE_EXEC"
                        else set())
            for behavior in behaviors:
                if behavior.rule_id in accepted:
                    state.add_edge(RelationshipType.SUPPORTS, _node(behavior), _node(sast),
                                   _minimum(sast.confidence, behavior.confidence),
                                   "CORRELATION.SAST_BEHAVIOR.SAME_SINK",
                                   "Behavior and SAST signal share a file and sink line.",
                                   ("same_file", "same_line", "compatible_operation"), directed=True)
                if state.aborted:
                    return
        for index, left in enumerate(behaviors):
            if left.rule_id not in _COMMAND_BEHAVIOR:
                continue
            for right in behaviors[index + 1:]:
                if right.rule_id in _COMMAND_BEHAVIOR and left.rule_id != right.rule_id:
                    generic = left if left.rule_id == "BEHAVIOR.PROCESS_EXEC" else right if right.rule_id == "BEHAVIOR.PROCESS_EXEC" else None
                    specific = right if generic is left else left if generic is right else None
                    if (generic is not None and specific is not None
                            and generic.location.start_column == specific.location.start_column
                            and generic.location.start_column is not None):
                        state.add_edge(RelationshipType.SUPPORTS, _node(generic), _node(specific),
                                       _minimum(generic.confidence, specific.confidence),
                                       "CORRELATION.BEHAVIOR.SAME_SINK_SPECIFIC",
                                       "A specific command signal and generic process signal share one sink location.",
                                       ("same_file", "same_line", "same_column", "specific_operation"),
                                       directed=True)
                    state.add_edge(RelationshipType.OVERLAPS, _node(left), _node(right),
                                   _minimum(left.confidence, right.confidence),
                                   "CORRELATION.BEHAVIOR.OVERLAP",
                                   "Compatible behavior labels describe one local operation.",
                                   ("same_file", "same_line"))
                if state.aborted:
                    return
    for path, bucket in files.items():
        if not state.time_ok() or state.aborted:
            return
        secrets = [f for f in bucket if f.scanner_id == "secrets"]
        networks = [f for f in bucket if f.rule_id == _NETWORK]
        if len(secrets) * len(networks) > limits.max_edges:
            state.notes["CORRELATION_LOCAL_BUCKET_LIMIT"] += 1
            state.aborted = True
            return
        for secret in secrets:
            line = secret.location.start_line
            for network in networks:
                distance = abs(line - network.location.start_line)
                same_function = (_metadata(secret, "function_id") is not None and
                                 _metadata(secret, "function_id") == _metadata(network, "function_id"))
                if distance <= limits.proximity_lines or same_function:
                    state.add_edge(RelationshipType.RELATED_BEHAVIOR, _node(secret), _node(network),
                                   Confidence.MEDIUM if same_function else Confidence.LOW,
                                   "CORRELATION.SECRET.NETWORK_CONTEXT",
                                   "Secret-like material and network behavior share local context.",
                                   ("same_function",) if same_function else ("same_file", "nearby_lines"))
                if state.aborted:
                    return
    # Import references are explicit normalized metadata, not guessed from prose.
    for dependency in (f for bucket in files.values() for f in bucket if f.dependency):
            dep = dependency.dependency
            if dep.ecosystem != "PyPI" or not _TOKEN.fullmatch(dep.name) or "-" in dep.name:
                continue
            # Name equality is conservative; distribution/import aliases need an explicit map.
            for reference in imports.get(dep.name.casefold(), ()):
                state.add_edge(RelationshipType.POSSIBLE_DEPENDENCY_USE,
                               _node(dependency), _node(reference), Confidence.MEDIUM,
                               "CORRELATION.DEPENDENCY.PROJECT_REFERENCE",
                               "Project source contains an explicit matching import reference.",
                               ("exact_name_mapping", "import_reference"))
                if state.aborted:
                    return
    # Phase 3's DOWNLOAD_EXECUTE is itself a bounded local flow signal. Do not
    # invent a chain from unrelated network and process findings.
    for path, bucket in files.items():
        for pattern in (f for f in bucket if f.rule_id == "BEHAVIOR.DOWNLOAD_EXECUTE"):
            if len(paths) >= limits.max_attack_paths:
                state.notes["CORRELATION_PATH_LIMIT"] += 1
                state.aborted = True
                return
            node = _node(pattern)
            if node not in state.nodes:
                continue
            paths.append(AttackPathCandidate(
                _id("path-v1", node), "Potential local download-and-execute sequence",
                (node,), (), Confidence.MEDIUM, pattern.severity,
                "Phase 3 reported a same-local-file download and later launch pattern.",
                ("Static alias and path matching represents runtime behavior." ,),
                ("No runtime execution or exploitability was validated.",),
                (pattern.fingerprint,), ("Phase 3 local-flow pattern",)))
    # A same-function ordered cluster is context, never a proven dataflow path.
    for bucket in functions.values():
        if len(bucket) > _MAX_LOCAL_BUCKET:
            state.notes["CORRELATION_LOCAL_BUCKET_LIMIT"] += 1
            state.aborted = True
            return
        ordered = sorted(bucket, key=lambda f: (f.location.start_line, f.fingerprint))
        networks = [f for f in ordered if f.rule_id == _NETWORK]
        executions = [f for f in ordered if f.rule_id == _PROCESS]
        for network in networks:
            for execution in executions:
                if (network.location.start_line < execution.location.start_line and
                        execution.location.start_line - network.location.start_line <= limits.proximity_lines):
                    state.add_edge(RelationshipType.POSSIBLE_SEQUENCE,
                                   _node(network), _node(execution), Confidence.LOW,
                                   "CORRELATION.BEHAVIOR.LOCAL_SEQUENCE",
                                   "Network and process operations are ordered within one recorded function.",
                                   ("same_function", "line_order"), directed=True)
                if state.aborted:
                    return
        for contextual, title, rule_id in (
            ([f for f in ordered if f.rule_id in _PERSISTENCE],
             "Potential persistence-related execution context",
             "CORRELATION.BEHAVIOR.PERSISTENCE_CLUSTER"),
            ([f for f in ordered if f.rule_id == "BEHAVIOR.CREDENTIAL_ACCESS"],
             "Credential-sensitive behavior context",
             "CORRELATION.BEHAVIOR.CREDENTIAL_CLUSTER"),
        ):
            if not networks or not executions or not contextual:
                continue
            triple = (networks[0], contextual[0], executions[0])
            if max(f.location.start_line for f in triple) - min(
                    f.location.start_line for f in triple) > limits.proximity_lines:
                continue
            if len(paths) >= limits.max_attack_paths:
                state.notes["CORRELATION_PATH_LIMIT"] += 1
                state.aborted = True
                return
            identifiers = tuple(_node(f) for f in triple)
            first = state.add_edge(RelationshipType.POSSIBLE_ATTACK_PATH,
                                   identifiers[0], identifiers[1], Confidence.LOW,
                                   rule_id, "Operations share one recorded function and nearby lines.",
                                   ("same_function", "nearby_lines"))
            second = state.add_edge(RelationshipType.POSSIBLE_ATTACK_PATH,
                                    identifiers[1], identifiers[2], Confidence.LOW,
                                    rule_id, "Operations share one recorded function and nearby lines.",
                                    ("same_function", "nearby_lines"))
            if state.aborted:
                return
            paths.append(AttackPathCandidate(
                _id("path-v1", rule_id, *identifiers), title, identifiers,
                tuple(edge for edge in (first, second) if edge), Confidence.LOW,
                max((f.severity for f in triple), key=_SEVERITIES.index),
                "Nearby operations form a contextual cluster within one recorded function.",
                ("Static proximity represents potential runtime sequence.",),
                ("No dataflow, execution, persistence, theft, or intent was established.",),
                tuple(f.fingerprint for f in triple),
                ("same function", "bounded line proximity")))
