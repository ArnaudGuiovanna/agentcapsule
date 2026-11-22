#!/usr/bin/env python3
"""Run the bounded and exhaustive checks of the formal models (VAL-01).

`quint test` and `quint run` (simulation) need only Node.js. The checks here
need a Java runtime: Apalache through `quint verify`, and TLC through
`quint verify --backend=tlc` (TLC ships inside apalache.jar). Each check names
a module of spec/*.qnt, a property, its bounds and the result the repository
expects: `ok` (no violation within the stated bounds) or `violation` (a broken
configuration or a witness schedule must produce a counterexample).

The tools come from --tools (default ~/.local/share/agentcapsule-tools), as
recorded in its model-checkers.json: the JDK, Apalache at the version Quint
pins, and the SHA-256 of apalache.jar. Quint comes from spec/node_modules
(`npm ci` in spec/). A missing or changed tool stops the run before any check.

The checks run one at a time on a frozen copy of spec/*.qnt, each in its own
directory under --output (default quint/results/check-models-<timestamp>):
run.log, result.json, and trace.itf.json for an Apalache counterexample (TLC
prints its trace in run.log). summary.json lists every result. The run fails
when a check ends otherwise than expected, on a timeout and on a tool error:
a timeout is never a pass. A witness schedule must fail at its last step.

Every fixed witness schedule (a module with `traceInit`) and every module of
the files written for the checkers (depth wrappers, controls, liveness,
induction) must have a check below, or a reason in UNCHECKED.
"""

import argparse
import dataclasses
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import socket
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parent.parent
SPEC = ROOT / "spec"
DEFAULT_TOOLS = Path("~/.local/share/agentcapsule-tools").expanduser()
RECORD = "model-checkers.json"
QUINT_PACKAGE = Path("node_modules/@informalsystems/quint")
OK, VIOLATION = "ok", "violation"
QUICK = 900  # seconds; the default time limit of one check

# Files written for the checkers: each of their modules needs a check.
CHECKER_FILES = ("bounded.qnt", "concurrent_bounded.qnt", "concurrent_focused.qnt",
                 "concurrent_loaded.qnt", "liveness.qnt", "induction.qnt",
                 "protocol_induction.qnt", "service_progress_controls.qnt")
UNCHECKED = {
    "concurrentPrefixes": "holds the start states of the focused checks; its runs are quint tests",
    "concurrentProtocolLoaded": "the start state of a simulation (spec/README.md); "
                                "concurrentProtocolLoadedDepth4 and concurrentProtocolLoadedDepth12 bound it",
}


@dataclasses.dataclass
class Check:
    file: str
    module: str
    prop: str
    expected: str
    backend: str  # "apalache" or "tlc"
    kind: str = "invariant"  # "invariant", "temporal" or "inductive"
    steps: int | None = None  # Apalache only: --max-steps
    init: str = "init"
    step: str = "step"
    inductive: str | None = None  # the inductive invariant, for kind "inductive"
    after: bool = False  # Apalache: check the invariant after the last step only
    last_step: bool = False  # a witness schedule: the violation must be at its last step
    timeout: int = QUICK
    heap: str | None = None  # TLC's heap
    scope: str = ""

    @property
    def id(self):
        return f"{self.module}.{self.prop}"


def apalache(file, module, prop, steps, expected=OK, **kw):
    return Check(file, module, prop, expected, "apalache", steps=steps, **kw)


def tlc(file, module, prop, expected=OK, temporal=False, heap="3G", **kw):
    return Check(file, module, prop, expected, "tlc", kind="temporal" if temporal else "invariant", heap=heap, **kw)


MODULE = re.compile(r"^\s*module\s+(\w+)")
CONST = re.compile(r"^\s*const\s+\w+")
TRACE = re.compile(r"^\s*action\s+traceInit\b")
PC = re.compile(r"\bpc\s*==\s*(\d+)")


def modules(path):
    """Return {module: {"const": bool, "trace": bool, "schedule": int}} for one model file.

    schedule is the length of a fixed schedule: one more than the highest
    `pc == N` of the module.
    """
    found, name = {}, None
    for line in Path(path).read_text().splitlines():
        line = line.split("//")[0]
        m = MODULE.match(line)
        if m:
            name = m.group(1)
            found[name] = {"const": False, "trace": False, "schedule": 0}
            continue
        if name is None:
            continue
        info = found[name]
        info["const"] |= bool(CONST.match(line))
        info["trace"] |= bool(TRACE.match(line))
        for n in PC.findall(line):
            info["schedule"] = max(info["schedule"], int(n) + 1)
    return found


def module_texts(text):
    """Return {module: its text} for the top-level modules of a model file, in order.

    A module runs from its `module` line to its closing brace; braces in
    comments and strings are ignored.
    """
    lines = text.splitlines(keepends=True)
    found, i = {}, 0
    while i < len(lines):
        m = re.match(r"module\s+(\w+)\s*\{", lines[i])
        if not m:
            i += 1
            continue
        depth, block, in_block_comment = 0, [], False
        for j in range(i, len(lines)):
            block.append(lines[j])
            code, k = lines[j], 0
            while k < len(code):
                if in_block_comment:
                    end = code.find("*/", k)
                    if end < 0:
                        break
                    in_block_comment, k = False, end + 2
                elif code.startswith("/*", k):
                    in_block_comment, k = True, k + 2
                elif code.startswith("//", k):
                    break
                elif code[k] == '"':
                    end = code.find('"', k + 1)
                    k = len(code) if end < 0 else end + 1
                else:
                    depth += {"{": 1, "}": -1}.get(code[k], 0)
                    k += 1
            if depth == 0:
                break
        found[m.group(1)] = "".join(block)
        i = j + 1
    return found


def imports(text):
    """Return [(module, file or None)] for the import statements of a module's text."""
    found = []
    for m in re.finditer(r"\bimport\s+(\w+)", text):
        k, depth = m.end(), 0
        while k < len(text):  # skip the instance's parameters, which nest parentheses
            c = text[k]
            if c == "(":
                depth += 1
            elif c == ")":
                depth -= 1
            elif depth == 0 and not c.isspace():
                break
            k += 1
        rest = re.match(r'(?:\.\*|\.\w+|as\s+\w+)?\s*(?:from\s+"\./([\w.]+)")?', text[k:])
        target = rest.group(1) if rest else None
        if target and not target.endswith(".qnt"):
            target += ".qnt"
        found.append((m.group(1), target))
    return found


def isolate(sources, file, module):
    """Return {file: text} holding only the modules that module needs, in their files.

    `quint verify` sends Apalache the whole typed spec of every module loaded
    as one string. restore_witness.qnt with restore_authority.qnt, thirty and
    eighteen instances of a 700-line module, make 446 MB of it for a single
    witness: Quint 0.33.1 then fails (RangeError: Invalid string length) or
    exits 0 without a result. The modules a check needs, alone in files of
    the same names, mean the same and weigh a tenth.
    """
    texts = {}
    needed, todo = {}, [(file, module)]
    while todo:
        f, name = todo.pop()
        if name in needed.setdefault(f, set()):
            continue
        if f not in texts:
            texts[f] = module_texts((sources / f).read_text())
        needed[f].add(name)
        for dep, target in imports(texts[f][name]):
            todo.append((target or f, dep))
    return {f: "".join(f"{texts[f][n]}\n" for n in texts[f] if n in names) for f, names in needed.items()}


def witnesses(spec, file, timeout=QUICK):
    """One check per fixed witness schedule of file: its `checked` invariant fails at its last step."""
    checks = []
    for name, info in modules(spec / file).items():
        if info["trace"] and not info["const"]:
            checks.append(apalache(file, name, "checked", info["schedule"], VIOLATION,
                                   init="traceInit", step="traceStep", last_step=True, timeout=timeout,
                                   scope=f"the fixed schedule of {info['schedule']} steps"))
    return checks


def schedule(spec, file, module):
    return modules(spec / file)[module]["schedule"]


def checks(spec=SPEC):
    """The checks the models declare, in the order they run."""
    p1 = ("concurrent_protocol.qnt", "concurrent_focused.qnt", "concurrent_bounded.qnt")
    trace = dict(init="traceInit", step="traceStep")
    envelope = schedule(spec, "protocol_witness.qnt", "protocolEnvelopeSchedule")
    fence = schedule(spec, "protocol_witness.qnt", "protocolFenceSchedule")
    former = schedule(spec, "restore_witness.qnt", "restoreWitnessDeclaredLossFormerInvariant")
    bounded = dict(init="boundedInit", step="boundedStep")
    return [
        # P1, the concurrent protocol. Witness schedules, two broken
        # configurations of the full step, then the depth-bounded explorations.
        *witnesses(spec, "concurrent_witness.qnt"),
        apalache(p1[0], "concurrentProtocolEarlyDelete", "tombstoneSafe", 2, VIOLATION,
                 scope="every execution of 2 steps; a deletion that does not wait for its barriers"),
        apalache(p1[0], "concurrentProtocolNoLock", "lockedAuthority", 4, VIOLATION,
                 scope="every execution of 4 steps; calls admitted without their agents' locks"),
        tlc(p1[1], "concurrentProtocolLoadedDepth4", "checked", timeout=3600, heap="4G", **bounded,
            scope="every 4-step continuation of the checked 12-action prefix with four requests"),
        tlc(p1[1], "concurrentProtocolClosingDepth4", "checked", timeout=3600, heap="4G", **bounded,
            scope="every 4-step continuation of the checked 22-action deletion prefix with an RPC in flight"),
        # The behaviours of ADR 007 and ADR 008 begin beyond the explorations
        # from init (a reply exists after 11 steps): these start where they do.
        tlc(p1[1], "concurrentProtocolRepliedDepth6", "checked", timeout=2 * 3600, heap="6G", **bounded,
            scope="every 6-step continuation of the checked 11-action prefix with a reply not yet sent"),
        tlc(p1[1], "concurrentProtocolReplyDeliveredDepth6", "checked", timeout=2 * 3600, heap="6G", **bounded,
            scope="every 6-step continuation of the checked 16-action prefix with the reply delivered"),
        tlc(p1[1], "concurrentProtocolExpiringDepth6", "checked", timeout=2 * 3600, heap="6G", **bounded,
            scope="every 6-step continuation of the checked 9-action prefix: a request expiring with "
                  "its delivery under way and a bystander stopped"),
        tlc(p1[1], "concurrentProtocolDepth7", "checked", timeout=4 * 3600, heap="6G", **bounded,
            scope="every execution of up to 7 steps from the initial state"),
        tlc(p1[2], "concurrentProtocolDepth8", "safety", timeout=4 * 3600, heap="6G",
            scope="every execution of up to 8 steps from the initial state"),
        # Beyond this machine (12 cores, 15 GB): 2.4 million states after six of
        # its twelve steps, and growing about fivefold a step. An attempt.
        tlc(p1[2], "concurrentProtocolLoadedDepth12", "safety", timeout=3600, heap="6G",
            scope="every 12-step continuation of the four-request prefix"),
        # P3, service progress: safety and the temporal properties (TLC).
        tlc("service_progress.qnt", "serviceProgressSmall", "safety", timeout=3600,
            scope="every reachable state, two request slots and two stores"),
        tlc("service_progress.qnt", "serviceProgressSmall", "progress", temporal=True, timeout=3600),
        tlc("service_progress.qnt", "serviceProgressSmall", "observed", temporal=True, timeout=3600),
        tlc("service_progress.qnt", "serviceProgressSmall", "deletionCompletes", temporal=True, timeout=3600),
        tlc("service_progress.qnt", "serviceProgressSmall", "arrivalsEventuallyStop", VIOLATION, temporal=True,
            timeout=3600, scope="negative property: fair executions with endless arrivals exist"),
        tlc("service_progress.qnt", "serviceProgressReliable", "successfulDelivery", temporal=True, timeout=3600),
        tlc("service_progress.qnt", "serviceProgressNoPriority", "progress", VIOLATION, temporal=True, timeout=3600),
        tlc("service_progress.qnt", "serviceProgressNoOutbox", "progress", VIOLATION, temporal=True, timeout=3600),
        tlc("service_progress_controls.qnt", "serviceProgressNoSchedulingControl", "checked", VIOLATION,
            temporal=True, timeout=3600),
        tlc("service_progress_controls.qnt", "serviceProgressNoRecoveryControl", "checked", VIOLATION,
            temporal=True, timeout=3600),
        # P2, the restore authority.
        *witnesses(spec, "restore_witness.qnt"),
        apalache("restore_witness.qnt", "restoreWitnessDeclaredLossFormerInvariant", "kept", former, **trace,
                 scope=f"the fixed schedule of {former} steps: safety holds where the former guarantee fails"),
        tlc("restore_authority.qnt", "restoreAuthorityTiny", "safety", timeout=2 * 3600, heap="6G",
            scope="every reachable state, one store, one subject"),
        # The protocol composition.
        apalache("protocol_witness.qnt", "protocolEnvelopeConforming", "checked", envelope, **trace,
                 scope=f"the fixed schedule of {envelope} steps"),
        # The schedule is the conforming one: the reused envelope fails at its
        # 28th step, whose RPC then fails, so its 29th step never comes.
        apalache("protocol_witness.qnt", "protocolEnvelopeReused", "envelopeSafe", envelope, VIOLATION, **trace,
                 scope=f"the fixed schedule of {envelope} steps"),
        apalache("protocol_witness.qnt", "protocolFenceRacy", "effectsSafe", fence, VIOLATION, **trace,
                 scope=f"the fixed schedule of {fence} steps"),
        apalache("protocol_witness.qnt", "protocolAuthorityNoLock", "lockedAuthority", 4, VIOLATION,
                 step="stepWithoutLock", scope="every execution of 4 steps"),
        apalache("protocol_induction.qnt", "protocolInductive", "protocolInvariant", 0, init="baseInit",
                 step="inductionStep", after=True, scope="base: the initial state satisfies the invariant"),
        apalache("protocol_induction.qnt", "protocolInductive", "preserved", 1, init="arbitraryInit",
                 step="inductionStep", after=True, timeout=1800,
                 scope="preservation: one step from any state of the finite domains satisfying the invariant"),
        apalache("protocol_induction.qnt", "protocolInductive", "implied", 0, init="arbitraryInit",
                 step="inductionStep", after=True, scope="entailment: the invariant implies safety"),
        apalache("protocol_composition.qnt", "protocolCompositionOk", "safety", 8, timeout=1800),
        apalache("protocol_composition.qnt", "protocolCompositionEarlyTombstone", "tombstoneSafe", 3, VIOLATION),
        apalache("protocol_composition.qnt", "protocolCompositionVolatileFence", "acksSound", 5, VIOLATION),
        apalache("protocol_composition.qnt", "protocolCompositionStaleCaller", "callerAuthorized", 5, VIOLATION),
        apalache("protocol_composition.qnt", "protocolCompositionForeignMandate", "callerAuthorized", 3, VIOLATION),
        apalache("protocol_composition.qnt", "protocolCompositionNoDedup", "effectOnce", 13, VIOLATION,
                 timeout=1800),
        apalache("protocol_composition.qnt", "protocolCompositionDependentStatus", "statusIndependent", 11,
                 VIOLATION),
        # Depth wrappers, liveness and induction over the original relations.
        tlc("bounded.qnt", "messagingDepth8", "safety", timeout=1800),
        tlc("bounded.qnt", "messagingDepth10", "safety", timeout=2 * 3600, heap="5G"),
        tlc("bounded.qnt", "messagingLargeDepth8", "safety", timeout=1800),
        tlc("bounded.qnt", "lifecycleLargeDepth10", "safety", timeout=1800),
        tlc("bounded.qnt", "deliveryLargeDepth12", "safety", timeout=2 * 3600, heap="5G"),
        tlc("liveness.qnt", "messagingLiveness", "requestsTerminate", temporal=True),
        tlc("liveness.qnt", "messagingLiveness", "requestsTerminateWithoutFairness", VIOLATION, temporal=True),
        tlc("liveness.qnt", "deliveryLiveness", "progress", temporal=True),
        tlc("liveness.qnt", "deliveryLivenessNoDeadLetter", "progress", VIOLATION, temporal=True),
        Check("induction.qnt", "lifecycleInductive", "exclusiveVolume", OK, "apalache", kind="inductive",
              steps=1, inductive="volumeInductive", scope="inductive invariant volumeInductive"),
        Check("induction.qnt", "deliveryInductive", "effectOnce", OK, "apalache", kind="inductive",
              steps=1, inductive="effectsInductive", scope="inductive invariant effectsInductive"),
        # The other models: every reachable state of the correct instance, and
        # a counterexample from each broken one.
        apalache("invocation_completion.qnt", "invocationCompletion", "safety", 10),
        apalache("invocation_completion.qnt", "invocationCompletionTrustsTheStream", "noDeltaAfterOutcome", 4, VIOLATION),
        apalache("invocation_completion.qnt", "invocationCompletionAnyAttempt", "deltaMatchesCurrentAttempt", 5, VIOLATION),
        apalache("invocation_completion.qnt", "invocationCompletionCloseFiles", "deltasNeverAnOutcome", 3, VIOLATION),
        tlc("delivery.qnt", "deliveryOk", "safety", step="stepCompact"),
        tlc("delivery.qnt", "deliveryThreeKeys", "safety", step="stepCompact"),
        tlc("delivery.qnt", "deliveryLarge", "safety", step="stepCompact", timeout=2 * 3600, heap="5G"),
        apalache("delivery.qnt", "deliveryNoFifo", "fifo", 5, VIOLATION),
        apalache("delivery.qnt", "deliveryNoDedup", "effectOnce", 4, VIOLATION),
        apalache("delivery.qnt", "deliveryNoDeadLetter", "noHeadOfLineBlocking", 4, VIOLATION),
        apalache("delivery.qnt", "deliveryNonAtomicIdem", "oneEventPerKey", 4, VIOLATION),
        tlc("lifecycle.qnt", "lifecycleOk", "safety", step="stepCompact"),
        apalache("lifecycle.qnt", "lifecycleNoHostLock", "exclusiveVolume", 9, VIOLATION),
        apalache("lifecycle.qnt", "lifecycleNoHostLock", "noVmAfterDelete", 9, VIOLATION),
        apalache("lifecycle.qnt", "lifecycleNoScan", "admission", 12, VIOLATION),
        apalache("messaging.qnt", "messagingNoPostcheck", "searchNoLeak", 5, VIOLATION),
        apalache("messaging.qnt", "messagingSendChecksAds", "noRequestToHidden", 6, VIOLATION),
        apalache("messaging.qnt", "messagingNoMandateOwner", "mandateOwned", 4, VIOLATION),
        apalache("messaging.qnt", "messagingRacyAccept", "terminalStable", 7, VIOLATION),
        apalache("messaging.qnt", "messagingRacyAccept", "noLiveRequestForDeleted", 7, VIOLATION),
        apalache("composition.qnt", "compositionOk", "safety", 6),
        apalache("composition.qnt", "compositionLarge", "safety", 6, timeout=1800),
        apalache("composition.qnt", "compositionNoCancel", "noLiveRequestForDeleted", 3, VIOLATION),
        apalache("composition.qnt", "compositionNoDeliveryFence", "noStaleEffect", 7, VIOLATION),
        apalache("composition.qnt", "compositionNoLaunchFence", "noVmAfterDelete", 5, VIOLATION),
        apalache("composition.qnt", "compositionOk", "noDeleteInFlight", 6, VIOLATION,
                 scope="reachability: an agent deleted while a request is in flight"),
        apalache("composition.qnt", "compositionLarge", "noThreeActors", 3, VIOLATION,
                 scope="reachability: three agents in requests at once"),
        tlc("composition.qnt", "compositionTiny", "progress", temporal=True),
        tlc("outbox.qnt", "outboxOk", "safety"),
        apalache("outbox.qnt", "outboxSplitCommit", "oneRequestPerKey", 7, VIOLATION),
        apalache("outbox.qnt", "outboxAsyncResponse", "acceptedSurvives", 7, VIOLATION),
        tlc("durability.qnt", "durabilityOk", "safety"),
        apalache("durability.qnt", "durabilitySplitCommit", "effectOnce", 8, VIOLATION),
        apalache("durability.qnt", "durabilityMarkerFirst", "ackSurvivesCrashes", 9, VIOLATION),
        apalache("durability.qnt", "durabilityAsyncCommit", "ackSurvivesCrashes", 6, VIOLATION),
        apalache("durability.qnt", "durabilityRacyRead", "effectOnce", 7, VIOLATION),
        tlc("fencing.qnt", "fencingOk", "safety"),
        apalache("fencing.qnt", "fencingRacyCheck", "noStaleEffect", 6, VIOLATION),
        apalache("fencing.qnt", "fencingVolatileFence", "ackFenceSurvives", 5, VIOLATION),
        tlc("revocation.qnt", "revocationOk", "safety"),
        apalache("revocation.qnt", "revocationEarlyTombstone", "noStaleEffect", 6, VIOLATION),
        apalache("revocation.qnt", "revocationRacyFence", "noStaleEffect", 12, VIOLATION),
        apalache("revocation.qnt", "revocationVolatileFence", "acknowledgedSurvives", 5, VIOLATION),
        tlc("leased_delivery.qnt", "leasedDeliveryOk", "safety"),
        apalache("leased_delivery.qnt", "leasedDeliveryNoFence", "noLateEffect", 8, VIOLATION),
        apalache("leased_delivery.qnt", "leasedDeliveryNoFence", "fifo", 11, VIOLATION),
        apalache("leased_delivery.qnt", "leasedDeliveryNoDedup", "effectOnce", 4, VIOLATION),
        tlc("store_seal.qnt", "storeSealOk", "safety"),
        apalache("store_seal.qnt", "storeSealEarlyReceipt", "physicalSeal", 5, VIOLATION),
        apalache("store_seal.qnt", "storeSealVolatileBan", "physicalSeal", 7, VIOLATION),
        tlc("store_enrollment.qnt", "storeEnrollmentTiny", "safety"),
        # Each step joins its transitions before the invariants are checked
        # (search.invariant.mode=after): checking each of five invariants on
        # each transition does not end within 15 minutes.
        apalache("store_enrollment.qnt", "storeEnrollmentOk", "safety", 8, after=True),
        apalache("store_enrollment.qnt", "storeEnrollmentStaleScan", "noRestoredRevocation", 9, VIOLATION),
        apalache("store_enrollment.qnt", "storeEnrollmentOldReceipt", "currentAcks", 7, VIOLATION),
        apalache("store_enrollment.qnt", "storeEnrollmentNoRetirement", "retiredBeforeInstall", 3, VIOLATION),
        apalache("store_enrollment.qnt", "storeEnrollmentRevivedSeal", "permanentSeals", 4, VIOLATION),
        tlc("barrier_capacity.qnt", "barrierCapacityOk", "safety"),
        tlc("barrier_capacity.qnt", "barrierCapacityOk", "progress", temporal=True),
        tlc("barrier_capacity.qnt", "barrierCapacityNoPriority", "progress", VIOLATION, temporal=True),
        tlc("barrier_capacity.qnt", "barrierCapacityNoReclaim", "progress", VIOLATION, temporal=True),
        tlc("barrier_capacity.qnt", "barrierCapacityNoReservation", "progress", VIOLATION, temporal=True),
        tlc("credential_renewal.qnt", "credentialRenewalOk", "safety"),
        tlc("credential_renewal.qnt", "credentialRenewalOk", "progress", temporal=True),
        apalache("credential_renewal.qnt", "credentialRenewalEarlyCompletion", "wakeSurvives", 9, VIOLATION),
        apalache("credential_renewal.qnt", "credentialRenewalNoRecheck", "canceledWakeRefused", 7, VIOLATION),
        tlc("fair_admission.qnt", "fairAdmissionShared", "safety"),
        tlc("fair_admission.qnt", "fairAdmissionExclusive", "safety"),
        tlc("fair_admission.qnt", "fairAdmissionShared", "progress", temporal=True),
        tlc("fair_admission.qnt", "fairAdmissionExclusive", "progress", temporal=True),
        tlc("fair_admission.qnt", "fairAdmissionWriterPriority", "progress", VIOLATION, temporal=True),
        tlc("fair_admission.qnt", "fairAdmissionReaderPriority", "progress", VIOLATION, temporal=True),
        tlc("corpus_lifecycle.qnt", "corpusLifecycleOk", "safety",
            scope="every reachable state: two organizations, three builds, three releases, two agents, one host"),
        apalache("corpus_lifecycle.qnt", "corpusLifecycleNoVersionCheck", "publishedIsImmutable", 4, VIOLATION),
        apalache("corpus_lifecycle.qnt", "corpusLifecycleNoReviewCheck", "buildPublishesAtMostOnce", 3, VIOLATION),
        apalache("corpus_lifecycle.qnt", "corpusLifecycleNoOrganizationCheck",
                 "bootsOnlyBoundCorporaOfItsOrganization", 3, VIOLATION),
        apalache("corpus_lifecycle.qnt", "corpusLifecycleHotSwap", "bindingChangesAtBootOnly", 3, VIOLATION),
        apalache("corpus_lifecycle.qnt", "corpusLifecycleNoPinCheck", "gcNeverRemovesPinned", 2, VIOLATION),
        apalache("corpus_lifecycle.qnt", "corpusLifecycleEvictsActive", "gcNeverRemovesPinned", 4, VIOLATION,
                 scope="every execution of 4 steps; the plan's first rule, an active release unpinned"),
    ]


def coverage(spec, table):
    """Return the modules that need a check and have none."""
    covered = {c.module for c in table}
    missing = []
    for path in sorted(spec.glob("*.qnt")):
        for name, info in modules(path).items():
            if info["const"] or name in covered or name in UNCHECKED:
                continue
            if info["trace"] or path.name in CHECKER_FILES:
                missing.append(f"{path.name}: {name}")
    return missing


# --- the tools --------------------------------------------------------------

def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def find_tools(tools, spec=SPEC):
    """Check the toolchain against model-checkers.json; return its paths and versions.

    Raises ValueError with every problem found.
    """
    problems = []
    record_path = tools / RECORD
    if not record_path.is_file():
        raise ValueError(f"{record_path} is missing: install the JDK and Apalache as spec/README.md says")
    record = json.loads(record_path.read_text())
    java = tools / record["jdk"]["home"] / "bin" / "java"
    apalache_home = tools / record["apalache"]["home"]
    jar = apalache_home / record["apalache"]["jar"]
    quint_home = tools / record["apalache"]["quint_home"]
    package = spec / QUINT_PACKAGE
    cli = package / "dist" / "src" / "cli.js"
    node = shutil.which("node")
    if not java.is_file():
        problems.append(f"no Java runtime at {java}")
    if not jar.is_file():
        problems.append(f"no Apalache at {jar}")
    elif sha256(jar) != record["apalache"]["jar_sha256"]:
        problems.append(f"{jar} does not match the SHA-256 in {record_path}")
    if apalache_home != quint_home / f"apalache-dist-{record['apalache']['version']}" / "apalache":
        problems.append(f"Apalache must be at QUINT_HOME/apalache-dist-<version>/apalache, not {apalache_home}")
    if node is None:
        problems.append("node is not on PATH")
    if not cli.is_file():
        problems.append(f"no Quint at {package}: run `npm ci` in spec/")
    if problems:
        raise ValueError("; ".join(problems))
    pinned = json.loads((spec / "package.json").read_text())["devDependencies"]["@informalsystems/quint"]
    quint = json.loads((package / "package.json").read_text())["version"]
    if quint != pinned:
        problems.append(f"Quint {quint} is installed, spec/package.json pins {pinned}: run `npm ci` in spec/")
    m = re.search(r"DEFAULT_APALACHE_VERSION_TAG = '([^']+)'", (package / "dist/src/apalache.js").read_text())
    if not m or m.group(1) != record["apalache"]["version"]:
        problems.append(f"Quint {quint} expects Apalache {m.group(1) if m else '?'}, "
                        f"{record_path} has {record['apalache']['version']}")
    out = subprocess.run([str(java), "-version"], capture_output=True, text=True, timeout=120)
    if out.returncode != 0 or record["jdk"]["version"].split("+")[0] not in out.stderr:
        problems.append(f"{java} -version does not report {record['jdk']['version']}: {out.stderr.strip()[:200]}")
    if problems:
        raise ValueError("; ".join(problems))
    versions = {"quint": quint, "apalache": record["apalache"]["version"], "jdk": out.stderr.strip(),
                "apalache_jar_sha256": record["apalache"]["jar_sha256"], "record": record}
    return {"java": java, "jdk": java.parent.parent, "jar": jar, "quint_home": quint_home, "cli": cli,
            "node": Path(node), "versions": versions}


# --- running ----------------------------------------------------------------

def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def command(check, tools, source, directory, port, workers):
    cmd = [str(tools["node"]), str(tools["cli"]), "verify", str(source), f"--main={check.module}",
           f"--init={check.init}", f"--step={check.step}", "--verbosity=3",
           f"--server-endpoint=localhost:{port}"]
    if check.kind == "temporal":
        cmd.append(f"--temporal={check.prop}")
    else:
        cmd.append(f"--invariant={check.prop}")
    if check.kind == "inductive":
        cmd.append(f"--inductive-invariant={check.inductive}")
    if check.backend == "tlc":
        config = directory / "tlc.json"
        config.write_text(json.dumps({"maxHeap": f"-Xmx{check.heap}", "stackSize": "-Xss16m",
                                      "workers": str(workers)}, indent=2) + "\n")
        cmd += ["--backend=tlc", f"--tlc-config={config}"]
    else:
        cmd += [f"--max-steps={check.steps}", f"--out-itf={directory / 'trace.itf.json'}"]
        if check.after:
            config = directory / "apalache.json"
            config.write_text(json.dumps({"checker": {"tuning": {"search.invariant.mode": "after"}}}, indent=2) + "\n")
            cmd.append(f"--apalache-config={config}")
    return cmd


def environment(tools, directory, heap):
    env = {k: v for k, v in os.environ.items() if not k.startswith(("JAVA_", "_JAVA_", "JDK_", "QUINT_"))}
    env["PATH"] = os.pathsep.join([str(tools["java"].parent), str(tools["node"].parent), env.get("PATH", os.defpath)])
    env["JAVA_HOME"] = str(tools["jdk"])
    env["QUINT_HOME"] = str(tools["quint_home"])
    env["TMPDIR"] = str(directory / "tmp")  # TLC's states and SANY's files, never /tmp
    env["JVM_ARGS"] = f"-Xmx{heap}"  # the Apalache server
    return env


STATS = re.compile(r"([\d,]+) states generated, ([\d,]+) distinct states found, ([\d,]+) states left on queue")
DEPTH = re.compile(r"The depth of the complete state graph search is (\d+)")
PROGRESS = re.compile(r"Progress\((\d+)\).*?([\d,]+) states generated.*?([\d,]+) distinct states found.*?([\d,]+) states left on queue")


def classify(check, returncode, output, timed_out):
    """Return the status of one run: ok, violation, timeout or error."""
    if timed_out:
        return "timeout"
    if check.backend == "tlc":
        if returncode == 0 and "[ok]" in output and "Model checking completed. No error has been found." in output:
            return "ok"
        if "found a counterexample" in output and re.search(
                r"Error: (Invariant q_inv is violated|Temporal propert(y q_temporalProps was|ies were) violated)", output):
            return "violation"
        return "error"
    if returncode == 0 and "[ok] No violation found" in output:
        return "ok"
    if "[violation]" in output and "found a counterexample" in output:
        return "violation"
    return "error"


def tlc_numbers(output):
    numbers = {}
    stats = STATS.findall(output)
    if stats:
        generated, distinct, left = (int(x.replace(",", "")) for x in stats[-1])
        numbers.update(generated=generated, distinct=distinct, left=left)
    else:
        progress = PROGRESS.findall(output)
        if progress:
            depth, generated, distinct, left = progress[-1]
            numbers.update(progress_depth=int(depth), generated=int(generated.replace(",", "")),
                           distinct=int(distinct.replace(",", "")), left=int(left.replace(",", "")))
    depth = DEPTH.findall(output)
    if depth:
        numbers["depth"] = int(depth[-1])
    errors = [line.strip() for line in output.splitlines() if line.startswith("Error:")]
    if errors:
        numbers["tlc_error"] = errors[0]
    return numbers


def trace_states(path):
    try:
        return len(json.loads(path.read_text())["states"])
    except (OSError, ValueError, KeyError):
        return None


def stop_group(proc):
    for sig, wait in ((signal.SIGTERM, 20), (signal.SIGKILL, 10)):
        try:
            os.killpg(proc.pid, sig)
        except ProcessLookupError:
            return
        try:
            proc.wait(timeout=wait)
        except subprocess.TimeoutExpired:
            continue


def run_check(check, tools, sources, directory, workers, scale, apalache_heap):
    directory.mkdir(parents=True)
    (directory / "tmp").mkdir()
    port = free_port()
    src = directory / "src"
    src.mkdir()
    files = isolate(sources, check.file, check.module)
    for name, text in files.items():
        (src / name).write_text(text)
    source = src / check.file
    cmd = command(check, tools, source, directory, port, workers)
    timeout = int(check.timeout * scale)
    started = dt.datetime.now(dt.timezone.utc)
    begin = time.monotonic()
    with open(directory / "run.log", "w") as log:
        proc = subprocess.Popen(cmd, cwd=directory, env=environment(tools, directory, apalache_heap),
                                stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT,
                                start_new_session=True)
        timed_out = False
        try:
            proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
        except BaseException:  # interrupted: leave no checker behind
            stop_group(proc)
            raise
        stop_group(proc)  # also any Apalache server or TLC left behind
    seconds = round(time.monotonic() - begin, 3)
    output = (directory / "run.log").read_text(errors="replace")
    status = classify(check, proc.returncode, output, timed_out)
    result = {**dataclasses.asdict(check), "id": check.id, "command": cmd, "sources": {n: sha256(src / n) for n in sorted(files)}, "started": started.isoformat(),
              "timeout_seconds": timeout, "seconds": seconds, "returncode": proc.returncode, "status": status}
    if check.backend == "tlc":
        result.update(tlc_numbers(output))
        result["workers"] = workers
    else:
        states = trace_states(directory / "trace.itf.json") if status == VIOLATION else None
        result["trace_states"] = states
    passed = status == check.expected
    if passed and check.last_step:
        # A schedule of n steps has n + 1 states; an earlier failure is not the witness.
        passed = result.get("trace_states") == check.steps + 1
        if not passed:
            result["reason"] = f"the violation is not at the schedule's last step ({check.steps})"
    result["passed"] = passed
    shutil.rmtree(directory / "tmp", ignore_errors=True)
    (directory / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    return result


def freeze(spec, target):
    target.mkdir(parents=True)
    hashes = {}
    for path in sorted(spec.glob("*.qnt")):
        shutil.copy2(path, target / path.name)
        hashes[path.name] = sha256(path)
    if {p.name: sha256(p) for p in sorted(spec.glob("*.qnt"))} != hashes:
        raise ValueError("spec/*.qnt changed during the copy; retry")
    return hashes


def git_commit():
    out = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True, text=True)
    dirty = subprocess.run(["git", "status", "--porcelain", "--", "spec"], cwd=ROOT, capture_output=True, text=True)
    return out.stdout.strip(), bool(dirty.stdout.strip())


def line(result):
    extra = ""
    if "distinct" in result:
        extra = f" {result['distinct']:,} states"
        if "depth" in result:
            extra += f", depth {result['depth']}"
    elif result.get("trace_states"):
        extra = f" trace of {result['trace_states'] - 1} steps"
    bound = f"{result['steps']} steps" if result.get("steps") is not None else "TLC"
    mark = "PASS" if result["passed"] else "FAIL"
    return (f"{mark} {result['id']} [{bound}] expected {result['expected']}, got {result['status']} "
            f"in {result['seconds']:.0f} s{extra}")


def interrupted(signum, frame):
    raise KeyboardInterrupt(f"signal {signum}")


def main():
    signal.signal(signal.SIGTERM, interrupted)
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--tools", type=Path, default=DEFAULT_TOOLS, help="the tools directory (model-checkers.json)")
    parser.add_argument("--output", type=Path, help="a new directory for the evidence")
    parser.add_argument("--only", action="append", default=[], help="run the checks whose id matches this regex")
    parser.add_argument("--skip", action="append", default=[], help="skip the checks whose id matches this regex")
    parser.add_argument("--quick", action="store_true", help=f"only the checks limited to {QUICK} s")
    parser.add_argument("--workers", type=int, default=4, help="TLC workers (default 4)")
    parser.add_argument("--timeout-scale", type=float, default=1.0, help="multiply every time limit")
    parser.add_argument("--apalache-heap", default="4g", help="the Apalache server's heap (default 4g)")
    parser.add_argument("--list", action="store_true", help="print the checks and exit")
    args = parser.parse_args()

    table = checks()
    missing = coverage(SPEC, table)
    if missing:
        for m in missing:
            print(f"FAIL {m} needs a check in scripts/check-models.py or a reason in UNCHECKED")
        return 1
    ids = [c.id for c in table]
    if len(ids) != len(set(ids)):
        print("FAIL duplicate check ids")
        return 1
    selected = [c for c in table
                if (not args.only or any(re.search(p, c.id) for p in args.only))
                and not any(re.search(p, c.id) for p in args.skip)
                and (not args.quick or c.timeout <= QUICK)]
    # Shortest time limits first: the quick checks report within the hour, and
    # the longest explorations, the likeliest to time out, come last.
    selected.sort(key=lambda c: c.timeout)
    if args.list:
        for c in selected:
            bound = f"{c.steps} steps" if c.steps is not None else "all reachable states"
            print(f"{c.id}\t{c.file}\t{c.backend}\t{c.kind}\t{bound}\texpect {c.expected}\t{c.timeout} s")
        print(f"{len(selected)} of {len(table)} checks")
        return 0
    if not selected:
        print("FAIL no check selected")
        return 1
    try:
        tools = find_tools(args.tools.expanduser())
    except (ValueError, OSError, KeyError, subprocess.SubprocessError) as e:
        print(f"FAIL tools: {e}")
        return 2

    stamp = dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    output = (args.output or ROOT / "quint" / "results" / f"check-models-{stamp}").resolve()
    if output.exists():
        print(f"FAIL {output} exists; use a new directory")
        return 1
    output.mkdir(parents=True)
    sources = output / "sources"
    hashes = freeze(SPEC, sources)
    commit, dirty = git_commit()
    environment_record = {"commit": commit, "spec_dirty": dirty, "sources": hashes,
                          "tools": {k: v for k, v in tools["versions"].items()},
                          "workers": args.workers, "timeout_scale": args.timeout_scale,
                          "apalache_heap": args.apalache_heap, "cpus": os.cpu_count(),
                          "meminfo": Path("/proc/meminfo").read_text().splitlines()[:3]}
    (output / "environment.json").write_text(json.dumps(environment_record, indent=2) + "\n")
    print(f"{len(selected)} checks, evidence in {output}", flush=True)

    results = []
    for n, check in enumerate(selected, 1):
        directory = output / f"{n:03d}-{check.id}"
        result = run_check(check, tools, sources, directory, args.workers, args.timeout_scale, args.apalache_heap)
        result["directory"] = str(directory.relative_to(output))
        results.append(result)
        print(line(result), flush=True)
        (output / "summary.json").write_text(json.dumps({"finished": False, "results": results}, indent=2) + "\n")

    failed = [r for r in results if not r["passed"]]
    summary = {"finished": True, "passed": not failed, "checks": len(results),
               "failed": [r["id"] for r in failed], "results": results}
    (output / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(f"{len(results) - len(failed)} of {len(results)} checks as expected; summary in {output / 'summary.json'}")
    for r in failed:
        print(f"FAIL {r['id']}: {r['status']} (expected {r['expected']}){': ' + r['reason'] if 'reason' in r else ''}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
