"""Assemble a safety verdict only from complete and internally consistent solver evidence."""

import argparse
import hashlib
import json
from graphlib import TopologicalSorter
from pathlib import Path
import ir_semantics as ir


def require(condition, message):
    if not condition:
        raise ValueError(message)


def read(path):
    return json.loads(path.read_text())


def source_conjuncts(n):
    if n["kind"] == "name":
        return [n["name"]]
    require(n["kind"] == "app" and n["opcode"] == "and", "Unexpected safety property composition")
    return [name for child in n["args"] for name in source_conjuncts(child)]


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def assemble(folder, script_dir):
    rules = folder / "rules.json"
    ir.load(rules)
    goal_names = source_conjuncts(ir.rules["safety"])
    actions = [n for n, _, _ in ir.branches(ir.rules["step"], {}, ("step",))]
    require(len(actions) == len(set(actions)), "Duplicate transition in the extracted step")
    families = {}
    exports = {}
    goal_producers = {}
    sources = {}
    for entry in sorted(folder.glob("*/coverage.json")):
        family = entry.parent.name
        row = read(entry)
        families[family] = row
        lines = (entry.parent / "solver.log").read_text().splitlines()
        require(len(lines) % 2 == 0, "Malformed solver log for " + family)
        require(len(lines[::2]) == len(set(lines[::2])), "Duplicate solver response for " + family)
        actual = dict(zip(lines[::2], lines[1::2]))
        expected = {"theory_consistency": "sat", "inductive_precondition_consistency": "sat"}
        require(
            list(row["guard_satisfiability"]) == actions, "Missing or reordered guards in " + family
        )
        for name, value in row["guard_satisfiability"].items():
            # The proof projects some guards away. With the original configuration
            # these two exact guards are disabled even in the relaxed relations.
            require(
                value == ("unsat" if name in ("oldPrimaryResends", "skipRetirement") else "sat"),
                "Unexpected guard result in " + family + ": " + name,
            )
            expected["enabled_" + name] = value
        goals = row["goals"]
        verdicts = ["base", *("implies_" + g for g in goals), *actions]
        require(list(row["verdicts"]) == verdicts, "Incomplete induction queries in " + family)
        require(
            all(row["verdicts"][v] == "unsat" for v in verdicts),
            "Open or unknown query in " + family,
        )
        expected.update(row["verdicts"])
        require(expected == actual, "Recorded verdict differs from solver output in " + family)
        for export in row["exports"]:
            require(
                "lemma_" + export in goals and export not in exports,
                "Missing or ambiguous exported predicate " + export,
            )
            exports[export] = family
        for goal in goals:
            goal_producers.setdefault(goal, []).append(family)
        sources[family] = {
            name: digest(entry.parent / name)
            for name in ("coverage.json", "obligations.smt2", "solver.log")
        }
    graph = {}
    for family, row in families.items():
        require(all(k in exports for k in row["uses"]), "Unproved dependency in " + family)
        graph[family] = sorted({exports[lemma] for lemma in row["uses"]})
    topo = list(TopologicalSorter(graph).static_order())
    coverage = {}
    for g in goal_names:
        targets = [g]
        if g == "acknowledgedWritesReplicated":
            parents = read(folder / "replication-clause-map.json")
            definition = ir.call(g, ())
            require(
                definition[0] == "implies" and definition[2][0] in ("and", "actionAll"),
                "Changed replicated-write structure",
            )
            require(
                [x["from"] for x in parents] == [repr(t) for t in definition[2][1:]],
                "Replicated write case differs from source",
            )
            targets = [x["subclause"] for x in parents]
            require(len(targets) == len(set(targets)), "Duplicated replicated-write obligation")
        for label in targets:
            require(
                len(goal_producers.get(label, [])) == 1,
                "Missing or ambiguous source property " + label,
            )
        coverage[g] = {label: goal_producers[label][0] for label in targets}
    controls = read(folder / "projection-controls.json")
    require(
        len(controls) == 11
        and len({r["changed_instance_flag"] for r in controls}) == 11
        and all(r["observed"] == r["expected"] == "sat" for r in controls),
        "An expected negative control failed",
    )
    require(
        read(folder / "vacuity-control.json")["detected"] is True,
        "Contradictory proof context was accepted",
    )
    provenance = read(folder / "input-provenance.json")
    require(
        provenance["reduced_ir_sha256"] == digest(rules),
        "Proof IR differs from the compilation record",
    )
    result = {
        "module": "restoreAuthorityTiny",
        "invariant": "safety",
        "method": "unbounded SMT induction with a local conservative projector on Quint IR",
        "input": provenance,
        "source_property_count": len(goal_names),
        "source_action_count": len(actions),
        "induction_family_count": len(families),
        "closed_queries": sum(len(row["verdicts"]) for row in families.values()),
        "guard_queries": sum(len(row["guard_satisfiability"]) for row in families.values()),
        "closed_source_conjuncts": coverage,
        "dependency_order": topo,
        "dependencies": graph,
        "exported_lemmas": exports,
        "source_predicates_used": {
            name: row["uses"] for name, row in families.items() if row["uses"]
        },
        "evidence_sha256": sources,
        "control_sha256": {
            n: digest(folder / n)
            for n in (
                "projection-controls.json",
                "vacuity-control.json",
                "replication-clause-map.json",
            )
        },
        "translator_sha256": {p.name: digest(p) for p in sorted(script_dir.glob("*.py"))},
        "passed": True,
    }
    (folder / "certificate.json").write_text(json.dumps(result, indent=2) + "\n")
    print(
        "Certified",
        len(coverage),
        "source conjuncts,",
        len(actions),
        "actions,",
        len(families),
        "inductive families,",
        result["closed_queries"],
        "unsatisfiable proof queries",
    )


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("folder", type=Path)
    args = ap.parse_args()
    assemble(args.folder, Path(__file__).resolve().parent)
