#!/usr/bin/env python3
"""Induct over all exact Quint actions through conservative, pointwise field projections."""
import argparse
import ctypes
import itertools
import json
from pathlib import Path
import sys
import ir_semantics as ir
from lemmas import schema, chosen_receipt

p = argparse.ArgumentParser(description=__doc__)
p.add_argument(
    "--inconsistent-control",
    action="store_true",
    help="inject contradictory assumptions to test the audit of proof vacuity",
)
p.add_argument("rules", type=Path)
p.add_argument("solver", type=Path)
p.add_argument("out", type=Path)
args = p.parse_args()
ir.load(args.rules)


def txt(k):
    return ("str", k)


def val(k):
    return ("int", k)


def F(s, k):
    return ir.field(s, k)


def mem(s, k):
    return ("contains", s, k)


def path(assign, parts):
    v = assign[parts[0]]
    for k in parts[1:]:
        v = F(v, k) if isinstance(k, str) else ir.get(v, k)
    return v


def prop(name):
    return ir.call(name, ())


def both(*conds):
    return "(and " + " ".join(conds) + ")"


def implication(a, b):
    return f"(=> {a} {b})"


class PointInduction:
    def __init__(self, name):
        self.name = name
        self.variables = {}
        self.known = {}
        self.opaque = {}
        self.const_sorts = {}
        self.points = {}
        self.certified_support = set()
        self.assumptions = []
        self.exports = {}
        self.uses = {}
        self.formulas = []
        self.claims = []

    def variable(self, name, term, sort="Bool"):
        self.variables[name] = (sort, term)
        node = term(ir.states)
        if node in self.known:
            raise ValueError("duplicate state coordinate " + name)
        self.known[node] = (sort, name)
        return name

    def scalar_path(self, name, typ, *where):
        return self.variable(name, lambda a: path(a, where), typ)

    def set_path(self, name, key, *where):
        return self.variable(name, lambda a: mem(path(a, where), key))

    def opaque_scalar(self, n, t):
        key = (n, t)
        if key not in self.opaque:
            self.opaque[key] = f"u{len(self.opaque)}"
        return self.opaque[key]

    def receipt_type(self, n):
        return (
            (
                n[0] == "Rec"
                and set(n[1::2])
                == {txt(k) for k in ("store", "incarnation", "revision", "epoch", "subjects")}
            )
            or (n[0] == "key" and n[2] == "Receipt")
            or (n[0] == "choice" and n[2] == "receipt")
        )

    def value(self, n, hint=None):
        if n in self.known:
            return self.known[n]
        k = n[0]
        if k == "int":
            return "Int", str(n[1]) if n[1] >= 0 else f"(- {abs(n[1])})"
        if k == "bool":
            return "Bool", "true" if n[1] else "false"
        if k == "variant" and n[1][0] == "str" and n[2] == ("Tup",):
            label = "tag_" + n[1][1]
            self.const_sorts[label] = "Int"
            return "Tag", label
        if k == "key":
            self.const_sorts[n[1]] = n[2]
            return n[2], n[1]
        if self.receipt_type(n) or hint == "Receipt":
            if k == "choice":
                return "Receipt", self.opaque_scalar(n, "Receipt")
            if k in ("Rec", "get", "field", "opaqueGet"):
                values = [
                    self.value(F(n, f), t)[1]
                    for f, t in [
                        ("store", "Int"),
                        ("incarnation", "Int"),
                        ("revision", "Int"),
                        ("epoch", "Int"),
                        ("subjects", "IntSet"),
                    ]
                ]
                return "Receipt", "(mkReceipt " + " ".join(values) + ")"
        if k == "field" and self.receipt_type(n[1]) and n[1][0] in ("key", "choice"):
            receipt = self.value(n[1], "Receipt")[1]
            fld = n[2][1]
            return ("IntSet" if fld == "subjects" else "Int"), f"(receipt_{fld} {receipt})"
        if hint == "IntSet":
            if k == "Set":
                arr = "((as const (Array Int Bool)) false)"
                for elt in n[1:]:
                    arr = f'(store {arr} {self.value(elt,"Int")[1]} true)'
                return "IntSet", arr
            if k in ("union", "intersect"):
                op = "or" if k == "union" else "and"
                return (
                    "IntSet",
                    f"((_ map {op}) {self.value(n[1],hint)[1]} {self.value(n[2],hint)[1]})",
                )
        if k == "Rec" and set(n[1::2]) == {txt("event"), txt("incarnation")}:
            e = self.value(F(n, "event"), "Int")[1]
            i = self.value(F(n, "incarnation"), "Int")[1]
            return "Loss", f"(mkLoss {e} {i})"
        if (
            k == "field"
            and n[1][0] == "key"
            and n[1][2] == "Loss"
            and n[2][1] in ("event", "incarnation")
        ):
            key = self.value(n[1])[1]
            selector = "lossEvent" if n[2][1] == "event" else "lossInc"
            return "Int", f"({selector} {key})"
        if k == "ite":
            t, x = self.value(n[2], hint)
            u, y = self.value(n[3], hint or t)
            if t and not u:
                u, y = self.value(n[3], t)
            if u and not t:
                t, x = self.value(n[2], u)
            if t and t == u:
                return t, f"(ite {self.boolean(n[1])} {x} {y})"
        if k in ("iadd", "iuminus"):
            return (
                "Int",
                "("
                + ("+" if k == "iadd" else "-")
                + " "
                + " ".join(self.value(x, "Int")[1] for x in n[1:])
                + ")",
            )
        if k in (
            "not",
            "and",
            "or",
            "implies",
            "contains",
            "eq",
            "neq",
            "ilte",
            "igte",
            "ilt",
            "igt",
            "actionAll",
            "subseteq",
        ):
            return "Bool", self.boolean(n)
        if hint:
            return hint, self.opaque_scalar(n, hint)
        return None, None

    def member(self, collection, key):
        if collection[0] == "Set":
            parts = [self.boolean(ir.reduce("eq", (key, elt))) for elt in collection[1:]]
            return ("(or " + " ".join(parts) + ")") if parts else "false"
        op = collection[0]
        if op in ("union", "intersect", "exclude"):
            left = self.member(collection[1], key)
            right = self.member(collection[2], key)
            if op == "exclude":
                return f"(and {left} (not {right}))"
            return f'({"or" if op=="union" else "and"} {left} {right})'
        if op == "ite":
            return f"(ite {self.boolean(collection[1])} {self.member(collection[2],key)} {self.member(collection[3],key)})"
        if op == "filter":
            return f"(and {self.member(collection[1],key)} {self.boolean(ir.apply(collection[2],(key,)))})"
        if op == "map":
            probe = ("isolatedBinder",)
            rec = ir.apply(collection[2], (probe,))
            if (
                rec[0] == "Rec"
                and set(rec[1::2]) == {txt("event"), txt("incarnation")}
                and F(rec, "event") == probe
                and "isolatedBinder" not in repr(F(rec, "incarnation"))
            ):
                return both(
                    self.member(collection[1], F(key, "event")),
                    self.boolean(ir.reduce("eq", (F(key, "incarnation"), F(rec, "incarnation")))),
                )
        n = mem(collection, key)
        if (
            op == "field"
            and collection[2] == txt("subjects")
            and self.receipt_type(collection[1])
            and n not in self.known
        ):
            return f'(select {self.value(collection,"IntSet")[1]} {self.value(key,"Int")[1]})'
        answer = self.known[n][1] if n in self.known else self.opaque_scalar(n, "Bool")
        self.points.setdefault(collection, {})[key] = answer
        return answer

    def supports_zero(self, n):
        if n in self.certified_support:
            return True
        op = n[0]
        if op == "Set":
            return all(x == val(0) for x in n[1:])
        if op in ("filter", "exclude"):
            return self.supports_zero(n[1])
        if op == "intersect":
            return self.supports_zero(n[1]) or self.supports_zero(n[2])
        if op == "union":
            return self.supports_zero(n[1]) and self.supports_zero(n[2])
        if op == "ite":
            return self.supports_zero(n[2]) and self.supports_zero(n[3])
        return False

    def boolean(self, n):
        if n in self.known:
            return self.known[n][1]
        k = n[0]
        if k == "bool":
            return "true" if n[1] else "false"
        if k == "contains":
            return self.member(n[1], n[2])
        if k == "forall" and self.supports_zero(n[1]):
            return implication(self.member(n[1], val(0)), self.boolean(ir.apply(n[2], (val(0),))))
        if k == "subseteq" and n[1][0] == "Set":
            return both(*(self.member(n[2], x) for x in n[1][1:])) if len(n[1]) > 1 else "true"
        if k == "subseteq" and self.supports_zero(n[1]):
            return implication(self.member(n[1], val(0)), self.member(n[2], val(0)))
        if k in ("and", "or", "actionAll", "not", "implies"):
            name = {"implies": "=>", "actionAll": "and"}.get(k, k)
            return f"({name} " + " ".join(self.boolean(x) for x in n[1:]) + ")"
        if k == "ite":
            return f"(ite {self.boolean(n[1])} {self.boolean(n[2])} {self.boolean(n[3])})"
        if k in ("eq", "neq", "ilt", "ilte", "igt", "igte"):
            if n[1] == n[2] and k in ("eq", "neq"):
                return "true" if k == "eq" else "false"
            hint = "Int" if k in ("ilt", "ilte", "igt", "igte") else None
            t, x = self.value(n[1], hint)
            u, y = self.value(n[2], t or hint)
            if u and not t:
                t, x = self.value(n[1], u)
            if t and t == u:
                op = {
                    "eq": "=",
                    "neq": "distinct",
                    "ilt": "<",
                    "ilte": "<=",
                    "igt": ">",
                    "igte": ">=",
                }[k]
                return f"({op} {x} {y})"
        return self.opaque_scalar(n, "Bool")

    def register(self, label, predicate):
        self.formulas.append((label, predicate))

    def claim(self, name, predicate):
        self.claims.append((name, predicate))

    def export(self, label, *params):
        if any(p[0] != "key" for p in params) or len(set(params)) != len(params):
            raise ValueError("expected distinct arbitrary parameters for " + label)
        self.exports[label] = [p[2] for p in params]
        self.claim("lemma_" + label, lambda v: self.boolean(schema(label, *params)))

    def use(self, label, *params, receipt=False):
        self.uses[label] = "recordReceipt only" if receipt else "all states"

        def instantiate(action, guards, assign):
            actual = params
            if receipt:
                r = chosen_receipt(action, guards)
                if r is None:
                    return "true"
                actual = (r, *actual)
            return self.boolean(schema(label, *actual))

        self.assumptions.append(instantiate)

    def projected(self, assign):
        return {
            name: self.value(expr(assign), sort)[1] for name, (sort, expr) in self.variables.items()
        }

    def solve(self, init, branches):
        pre = {n: n for n in self.variables}
        inv = lambda v: both(*(f(v) for _, f in self.formulas))
        cases = {"base": "(not " + inv(self.projected(init)) + ")"}
        prior = both(inv(pre), *(assume(None, (), {}) for assume in self.assumptions))
        for label, f in self.claims:
            cases["implies_" + label] = both(prior, "(not " + f(pre) + ")")
        enabled = {}
        for name, guards, assign in branches:
            if name in cases:
                raise ValueError(name)
            enabled[name] = both(
                inv(pre),
                *(assume(name, guards, assign) for assume in self.assumptions),
                *(self.boolean(g) for g in guards),
            )
            cases[name] = both(enabled[name], "(not " + inv(self.projected(assign)) + ")")

        def smt_sort(t):
            return {"Tag": "Int", "IntSet": "(Array Int Bool)"}.get(t, t)

        for known, (typ, symbol) in self.known.items():
            if known[0] == "contains":
                self.points.setdefault(known[1], {})[known[2]] = symbol
        congruences = []
        for collection, group in self.points.items():
            if collection[0] == "field" and collection[2] == txt("subjects"):
                for key, code in group.items():
                    congruences.append(
                        f'(= {code} (select {self.value(collection,"IntSet")[1]} {self.value(key,"Int")[1]}))'
                    )
        for group in self.points.values():
            for (left, lv), (right, rv) in itertools.combinations(group.items(), 2):
                lt, lx = self.value(left)
                rt, rx = self.value(right, lt)
                if rt and not lt:
                    lt, lx = self.value(left, rt)
                if lt and lt == rt:
                    congruences.append(implication(f"(= {lx} {rx})", f"(= {lv} {rv})"))
        env = (
            {n: smt_sort(t) for n, (t, _) in self.variables.items()}
            | {v: smt_sort(t) for (_, t), v in self.opaque.items()}
            | self.const_sorts
        )
        tags = [n for n in self.const_sorts if n.startswith("tag_")]
        preamble = (
            "(declare-datatypes ((Loss 0)) (((mkLoss (lossEvent Int) (lossInc Int)))))\n(declare-datatypes ((Receipt 0)) (((mkReceipt (receipt_store Int) (receipt_incarnation Int) (receipt_revision Int) (receipt_epoch Int) (receipt_subjects (Array Int Bool))))))\n"
            + "\n".join(f"(declare-const {n} {t})" for n, t in env.items())
        )
        if congruences:
            preamble += "\n" + "\n".join(f"(assert {c})" for c in congruences)
        if len(tags) > 1:
            preamble += "\n(assert (distinct " + " ".join(tags) + "))"
        if args.inconsistent_control:
            preamble += "\n(assert false)"
        checks = f'(echo "theory_consistency")\n(check-sat)\n(echo "inductive_precondition_consistency")\n(push)\n(assert {prior})\n(check-sat)\n(pop)\n'
        all_queries = {**{"enabled_" + key: term for key, term in enabled.items()}, **cases}
        script = (
            preamble
            + "\n"
            + checks
            + "\n".join(
                f'(echo "{n}")\n(push)\n(assert {formula})\n(check-sat)\n(pop)'
                for n, formula in all_queries.items()
            )
            + "\n"
        )
        folder = args.out / self.name
        folder.mkdir(exist_ok=True)
        (folder / "obligations.smt2").write_text(script)
        raw = solve(script)
        (folder / "solver.log").write_text(raw)
        a = raw.splitlines()
        outcomes = dict(zip(a[::2], a[1::2]))
        if (
            outcomes.pop("theory_consistency", None) != "sat"
            or outcomes.pop("inductive_precondition_consistency", None) != "sat"
        ):
            raise RuntimeError("Inconsistent proof context for " + self.name)
        possible = {k: outcomes.pop("enabled_" + k, None) for k in enabled}
        if any(v not in ("sat", "unsat") for v in possible.values()):
            raise RuntimeError("Unknown guard satisfiability")
        if list(outcomes) != list(cases):
            raise RuntimeError(raw[:900])
        (folder / "coverage.json").write_text(
            json.dumps(
                {
                    "lemmas": [k for k, _ in self.formulas],
                    "goals": [k for k, _ in self.claims],
                    "verdicts": outcomes,
                    "guard_satisfiability": possible,
                    "exports": self.exports,
                    "uses": self.uses,
                },
                indent=2,
            )
            + "\n"
        )
        return {n: v for n, v in outcomes.items() if v != "unsat"}


def fencing(p):
    for k, t in [
        ("epoch", "Int"),
        ("oldEpoch", "Int"),
        ("primaryLost", "Bool"),
        ("rootAvailable", "Bool"),
        ("staleWriter", "Bool"),
        ("hasStandby", "Bool"),
        ("link", "Bool"),
        ("degraded", "Bool"),
        ("apiOpen", "Bool"),
        ("reconciled", "Bool"),
    ]:
        p.scalar_path(k, t, "s", k)
    p.register(
        "fencing",
        lambda v: both(
            f'(not {v["staleWriter"]})',
            f'(<= {v["oldEpoch"]} {v["epoch"]})',
            implication(f'(not {v["primaryLost"]})', f'(< {v["oldEpoch"]} {v["epoch"]})'),
            implication(v["primaryLost"], f'(not {v["rootAvailable"]})'),
        ),
    )


def durable(name, ever, root_name):
    p = PointInduction(name)
    fencing(p)
    key = ("key", "k", "Loss" if root_name == "lost" else "Int")
    for n, where in [
        ("ever", ("s", ever)),
        ("rootElem", ("root", root_name)),
        ("replicaElem", ("s", "replica", root_name)),
        ("receivedElem", ("s", "received", root_name)),
    ]:
        p.set_path(n, key, *where)
    exact = prop(name)
    if not (
        exact == ("subseteq", path(ir.states, ("s", ever)), path(ir.states, ("root", root_name)))
    ):
        raise ValueError("Source operator or argument shape changed in durable")
    target = lambda v: implication(v["ever"], v["rootElem"])
    p.register("authority retains acknowledged members", target)
    p.register(
        "standby retains acknowledged members",
        lambda v: implication(both(v["hasStandby"], v["ever"]), v["replicaElem"]),
    )
    p.register(
        "received and durable replicas agree pointwise",
        lambda v: f'(= {v["replicaElem"]} {v["receivedElem"]})',
    )
    p.claim(name, target)
    return p


def database(name, root_field, pg_field):
    p = PointInduction(name)
    fencing(p)
    k = ("key", "k", "Int")
    p.set_path("r", k, "root", root_field)
    p.set_path("pg", k, "s", "pg", pg_field)
    exact = prop(name)
    if not (
        exact
        == (
            "implies",
            path(ir.states, ("s", "apiOpen")),
            (
                "subseteq",
                path(ir.states, ("root", root_field)),
                path(ir.states, ("s", "pg", pg_field)),
            ),
        )
    ):
        raise ValueError("Source operator or argument shape changed in database")
    p.register(
        "API opens after reconciliation", lambda v: implication(v["apiOpen"], v["reconciled"])
    )
    p.register(
        "a reconciled database covers the authority",
        lambda v: implication(both(v["reconciled"], v["r"]), v["pg"]),
    )
    p.claim(name, lambda v: implication(both(v["apiOpen"], v["r"]), v["pg"]))
    return p


def phase_checks():
    p = PointInduction("retiredBeforeInstall")
    fencing(p)
    zero = val(0)
    for n, t in [("phase", "Tag"), ("alive", "Bool"), ("writer", "Int")]:
        p.scalar_path(n, t, "s", "stores", zero, n)
    for n in ("Installing", "Sealed"):
        p.value(prop(n))
    invariant = lambda v: implication(
        f'(or (= {v["phase"]} tag_Installing) (= {v["phase"]} tag_Sealed))',
        both(f'(not {v["alive"]})', f'(= {v["writer"]} (- 1))'),
    )
    p.register("installation and sealed phases are physically retired", invariant)
    p.claim(p.name, lambda v: p.boolean(prop(p.name)))
    return p


def freshness():
    p = PointInduction("identitiesFresh")
    fencing(p)
    zero = val(0)
    for n, where in [
        ("r", ("root", "incarnations", zero)),
        ("rep", ("s", "replica", "incarnations", zero)),
        ("rx", ("s", "received", "incarnations", zero)),
        ("high", ("s", "highIncarnation", zero)),
    ]:
        p.scalar_path(n, "Int", *where)
    p.register(
        "authority incarnation meets high water mark", lambda v: f'(>= {v["r"]} {v["high"]})'
    )
    p.register(
        "standby incarnation meets high water mark",
        lambda v: implication(v["hasStandby"], f'(>= {v["rep"]} {v["high"]})'),
    )
    p.register(
        "synchronous receipt and replica have the same incarnation",
        lambda v: f'(= {v["rx"]} {v["rep"]})',
    )
    p.claim(p.name, lambda v: p.boolean(prop(p.name)))
    return p


def divergence():
    p = PointInduction("divergenceReported")
    fencing(p)
    zero = val(0)
    p.scalar_path("r", "Int", "root", "incarnations", zero)
    p.scalar_path("pg", "Int", "s", "pg", "incarnations", zero)
    p.set_path("reported", zero, "s", "reported")
    p.register(
        "API opens after reconciliation", lambda v: implication(v["apiOpen"], v["reconciled"])
    )
    p.register(
        "reconciled divergent store reported",
        lambda v: implication(
            both(v["reconciled"], f'(distinct {v["r"]} {v["pg"]})'), v["reported"]
        ),
    )
    p.claim(p.name, lambda v: p.boolean(prop(p.name)))
    return p


def access():
    p = PointInduction("noRevivedAccess")
    fencing(p)
    k = ("key", "k", "Int")
    for n, where in [
        ("r", ("root", "accessRevoked")),
        ("pg", ("s", "pg", "accessRevoked")),
        ("ever", ("s", "everRevokedAccess")),
        ("rep", ("s", "replica", "accessRevoked")),
        ("rx", ("s", "received", "accessRevoked")),
        ("degradedAccess", ("s", "degradedAccess")),
    ]:
        p.set_path(n, k, *where)
    p.register(
        "API opens after reconciliation", lambda v: implication(v["apiOpen"], v["reconciled"])
    )
    p.register(
        "reconciled PostgreSQL retains revoked access",
        lambda v: implication(both(v["reconciled"], v["ever"]), v["pg"]),
    )
    p.register("authority retains all revoked access", lambda v: implication(v["ever"], v["r"]))
    p.register(
        "received and durable replica access records agree", lambda v: f'(= {v["rep"]} {v["rx"]})'
    )
    token = p.boolean(mem(prop("TOKENS"), k))
    p.register(
        "replicated or tracked during degraded access writes",
        lambda v: implication(
            both(v["hasStandby"], v["ever"]), f'(or {v["rep"]} {v["degradedAccess"]})'
        ),
    )
    p.register(
        "only degraded bearer-token writes may be outstanding",
        lambda v: implication(
            both(v["hasStandby"], v["ever"]), f'(or {v["rep"]} (and {v["degraded"]} {token}))'
        ),
    )
    if not (
        prop(p.name)
        == (
            "implies",
            F(ir.states["s"], "apiOpen"),
            (
                "subseteq",
                F(ir.states["s"], "everRevokedAccess"),
                F(F(ir.states["s"], "pg"), "accessRevoked"),
            ),
        )
    ):
        raise ValueError("Source operator or argument shape changed in access")
    p.claim(p.name, lambda v: implication(both(v["apiOpen"], v["ever"]), v["pg"]))
    return p


def erased():
    p = PointInduction("erasedKeysUnavailable")
    fencing(p)
    k = val(0)
    for n, where in [
        ("r", ("root", "destroyedKeys")),
        ("ever", ("s", "everDestroyed")),
        ("rep", ("s", "replica", "destroyedKeys")),
        ("rx", ("s", "received", "destroyedKeys")),
        ("cached", ("s", "stores", k, "cachedKeys")),
    ]:
        p.set_path(n, k, *where)
    p.scalar_path("leaked", "Bool", "s", "leakedRevokedData")
    p.register("concrete sticky error remains unset", lambda v: f'(not {v["leaked"]})')
    p.register("authority preserves destruction", lambda v: implication(v["ever"], v["r"]))
    p.register(
        "standby preserves destruction",
        lambda v: implication(both(v["hasStandby"], v["ever"]), v["rep"]),
    )
    p.register("replicated roots agree on destruction", lambda v: f'(= {v["rep"]} {v["rx"]})')
    p.register(
        "destroyed keys have no cached copy",
        lambda v: implication(v["ever"], f'(not {v["cached"]})'),
    )
    p.claim(p.name, lambda v: p.boolean(prop(p.name)))
    return p


def sealed():
    p = PointInduction("permanentSeals")
    fencing(p)
    zero = val(0)
    k = ("key", "k", "Int")
    for n, where in [
        ("r", ("root", "sealed")),
        ("e", ("s", "everSealed")),
        ("rep", ("s", "replica", "sealed")),
        ("rx", ("s", "received", "sealed")),
    ]:
        p.set_path(n, zero, *where)
    p.set_path("everAny", k, "s", "everSealed")
    p.scalar_path("phase", "Tag", "s", "stores", zero, "phase")
    tag = p.value(prop("Sealed"))[1]
    key = p.value(k)[1]
    domain = lambda v: implication(v["everAny"], f"(= {key} 0)")
    p.register("only configured store IDs can be sealed", domain)
    p.register("sealed phase survives", lambda v: implication(v["e"], f'(= {v["phase"]} {tag})'))
    p.register("authority remembers seals", lambda v: implication(v["e"], v["r"]))
    p.register(
        "standby remembers seals", lambda v: implication(both(v["hasStandby"], v["e"]), v["rep"])
    )
    p.register("replicas agree on seals", lambda v: f'(= {v["rx"]} {v["rep"]})')
    exact = prop(p.name)
    if not (
        exact[0] == "forall"
        and exact[1] == F(ir.states["s"], "everSealed")
        and (prop("STORES") == ("Set", zero))
    ):
        raise ValueError("Source operator or argument shape changed in sealed")
    p.claim(
        p.name,
        lambda v: both(domain(v), implication(v["e"], p.boolean(ir.apply(exact[2], (zero,))))),
    )
    return p


def reruns():
    p = PointInduction("rerunsFollowDeclaredLoss")
    fencing(p)
    k = ("key", "lossK", "Loss")
    for prefix, base in [("r", ("root",)), ("rep", ("s", "replica")), ("rx", ("s", "received"))]:
        for suffix, leaf in [("Run", "rerun"), ("Lost", "lost")]:
            p.set_path(prefix + suffix, k, *base, leaf)
        p.register(
            prefix + " reruns refer to declared loss",
            lambda v, n=prefix: implication(v[n + "Run"], v[n + "Lost"]),
        )
    original = prop(p.name)
    if not (original == ("subseteq", F(ir.states["root"], "rerun"), F(ir.states["root"], "lost"))):
        raise ValueError("Source operator or argument shape changed in reruns")
    p.claim(p.name, lambda v: implication(v["rRun"], v["rLost"]))
    return p


def named():
    p = PointInduction("lossesNameAcknowledgedWork")
    fencing(p)
    k = ("key", "lossK", "Loss")
    event = F(k, "event")
    p.set_path("ever", event, "s", "everAcked")
    for prefix, base in [("r", ("root",)), ("rep", ("s", "replica")), ("rx", ("s", "received"))]:
        p.set_path(prefix + "Lost", k, *base, "lost")
        p.set_path(prefix + "Committed", event, *base, "committed")
        for suffix in ("Lost", "Committed"):
            p.register(
                prefix + suffix + " refers to acknowledged work",
                lambda v, n=prefix + suffix: implication(v[n], v["ever"]),
            )
    original = prop(p.name)
    if not (
        original[0] == "forall"
        and original[1] == F(ir.states["root"], "lost")
        and (ir.apply(original[2], (k,)) == mem(F(ir.states["s"], "everAcked"), event))
    ):
        raise ValueError("Source operator or argument shape changed in named")
    p.claim(p.name, lambda v: implication(v["rLost"], v["ever"]))
    return p


def outcomes():
    p = PointInduction("replicatedOutcomes")
    fencing(p)
    k = ("key", "k", "Int")
    for n, where in [
        ("r", ("root", "committed")),
        ("rep", ("s", "replica", "committed")),
        ("rx", ("s", "received", "committed")),
        ("e", ("s", "everAcked")),
        ("d", ("s", "degradedAcks")),
        ("w", ("s", "window")),
    ]:
        p.set_path(n, k, *where)
    p.register(
        "outcomes are kept or their loss window is declared",
        lambda v: implication(v["e"], f'(or {v["r"]} {v["w"]})'),
    )
    p.register(
        "degraded mode requires a standby", lambda v: implication(v["degraded"], v["hasStandby"])
    )
    p.register(
        "only degraded mode has outstanding degraded acknowledgments",
        lambda v: implication(v["d"], v["degraded"]),
    )
    p.register("received and durable outcomes agree", lambda v: f'(= {v["rep"]} {v["rx"]})')
    target = lambda v: implication(
        both(v["hasStandby"], v["e"]), f'(or {v["rep"]} {v["d"]} {v["w"]})'
    )
    p.register("standby outcomes or explicitly tracked exceptions", target)
    p.claim("replicated outcomes", target)
    p.export("acknowledgedOutcomeIsCurrentOrInWindow", k)
    return p


def outcome_support():
    p = PointInduction("outcomeSupport")
    fencing(p)
    k = ("key", "ev", "Int")
    kname = p.value(k)[1]
    for n, where in [
        ("ever", ("s", "everAcked")),
        ("root", ("root", "committed")),
        ("rep", ("s", "replica", "committed")),
        ("rx", ("s", "received", "committed")),
    ]:
        p.set_path(n, k, *where)
        p.register(
            n + " contains only configured events",
            lambda v, s=n: implication(v[s], f"(= {kname} 0)"),
        )
    p.export("outcomesHaveConfiguredIDs", k)
    p.claim(
        "everAcked and root committed are subsets of the singleton EVENTS",
        lambda v: both(
            implication(v["ever"], f"(= {kname} 0)"), implication(v["root"], f"(= {kname} 0)")
        ),
    )
    return p


def remembered():
    p = PointInduction("lossesRemembered")
    fencing(p)
    k = ("key", "loss", "Loss")
    p.set_path("ever", k, "s", "everDeclared")
    for n, base in [("r", ("root",)), ("rep", ("s", "replica")), ("rx", ("s", "received"))]:
        p.set_path(n, k, *base, "lost")
        p.register(n + " losses are remembered", lambda v, n=n: implication(v[n], v["ever"]))
    p.export("declaredLossIsRemembered", k)
    p.claim("root losses are remembered for every loss", lambda v: implication(v["r"], v["ever"]))
    return p


def loss_guarantees():
    p = PointInduction("lossGuarantees")
    fencing(p)
    zero = val(0)
    st = ir.states
    # These two lemmas are separately established for arbitrary event/loss values.
    p.certified_support = {F(st["s"], "everAcked"), F(st["root"], "committed")}
    for n, where in [
        ("e", ("s", "everAcked")),
        ("r", ("root", "committed")),
        ("w", ("s", "window")),
        ("seen", ("s", "stores", zero, "disk", "seen")),
        ("eff", ("s", "stores", zero, "disk", "effects")),
    ]:
        p.set_path(n, zero, *where)
    for n, t in [("phase", "Tag"), ("writer", "Int"), ("incarnation", "Int")]:
        p.scalar_path(n, t, "s", "stores", zero, n)
    p.scalar_path("undeclared", "Bool", "s", "undeclaredLoss")
    p.scalar_path("silent", "Bool", "s", "silentRerun")
    for n, where in [("l", ("root", "lost")), ("everLoss", ("s", "everDeclared"))]:

        def expr(a, where=where):
            inc = path(a, ("s", "stores", zero, "incarnation"))
            k = ir.call("lossAt", (zero, inc))
            return mem(path(a, where), k)

        p.variable(n, expr)
    for name in ("Ready", "Draining"):
        p.value(prop(name))
    p.register("undeclared loss monitor stays clear", lambda v: f'(not {v["undeclared"]})')
    p.register("silent rerun monitor stays clear", lambda v: f'(not {v["silent"]})')
    p.register(
        "writer is absent or the single event in an executing phase",
        lambda v: implication(
            f'(distinct {v["writer"]} (- 1))',
            both(
                f'(= {v["writer"]} 0)',
                f'(or (= {v["phase"]} tag_Ready) (= {v["phase"]} tag_Draining))',
            ),
        ),
    )
    p.register(
        "executing image retains or has announced every acknowledgment",
        lambda v: implication(
            both(v["e"], f'(or (= {v["phase"]} tag_Ready) (= {v["phase"]} tag_Draining))'),
            f'(or (and {v["seen"]} {v["eff"]}) {v["everLoss"]} {v["w"]})',
        ),
    )
    p.use("acknowledgedOutcomeIsCurrentOrInWindow", zero)
    current_loss = ir.call("lossAt", (zero, path(st, ("s", "stores", zero, "incarnation"))))
    p.use("declaredLossIsRemembered", current_loss)
    p.uses["outcomesHaveConfiguredIDs"] = "support of quantified sets, for every event"
    p.claim("noUndeclaredLoss", lambda v: p.boolean(prop("noUndeclaredLoss")))
    p.claim("noSilentRerun", lambda v: p.boolean(prop("noSilentRerun")))
    return p


def receipt_sound():
    p = PointInduction("receiptHistory")
    fencing(p)
    zero = val(0)
    k = ("key", "subjectK", "Int")
    r = ("key", "receiptR", "Receipt")
    for n, typ, where in [
        ("storeInc", "Int", ("s", "stores", zero, "incarnation")),
        ("scanStore", "Int", ("s", "scans", zero, "store")),
        ("scanInc", "Int", ("s", "scans", zero, "incarnation")),
    ]:
        p.scalar_path(n, typ, *where)
    p.set_path("member", r, "s", "receipts")
    p.set_path("fence", k, "s", "stores", zero, "fences")
    p.set_path("scanSubject", k, "s", "scans", zero, "subjects")
    rid = p.value(F(r, "store"), "Int")[1]
    inc = p.value(F(r, "incarnation"), "Int")[1]
    subj = p.member(F(r, "subjects"), k)
    p.register("scan identity is the configured store", lambda v: f'(= {v["scanStore"]} 0)')
    p.register(
        "receipts come from the configured store",
        lambda v: implication(v["member"], f"(= {rid} 0)"),
    )
    p.register(
        "a receipt never comes from a future incarnation",
        lambda v: implication(v["member"], f'(<= {inc} {v["storeInc"]})'),
    )
    p.register(
        "same-image receipts certify installed fences",
        lambda v: implication(both(v["member"], f'(= {inc} {v["storeInc"]})', subj), v["fence"]),
    )
    p.export("sameImageReceiptsCertifyFences", r, k)
    p.claim(
        "receipt history",
        lambda v: implication(
            v["member"],
            both(
                f"(= {rid} 0)",
                f'(<= {inc} {v["storeInc"]})',
                implication(both(f'(= {inc} {v["storeInc"]})', subj), v["fence"]),
            ),
        ),
    )
    return p


def acks():
    p = PointInduction("acksSound")
    fencing(p)
    zero = val(0)
    k = ("key", "subjectK", "Int")
    p.set_path("fence", k, "s", "stores", zero, "fences")
    p.scalar_path("storeInc", "Int", "s", "stores", zero, "incarnation")
    p.register("store incarnations start at one", lambda v: f'(>= {v["storeInc"]} 1)')
    for prefix, base in [("r", ("root",)), ("rep", ("s", "replica")), ("rx", ("s", "received"))]:
        p.scalar_path(prefix + "Inc", "Int", *base, "incarnations", zero)
        p.scalar_path(prefix + "Ack", "Int", *base, "acks", zero, "incarnation")
        p.set_path(prefix + "Subject", k, *base, "acks", zero, "subjects")

        def qualifier(v, body, b=prefix):
            return body if b == "r" else implication(v["hasStandby"], body)

        p.register(
            prefix + " incarnation order",
            lambda v, n=prefix, q=qualifier: q(v, f'(<= {v["storeInc"]} {v[n+"Inc"]})'),
        )
        p.register(
            prefix + " receipt was issued by a present or previous image",
            lambda v, n=prefix, q=qualifier: q(v, f'(<= {v[n+"Ack"]} {v["storeInc"]})'),
        )
        p.register(
            prefix + " matching acknowledgment has installed fences",
            lambda v, n=prefix, q=qualifier: q(
                v,
                implication(
                    f'(= {v[n+"Ack"]} {v[n+"Inc"]})',
                    both(
                        f'(= {v["storeInc"]} {v[n+"Inc"]})',
                        implication(v[n + "Subject"], v["fence"]),
                    ),
                ),
            ),
        )
    for n in ("rep", "rx"):
        p.register(
            "reserved incarnation synchronous " + n,
            lambda v, n=n: implication(v["hasStandby"], f'(= {v["rInc"]} {v[n+"Inc"]})'),
        )
    p.use("sameImageReceiptsCertifyFences", k, receipt=True)
    p.export("acceptedAckCertifiesFence", k)
    actual = prop(p.name)
    # The outer singleton forall was expanded by the Quint IR projector. The
    # integer k is arbitrary, so this query establishes the original subset.
    if not (
        actual[0] == "and"
        and len(actual) == 2
        and (actual[1][0] == "implies")
        and (actual[1][2][0] == "and")
        and (actual[1][2][2][0] == "subseteq")
    ):
        raise ValueError("Source operator or argument shape changed in acks")
    premise, success = actual[1][1:]
    subset = success[2]
    p.claim(
        p.name,
        lambda v: implication(
            p.boolean(premise),
            both(
                p.boolean(success[1]), implication(p.member(subset[1], k), p.member(subset[2], k))
            ),
        ),
    )
    return p


def scope_revision():
    p = PointInduction("scopeAndReceiptRevision")
    fencing(p)
    zero = val(0)
    r = ("key", "receiptR", "Receipt")
    for n, base in [("r", ("root",)), ("rep", ("s", "replica")), ("rx", ("s", "received"))]:
        p.set_path(n + "Pending", zero, *base, "pending")
        p.scalar_path(n + "Rev", "Int", *base, "revision")
        p.scalar_path(n + "Scope", "Int", *base, "scoped", zero)
        p.register(
            n + " singleton pending subject determines revision and scope",
            lambda v, n=n: both(
                f'(= {v[n+"Rev"]} (ite {v[n+"Pending"]} 1 0))', f'(= {v[n+"Scope"]} {v[n+"Rev"]})'
            ),
        )
    p.scalar_path("scanRev", "Int", "s", "scans", zero, "revision")
    p.set_path("scanSubject", zero, "s", "scans", zero, "subjects")
    p.set_path("member", r, "s", "receipts")
    rr = p.value(F(r, "revision"), "Int")[1]
    rs = p.member(F(r, "subjects"), zero)
    p.register(
        "a positive scan revision includes the singleton subject",
        lambda v: implication(f'(>= {v["scanRev"]} 1)', v["scanSubject"]),
    )
    p.register(
        "positive receipt revision includes the singleton subject",
        lambda v: implication(both(v["member"], f"(>= {rr} 1)"), rs),
    )
    p.export("positiveRevisionReceiptsCoverSubject", r)
    p.export("pendingHasPositiveScope")
    p.claim(
        "receipt revision covers subject",
        lambda v: implication(both(v["member"], f"(>= {rr} 1)"), rs),
    )
    p.claim(
        "current pending subject implies positive scope",
        lambda v: implication(v["rPending"], f'(>= {v["rScope"]} 1)'),
    )
    return p


def ack_revision():
    p = PointInduction("ackRevision")
    fencing(p)
    zero = val(0)
    st = ir.states
    for n, base in [("r", ("root",)), ("rep", ("s", "replica")), ("rx", ("s", "received"))]:
        p.scalar_path(n + "Rev", "Int", *base, "acks", zero, "revision")
        p.set_path(n + "Subject", zero, *base, "acks", zero, "subjects")
        p.register(
            n + " accepted positive revision names the singleton subject",
            lambda v, n=n: implication(f'(>= {v[n+"Rev"]} 1)', v[n + "Subject"]),
        )
    p.use("positiveRevisionReceiptsCoverSubject", receipt=True)
    p.export("positiveAckCoversSubject")
    p.claim(
        "current positive acknowledgment names subject",
        lambda v: implication(f'(>= {v["rRev"]} 1)', v["rSubject"]),
    )
    return p


def revoked_pending():
    p = PointInduction("revokedImpliesPending")
    fencing(p)
    k = ("key", "subject", "Int")
    p.set_path("e", k, "s", "everRevoked")
    for n, base in [("r", ("root",)), ("rep", ("s", "replica")), ("rx", ("s", "received"))]:
        p.set_path(n + "Revoked", k, *base, "revoked")
        p.set_path(n + "Pending", k, *base, "pending")
        p.register(
            n + " revocations were begun",
            lambda v, n=n: implication(v[n + "Revoked"], v[n + "Pending"]),
        )
        p.register(
            n + " revocations were acknowledged",
            lambda v, n=n: implication(v[n + "Revoked"], v["e"]),
        )
        p.register(
            n + " recalls every revocation as required",
            lambda v, n=n: implication(
                v["e"] if n == "r" else both(v["hasStandby"], v["e"]), v[n + "Revoked"]
            ),
        )
    p.export("revocationsAreCurrentAndPending", k)
    p.claim(
        "acknowledged revocation is current and pending",
        lambda v: both(f'(= {v["e"]} {v["rRevoked"]})', implication(v["e"], v["rPending"])),
    )
    return p


def executable_fences():
    p = PointInduction("executableFences")
    fencing(p)
    zero = val(0)
    st = ir.states
    for n, t, where in [
        ("phase", "Tag", ("s", "stores", zero, "phase")),
        ("alive", "Bool", ("s", "stores", zero, "alive")),
        ("writer", "Int", ("s", "stores", zero, "writer")),
        ("ackRev", "Int", ("root", "acks", zero, "revision")),
        ("ackInc", "Int", ("root", "acks", zero, "incarnation")),
        ("inc", "Int", ("root", "incarnations", zero)),
        ("scope", "Int", ("root", "scoped", zero)),
        ("bad", "Bool", ("s", "badActivation")),
        ("stale", "Bool", ("s", "staleEffect")),
    ]:
        p.scalar_path(n, t, *where)
    for n, where in [
        ("pending", ("root", "pending")),
        ("revoked", ("root", "revoked")),
        ("ever", ("s", "everRevoked")),
        ("fence", ("s", "stores", zero, "fences")),
        ("acks", ("root", "acks", zero, "subjects")),
    ]:
        p.set_path(n, zero, *where)
    for name in ("Ready", "Draining"):
        p.value(prop(name))

    def active(v):
        return both(v["alive"], f'(or (= {v["phase"]} tag_Ready) (= {v["phase"]} tag_Draining))')

    p.register("activation monitor never reports a missing barrier", lambda v: f'(not {v["bad"]})')
    p.register("old deliveries never apply a stale effect", lambda v: f'(not {v["stale"]})')
    p.register(
        "executing stores enforce every acknowledged revocation",
        lambda v: implication(both(active(v), v["ever"]), v["fence"]),
    )
    p.register(
        "an in-flight writer is executing the singleton unfenced event",
        lambda v: implication(
            f'(distinct {v["writer"]} (- 1))',
            both(f'(= {v["writer"]} 0)', active(v), f'(not {v["fence"]})'),
        ),
    )
    p.use("revocationsAreCurrentAndPending", zero)
    p.use("pendingHasPositiveScope")
    p.use("positiveAckCoversSubject")
    p.use("acceptedAckCertifiesFence", zero)
    p.claim("activationCurrent", lambda v: p.boolean(prop("activationCurrent")))
    p.claim("noStaleEffect", lambda v: p.boolean(prop("noStaleEffect")))
    # The exact source checks all subjects in reach(0), a literal singleton
    # computed from the instance. No bound is imposed on abstract set values.
    p.claim("noRestoredRevocation", lambda v: p.boolean(prop("noRestoredRevocation")))
    return p


def old_primary():
    p = PointInduction("oldPrimaryFenced")
    fencing(p)
    p.claim(p.name, lambda v: p.boolean(prop(p.name)))
    return p


def replica_claims(jobs):
    exact = prop("acknowledgedWritesReplicated")
    if not (exact[0] == "implies" and exact[1] == F(ir.states["s"], "hasStandby")):
        raise ValueError("Source operator or argument shape changed in replica_claims")
    clauses = exact[2]
    if not (clauses[0] in ("and", "actionAll") and len(clauses) == 8):
        raise ValueError("Source operator or argument shape changed in replica_claims")
    sources = dict((job.name, job) for job in jobs)
    record = []
    families = [
        "replicatedOutcomes",
        "revocationsSurvive",
        "noRevivedAccess",
        "permanentSeals",
        "keyDestructionSurvives",
        "declaredLossesSurvive",
        "identitiesFresh",
    ]
    for number, (clause, family) in enumerate(zip(clauses[1:], families), 1):
        job = sources[family]
        label = "acknowledgedWritesReplicated." + str(number)
        if number <= 6:
            if not (clause[0] == "subseteq"):
                raise ValueError("Source operator or argument shape changed in replica_claims")
            key = ("key", "k", "Loss" if number == 6 else "Int")

            def claim(v, c=clause, k=key, proof=job):
                return implication(
                    proof.boolean(exact[1]),
                    implication(proof.member(c[1], k), proof.member(c[2], k)),
                )

        else:

            def claim(v, c=clause, proof=job):
                return implication(proof.boolean(exact[1]), proof.boolean(c))

        job.claim(label, claim)
        record.append({"subclause": label, "certificate": family, "from": repr(clause)})
    (args.out / "replication-clause-map.json").write_text(json.dumps(record, indent=2) + "\n")


z = ctypes.CDLL(str(args.solver.resolve()))
for name, dom, res in [
    ("Z3_mk_config", [], ctypes.c_void_p),
    ("Z3_mk_context", [ctypes.c_void_p], ctypes.c_void_p),
    ("Z3_eval_smtlib2_string", [ctypes.c_void_p, ctypes.c_char_p], ctypes.c_char_p),
    ("Z3_del_context", [ctypes.c_void_p], None),
    ("Z3_del_config", [ctypes.c_void_p], None),
]:
    f = getattr(z, name)
    f.argtypes = dom
    f.restype = res


def solve(script):
    c = z.Z3_mk_config()
    s = z.Z3_mk_context(c)
    res = z.Z3_eval_smtlib2_string(s, script.encode()).decode()
    z.Z3_del_context(s)
    z.Z3_del_config(c)
    return res


init = ir.branches(ir.rules["init"], {}, ("init",))[0][2]
leaves = ir.branches(ir.rules["step"], {}, ("step",))
jobs = [
    durable("revocationsSurvive", "everRevoked", "revoked"),
    durable("keyDestructionSurvives", "everDestroyed", "destroyedKeys"),
    durable("declaredLossesSurvive", "everDeclared", "lost"),
    database("subjectsCopiedBack", "pending", "subjects"),
    database("deletionsResumed", "sealed", "sealed"),
    phase_checks(),
    freshness(),
    divergence(),
    access(),
    erased(),
    sealed(),
    reruns(),
    named(),
    outcomes(),
    outcome_support(),
    remembered(),
    loss_guarantees(),
    receipt_sound(),
    acks(),
    scope_revision(),
    ack_revision(),
    revoked_pending(),
    executable_fences(),
    old_primary(),
]
replica_claims(jobs)
failed = {}
for job in jobs:
    bad = job.solve(init, leaves)
    if bad:
        failed[job.name] = bad
    print(job.name, bad or "all unsat")
if failed:
    raise SystemExit(1)
