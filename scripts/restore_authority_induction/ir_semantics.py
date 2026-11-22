"""Selected structural Quint IR reductions. All omitted guards are relaxed in the solver."""

from functools import lru_cache
import itertools
import json
from pathlib import Path

rules = {}
states = {"s": ("state", "s"), "root": ("state", "root")}
choices = itertools.count()


def load(path):
    rules.update(json.loads(Path(path).read_text()))
    call.cache_clear()


def apply(f, vals):
    if f[0] != "opaqueLambda":
        raise ValueError("expected lambda")
    n = json.loads(f[1])
    return evaluate(n["expr"], dict(f[2]) | {p["name"]: v for p, v in zip(n["params"], vals)})


def field(v, k):
    if v[0] == "with":
        return v[3] if v[2] == ("str", k) else field(v[1], k)
    if v[0] == "Rec":
        return dict(zip(v[1::2], v[2::2]))[("str", k)]
    if v[0] == "ite":
        return reduce("ite", (v[1], field(v[2], k), field(v[3], k)))
    return ("field", v, ("str", k))


def get(m, k):
    if m[0] == "set":
        return reduce("ite", (reduce("eq", (m[2], k)), m[3], get(m[1], k)))
    if m[0] == "mapBy" and m[1][0] == "Set" and k in m[1][1:]:
        return apply(m[2], (k,))
    if m[0] == "Map":
        for t in m[1:]:
            if t[1] == k:
                return t[2]
    if m[0] == "ite":
        return reduce("ite", (m[1], get(m[2], k), get(m[3], k)))
    if k[0] != "int":
        return reduce(
            "ite", (reduce("eq", (k, ("int", 0))), get(m, ("int", 0)), ("opaqueGet", m, k))
        )
    return ("get", m, k)


def literal(v):
    return v[0] in ("int", "bool") or (v[0] == "variant" and v[1][0] == "str" and v[2] == ("Tup",))


def reduce(op, vs):
    if op == "field" and vs[1][0] == "str":
        return field(vs[0], vs[1][1])
    if op == "get":
        return get(*vs)
    if op == "ite":
        if vs[0][0] == "bool":
            return vs[1] if vs[0][1] else vs[2]
        if vs[1] == vs[2]:
            return vs[1]
    if op == "eq":
        if vs[0] == vs[1]:
            return ("bool", True)
        if vs[0][0] == vs[1][0] and all(literal(item) for item in vs):
            return ("bool", False)
    if op == "keys" and vs[0][0] == "Map":
        return ("Set", *(pair[1] for pair in vs[0][1:]))
    if (
        op in ("union", "intersect", "exclude")
        and vs[0][0] == vs[1][0] == "Set"
        and all(literal(a) for a in (*vs[0][1:], *vs[1][1:]))
    ):
        left, right = set(vs[0][1:]), set(vs[1][1:])
        result = {"union": left | right, "intersect": left & right, "exclude": left - right}[op]
        return ("Set", *sorted(result, key=repr))
    if op in ("map", "forall", "exists") and vs[0][0] == "Set":
        applied = tuple(apply(vs[1], (val,)) for val in vs[0][1:])
        if op == "map":
            return ("Set", *applied)
        if not applied:
            return ("bool", op == "forall")
        return ("and" if op == "forall" else "or", *applied)
    if op == "filter" and vs[0][0] == "Set":
        tested = [(v, apply(vs[1], (v,))) for v in vs[0][1:]]
        if all(pred[0] == "bool" for _, pred in tested):
            return ("Set", *(v for v, pred in tested if pred[1]))
    return (op, *vs)


def evaluate(n, env):
    kind = n["kind"]
    if kind in ("bool", "int", "str"):
        return (kind, n["value"])
    if kind == "name":
        name = n["name"]
        if name in env:
            return env[name]
        if name in states:
            return states[name]
        return call(name, ())
    if kind == "let":
        d = n["opdef"]
        return evaluate(n["expr"], env | {d["name"]: evaluate(d["expr"], env)})
    if kind == "lambda":
        return ("opaqueLambda", json.dumps(n, sort_keys=True), tuple(sorted(env.items())))
    if kind != "app":
        raise ValueError(kind)
    op = n["opcode"]
    vals = tuple(evaluate(a, env) for a in n["args"])
    if op in rules:
        return call(op, vals)
    return reduce(op, vals)


@lru_cache(None)
def call(name, vals):
    n = rules[name]
    if n["kind"] == "lambda":
        params = n["params"]
        if len(params) != len(vals):
            raise ValueError("arity " + name)
        return evaluate(n["expr"], {p["name"]: v for p, v in zip(params, vals)})
    if vals:
        raise ValueError("unexpected arguments " + name)
    return evaluate(n, {})


def branches(n, env, labels=()):
    kind = n["kind"]
    if kind == "let":
        d = n["opdef"]
        v = evaluate(d["expr"], env)
        extra = ()
        if d["qualifier"] == "nondet":
            if v[0] != "oneOf":
                raise ValueError("unsupported nondeterministic binder")
            domain = v[1]
            v = (
                domain[1]
                if domain[0] == "Set" and len(domain) == 2
                else ("choice", next(choices), d["name"], domain)
            )
            extra = (("contains", domain, v),)
        return [
            (k, extra + guards, assign)
            for k, guards, assign in branches(n["expr"], env | {d["name"]: v}, labels)
        ]
    if kind == "app" and n["opcode"] == "actionAny":
        return [branch for a in n["args"] for branch in branches(a, env, labels)]
    if kind == "app" and n["opcode"] == "actionAll":
        exprs = [evaluate(a, env) for a in n["args"]]
        guards = [v for v in exprs if v[0] != "assign"]
        assigns = {v[1][1]: v[2] for v in exprs if v[0] == "assign"}
        if (
            len(exprs) - len(guards) != len(states)
            or set(assigns) != set(states)
            or any(v[0] in ("actionAny", "actionAll") for v in guards)
        ):
            raise ValueError(("unexpected action layout", labels))
        return [(labels[-1], tuple(guards), assigns)]
    name = n["name"] if kind == "name" else n["opcode"]
    target = rules[name]
    if target["kind"] == "lambda":
        vals = [evaluate(a, env) for a in n["args"]]
        return branches(
            target["expr"], {p["name"]: v for p, v in zip(target["params"], vals)}, labels + (name,)
        )
    return branches(target, {}, labels + (name,))
