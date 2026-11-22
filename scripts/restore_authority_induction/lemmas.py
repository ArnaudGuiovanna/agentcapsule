"""Parameterized predicates shared verbatim by the producer and every use of a lemma."""

import ir_semantics as ir


def fld(obj, k):
    return ir.field(obj, k)


def at(obj, k):
    return ir.get(obj, k)


def member(collection, key):
    return ("contains", collection, key)


def conjunction(*parts):
    return ("and", *parts)


def implies(a, b):
    return ("implies", a, b)


def equals(a, b):
    return ir.reduce("eq", (a, b))


def schema(name, *args):
    state, root = ir.states["s"], ir.states["root"]
    zero, one = ("int", 0), ("int", 1)
    store = at(fld(state, "stores"), zero)
    ack = at(fld(root, "acks"), zero)
    inc = at(fld(root, "incarnations"), zero)
    if name == "outcomesHaveConfiguredIDs":
        (e,) = args
        return conjunction(
            *(
                implies(member(xs, e), equals(e, zero))
                for xs in (fld(state, "everAcked"), fld(root, "committed"))
            )
        )
    if name == "acknowledgedOutcomeIsCurrentOrInWindow":
        (e,) = args
        return implies(
            member(fld(state, "everAcked"), e),
            ("or", member(fld(root, "committed"), e), member(fld(state, "window"), e)),
        )
    if name == "declaredLossIsRemembered":
        (loss,) = args
        return implies(member(fld(root, "lost"), loss), member(fld(state, "everDeclared"), loss))
    if name == "sameImageReceiptsCertifyFences":
        receipt, k = args
        ri, si = fld(receipt, "incarnation"), fld(store, "incarnation")
        return implies(
            member(fld(state, "receipts"), receipt),
            conjunction(
                equals(fld(receipt, "store"), zero),
                ("ilte", ri, si),
                implies(
                    conjunction(equals(ri, si), member(fld(receipt, "subjects"), k)),
                    member(fld(store, "fences"), k),
                ),
            ),
        )
    if name == "positiveRevisionReceiptsCoverSubject":
        (receipt,) = args
        return implies(
            conjunction(
                member(fld(state, "receipts"), receipt), ("igte", fld(receipt, "revision"), one)
            ),
            member(fld(receipt, "subjects"), zero),
        )
    if name == "pendingHasPositiveScope":
        if not (not args):
            raise ValueError("Source operator or argument shape changed in schema")
        return implies(
            member(fld(root, "pending"), zero), ("igte", at(fld(root, "scoped"), zero), one)
        )
    if name == "positiveAckCoversSubject":
        if not (not args):
            raise ValueError("Source operator or argument shape changed in schema")
        return implies(("igte", fld(ack, "revision"), one), member(fld(ack, "subjects"), zero))
    if name == "revocationsAreCurrentAndPending":
        (k,) = args
        ever = member(fld(state, "everRevoked"), k)
        return conjunction(
            equals(ever, member(fld(root, "revoked"), k)),
            implies(ever, member(fld(root, "pending"), k)),
        )
    if name == "acceptedAckCertifiesFence":
        (k,) = args
        return implies(
            conjunction(equals(fld(ack, "incarnation"), inc), member(fld(ack, "subjects"), k)),
            member(fld(store, "fences"), k),
        )
    raise KeyError(name)


def chosen_receipt(action, guards):
    if action != "recordReceipt":
        return None
    candidates = [
        g[2]
        for g in guards
        if g[0] == "contains" and g[1] == fld(ir.states["s"], "receipts") and g[2][0] == "choice"
    ]
    if len(candidates) != 1:
        raise ValueError("expected one bound receipt from the original queue")
    return candidates[0]
