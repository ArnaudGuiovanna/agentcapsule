// -*- mode: Bluespec; -*-
/**
 * Model 2 — Agent messaging between users.
 *
 * Covers (section numbers refer to the original, unpublished design specification):
 *   - point 2: requests, consent, mandate, single final state (§12.4, §12.5);
 *   - point 4: visibility and asynchronous synchronization of the ADS directory (§12.3);
 *   - point 5: deletion of a user while requests are in flight (§6.7).
 *
 * Abstractions:
 *   - one user = one companion; the companion is identified by its user;
 *   - companions are adversarial: they may try any mandate, any
 *     recipient; only the PaaS checks prevent them from doing so;
 *   - wake-up and physical delivery are summarized by `deliver` (see the lifecycle model);
 *   - time is not modeled: expirations are nondeterministic.
 *
 * The boolean constants enable the design mechanisms; the instances at the end
 * of the file each disable one of them to show the matching counterexample.
 */
module messaging {
  const USERS: Set[str]
  const MAX_MANDATES: int
  const MAX_REQS: int
  const MAX_PER_MANDATE: int
  // Search rechecks visibility in PostgreSQL (ADS may lag behind).
  const POSTCHECK_SEARCH: bool
  // Sending a request checks visibility in PostgreSQL (not in ADS).
  const SEND_CHECKS_PG: bool
  // The mandate used must belong to the sending agent (identity derived from the vsock channel).
  const CHECK_MANDATE_OWNER: bool
  // Transitions are conditional updates (UPDATE ... WHERE state = ...).
  const CONDITIONAL_UPDATES: bool

  type Mode = Manual | Auto
  type RState = PendingApproval | Delivering | Processing | Replied | Declined
              | Expired | Canceled | Failed
  type Mandate = { owner: str, remaining: int, valid: bool }
  type Req = {
    sender: str, recipient: str, mandate: int, state: RState,
    viaAuto: bool,                 // sent while the recipient was in auto mode
    accepted: bool,                // accepted by the recipient user
    delivered: bool,               // delivered to the recipient harness (so the companion was woken)
    recipientVisibleAtSubmit: bool,
    wasTerminal: bool,             // has already reached a final state
    senderNotified: bool,
  }
  type Search = { who: str, results: Set[str], visible: Set[str] }

  // --- state ---
  var discoverable: str -> bool   // source of truth (PostgreSQL)
  var ads: Set[str]               // asynchronous projection into the Agent Directory
  var mode: str -> Mode
  var deleted: str -> bool
  var mandates: int -> Mandate
  var nextMandate: int
  var requests: int -> Req
  var nextReq: int
  var acceptIntent: Set[int]      // "pending" reads not followed by a write (non-conditional variant)
  var lastSearch: Search

  pure def isTerminal(s: RState): bool = match s {
    | Replied => true | Declined => true | Expired => true | Canceled => true | Failed => true
    | _ => false
  }

  def visibleNow(u: str): bool = discoverable.get(u) and not(deleted.get(u))
  def reqIds: Set[int] = requests.keys()

  // Helper: updates a request's state and marks final states.
  def withState(r: Req, s: RState): Req = { ...r, state: s, wasTerminal: r.wasTerminal or isTerminal(s) }

  action init = all {
    discoverable' = USERS.mapBy(u => false),      // default: not discoverable
    ads' = Set(),
    mode' = USERS.mapBy(u => Manual),
    deleted' = USERS.mapBy(u => false),
    mandates' = Map(),
    nextMandate' = 0,
    requests' = Map(),
    nextReq' = 0,
    acceptIntent' = Set(),
    lastSearch' = { who: "", results: Set(), visible: Set() },
  }

  // Frame: "nothing else changes" macro for each variable.
  action keepVis = all { discoverable' = discoverable, ads' = ads }
  action keepMandates = all { mandates' = mandates, nextMandate' = nextMandate }

  // --- user settings ---

  action setVisibility(u: str, b: bool): bool = all {
    not(deleted.get(u)),
    discoverable' = discoverable.set(u, b),
    ads' = ads,
    mode' = mode, deleted' = deleted, keepMandates, requests' = requests, nextReq' = nextReq,
    acceptIntent' = acceptIntent, lastSearch' = lastSearch,
  }

  // Projection asynchrone PostgreSQL -> ADS (outbox).
  action syncAds(u: str): bool = all {
    visibleNow(u) != ads.contains(u),
    ads' = if (visibleNow(u)) ads.union(Set(u)) else ads.exclude(Set(u)),
    discoverable' = discoverable,
    mode' = mode, deleted' = deleted, keepMandates, requests' = requests, nextReq' = nextReq,
    acceptIntent' = acceptIntent, lastSearch' = lastSearch,
  }

  action setMode(u: str, m: Mode): bool = all {
    not(deleted.get(u)),
    mode' = mode.set(u, m),
    keepVis, deleted' = deleted, keepMandates, requests' = requests, nextReq' = nextReq,
    acceptIntent' = acceptIntent, lastSearch' = lastSearch,
  }

  // --- mandate (§12.4): created ONLY when the owner gives an instruction ---

  action instruct(u: str): bool = all {
    not(deleted.get(u)),
    nextMandate < MAX_MANDATES,
    mandates' = mandates.put(nextMandate, { owner: u, remaining: MAX_PER_MANDATE, valid: true }),
    nextMandate' = nextMandate + 1,
    keepVis, mode' = mode, deleted' = deleted, requests' = requests, nextReq' = nextReq,
    acceptIntent' = acceptIntent, lastSearch' = lastSearch,
  }

  action expireMandate(m: int): bool = all {
    mandates.keys().contains(m),
    mandates.get(m).valid,
    mandates' = mandates.set(m, { ...mandates.get(m), valid: false }),
    nextMandate' = nextMandate,
    keepVis, mode' = mode, deleted' = deleted, requests' = requests, nextReq' = nextReq,
    acceptIntent' = acceptIntent, lastSearch' = lastSearch,
  }

  // --- annuaire (§12.3) ---

  action search(u: str): bool = {
    val candidates = if (POSTCHECK_SEARCH) ads.filter(x => visibleNow(x)) else ads
    all {
      not(deleted.get(u)),
      lastSearch' = { who: u, results: candidates.exclude(Set(u)),
                      visible: USERS.filter(x => visibleNow(x)) },
      keepVis, mode' = mode, deleted' = deleted, keepMandates, requests' = requests,
      nextReq' = nextReq, acceptIntent' = acceptIntent,
    }
  }

  // --- a companion sends a request (adversarial) ---

  action submit(u: str, r: str, m: int): bool = {
    val md = mandates.get(m)
    val recipientOk = if (SEND_CHECKS_PG) visibleNow(r) else ads.contains(r)
    all {
      u != r,
      not(deleted.get(u)),
      nextReq < MAX_REQS,
      mandates.keys().contains(m),
      md.valid, md.remaining > 0,
      if (CHECK_MANDATE_OWNER) md.owner == u else true,
      recipientOk,
      val auto = mode.get(r) == Auto
      requests' = requests.put(nextReq, {
        sender: u, recipient: r, mandate: m,
        state: if (auto) Delivering else PendingApproval,
        viaAuto: auto, accepted: false, delivered: false,
        recipientVisibleAtSubmit: visibleNow(r),
        wasTerminal: false, senderNotified: false,
      }),
      nextReq' = nextReq + 1,
      mandates' = mandates.set(m, { ...md, remaining: md.remaining - 1 }),
      nextMandate' = nextMandate,
      keepVis, mode' = mode, deleted' = deleted, acceptIntent' = acceptIntent,
      lastSearch' = lastSearch,
    }
  }

  // --- request transitions (§12.5) ---

  // Frame shared by transitions that only touch `requests`.
  action onlyRequests(newReqs: int -> Req): bool = all {
    requests' = newReqs,
    keepVis, mode' = mode, deleted' = deleted, keepMandates, nextReq' = nextReq,
    acceptIntent' = acceptIntent, lastSearch' = lastSearch,
  }

  // Acceptance by the recipient: conditional update.
  action accept(id: int): bool = {
    val q = requests.get(id)
    all {
      CONDITIONAL_UPDATES,
      reqIds.contains(id),
      q.state == PendingApproval,
      not(deleted.get(q.recipient)),
      onlyRequests(requests.set(id, { ...withState(q, Delivering), accepted: true })),
    }
  }

  // Non-conditional variant: read, then write later without rechecking the state.
  action acceptRead(id: int): bool = all {
    not(CONDITIONAL_UPDATES),
    reqIds.contains(id),
    requests.get(id).state == PendingApproval,
    acceptIntent' = acceptIntent.union(Set(id)),
    requests' = requests,
    keepVis, mode' = mode, deleted' = deleted, keepMandates, nextReq' = nextReq,
    lastSearch' = lastSearch,
  }

  action acceptWrite(id: int): bool = {
    val q = requests.get(id)
    all {
      acceptIntent.contains(id),
      acceptIntent' = acceptIntent.exclude(Set(id)),
      requests' = requests.set(id, { ...withState(q, Delivering), accepted: true }),
      keepVis, mode' = mode, deleted' = deleted, keepMandates, nextReq' = nextReq,
      lastSearch' = lastSearch,
    }
  }

  action decline(id: int): bool = {
    val q = requests.get(id)
    all {
      reqIds.contains(id), q.state == PendingApproval,
      onlyRequests(requests.set(id, withState(q, Declined))),
    }
  }

  action cancel(id: int): bool = {
    val q = requests.get(id)
    all {
      reqIds.contains(id),
      q.state == PendingApproval or q.state == Delivering or q.state == Processing,
      onlyRequests(requests.set(id, withState(q, Canceled))),
    }
  }

  action expire(id: int): bool = {
    val q = requests.get(id)
    all {
      reqIds.contains(id),
      q.state == PendingApproval or q.state == Processing,
      onlyRequests(requests.set(id, withState(q, Expired))),
    }
  }

  // Delivery to the recipient harness (including wake-up), via SLIM/bridge/vsock.
  action deliver(id: int): bool = {
    val q = requests.get(id)
    all {
      reqIds.contains(id), q.state == Delivering,
      not(deleted.get(q.recipient)),
      onlyRequests(requests.set(id, { ...withState(q, Processing), delivered: true })),
    }
  }

  action deliverFail(id: int): bool = {
    val q = requests.get(id)
    all {
      reqIds.contains(id), q.state == Delivering,
      onlyRequests(requests.set(id, withState(q, Failed))),
    }
  }

  action reply(id: int): bool = {
    val q = requests.get(id)
    all {
      reqIds.contains(id), q.state == Processing,
      onlyRequests(requests.set(id, withState(q, Replied))),
    }
  }

  // In auto mode, the recipient companion may decline.
  action autoDecline(id: int): bool = {
    val q = requests.get(id)
    all {
      reqIds.contains(id), q.state == Processing, q.viaAuto,
      onlyRequests(requests.set(id, withState(q, Declined))),
    }
  }

  // Delivery of the outcome to the sending companion.
  action notifySender(id: int): bool = {
    val q = requests.get(id)
    all {
      reqIds.contains(id), isTerminal(q.state), not(q.senderNotified),
      not(deleted.get(q.sender)),
      onlyRequests(requests.set(id, { ...q, senderNotified: true })),
    }
  }

  // User deletion: visibility removed and in-flight requests canceled.
  action deleteUser(u: str): bool = all {
    not(deleted.get(u)),
    deleted' = deleted.set(u, true),
    discoverable' = discoverable.set(u, false),
    ads' = ads,
    requests' = requests.keys().mapBy(id => {
      val q = requests.get(id)
      if ((q.sender == u or q.recipient == u) and not(isTerminal(q.state)))
        withState(q, Canceled)
      else q
    }),
    mode' = mode, keepMandates, nextReq' = nextReq, acceptIntent' = acceptIntent,
    lastSearch' = lastSearch,
  }

  action step = {
    nondet u = USERS.oneOf()
    nondet r = USERS.oneOf()
    nondet b = Set(true, false).oneOf()
    nondet md = Set(Manual, Auto).oneOf()
    nondet m = 0.to(MAX_MANDATES - 1).oneOf()
    nondet id = 0.to(MAX_REQS - 1).oneOf()
    any {
      setVisibility(u, b), syncAds(u), setMode(u, md), instruct(u), expireMandate(m),
      search(u), submit(u, r, m),
      accept(id), acceptRead(id), acceptWrite(id), decline(id), cancel(id), expire(id),
      deliver(id), deliverFail(id), reply(id), autoDecline(id), notifySender(id),
      deleteUser(u),
    }
  }

  // Exact same transition relation as step for nonempty choice domains (all instances here).
  // Distribute existential choices over disjunction and drop unused choices in each branch.
  // TLC otherwise enumerates their Cartesian product even for unrelated actions.
  // Keep step unchanged for comparison and historical random-simulation seeds.
  action stepCompact = any {
    {
      nondet u = USERS.oneOf()
      nondet b = Set(true, false).oneOf()
      setVisibility(u, b)
    },
    {
      nondet u = USERS.oneOf()
      syncAds(u)
    },
    {
      nondet u = USERS.oneOf()
      nondet md = Set(Manual, Auto).oneOf()
      setMode(u, md)
    },
    {
      nondet u = USERS.oneOf()
      instruct(u)
    },
    {
      nondet m = 0.to(MAX_MANDATES - 1).oneOf()
      expireMandate(m)
    },
    {
      nondet u = USERS.oneOf()
      search(u)
    },
    {
      nondet u = USERS.oneOf()
      nondet r = USERS.oneOf()
      nondet m = 0.to(MAX_MANDATES - 1).oneOf()
      submit(u, r, m)
    },
    {
      nondet id = 0.to(MAX_REQS - 1).oneOf()
      accept(id)
    },
    {
      nondet id = 0.to(MAX_REQS - 1).oneOf()
      acceptRead(id)
    },
    {
      nondet id = 0.to(MAX_REQS - 1).oneOf()
      acceptWrite(id)
    },
    {
      nondet id = 0.to(MAX_REQS - 1).oneOf()
      decline(id)
    },
    {
      nondet id = 0.to(MAX_REQS - 1).oneOf()
      cancel(id)
    },
    {
      nondet id = 0.to(MAX_REQS - 1).oneOf()
      expire(id)
    },
    {
      nondet id = 0.to(MAX_REQS - 1).oneOf()
      deliver(id)
    },
    {
      nondet id = 0.to(MAX_REQS - 1).oneOf()
      deliverFail(id)
    },
    {
      nondet id = 0.to(MAX_REQS - 1).oneOf()
      reply(id)
    },
    {
      nondet id = 0.to(MAX_REQS - 1).oneOf()
      autoDecline(id)
    },
    {
      nondet id = 0.to(MAX_REQS - 1).oneOf()
      notifySender(id)
    },
    {
      nondet u = USERS.oneOf()
      deleteUser(u)
    },
  }

  // --- properties ---

  // Point 2 — consent: a request is delivered (and the recipient companion woken)
  // only if its owner accepted it or was in auto mode when it was sent.
  val consentRespected: bool = reqIds.forall(id => {
    val q = requests.get(id)
    q.delivered implies (q.accepted or q.viaAuto)
  })

  // Point 2 — mandate: each request uses a mandate issued to its own sender,
  // and no mandate is used beyond its budget.
  val mandateOwned: bool = reqIds.forall(id =>
    mandates.get(requests.get(id).mandate).owner == requests.get(id).sender)

  val mandateBudget: bool = mandates.keys().forall(m =>
    reqIds.filter(id => requests.get(id).mandate == m).size() <= MAX_PER_MANDATE)

  // Point 2 — single final state: a request that reached a final state never leaves it.
  val terminalStable: bool = reqIds.forall(id =>
    requests.get(id).wasTerminal implies isTerminal(requests.get(id).state))

  // Point 4 — no search returns a non-discoverable (or deleted) user.
  val searchNoLeak: bool = lastSearch.results.subseteq(lastSearch.visible)

  // Point 4 — not discoverable = not reachable: every request targeted a discoverable recipient.
  val noRequestToHidden: bool = reqIds.forall(id => requests.get(id).recipientVisibleAtSubmit)

  // Point 5 — after deletion, no in-flight request involves the user any more.
  val noLiveRequestForDeleted: bool = reqIds.forall(id => {
    val q = requests.get(id)
    (deleted.get(q.sender) or deleted.get(q.recipient)) implies isTerminal(q.state)
  })

  val safety: bool = consentRespected and mandateOwned and mandateBudget and terminalStable
                     and searchNoLeak and noRequestToHidden and noLiveRequestForDeleted
}

// --- instances ---

module messagingOk {
  import messaging(USERS = Set("arnaud", "marc", "zoe"), MAX_MANDATES = 2, MAX_REQS = 3,
                   MAX_PER_MANDATE = 2, POSTCHECK_SEARCH = true, SEND_CHECKS_PG = true,
                   CHECK_MANDATE_OWNER = true, CONDITIONAL_UPDATES = true).*
}

// Search trusts ADS, which may lag behind.
module messagingNoPostcheck {
  import messaging(USERS = Set("arnaud", "marc", "zoe"), MAX_MANDATES = 2, MAX_REQS = 3,
                   MAX_PER_MANDATE = 2, POSTCHECK_SEARCH = false, SEND_CHECKS_PG = true,
                   CHECK_MANDATE_OWNER = true, CONDITIONAL_UPDATES = true).*
}

// Sending checks visibility in ADS instead of PostgreSQL.
module messagingSendChecksAds {
  import messaging(USERS = Set("arnaud", "marc", "zoe"), MAX_MANDATES = 2, MAX_REQS = 3,
                   MAX_PER_MANDATE = 2, POSTCHECK_SEARCH = true, SEND_CHECKS_PG = false,
                   CHECK_MANDATE_OWNER = true, CONDITIONAL_UPDATES = true).*
}

// The PaaS does not check that the mandate belongs to the sender.
module messagingNoMandateOwner {
  import messaging(USERS = Set("arnaud", "marc", "zoe"), MAX_MANDATES = 2, MAX_REQS = 3,
                   MAX_PER_MANDATE = 2, POSTCHECK_SEARCH = true, SEND_CHECKS_PG = true,
                   CHECK_MANDATE_OWNER = false, CONDITIONAL_UPDATES = true).*
}

// Acceptance reads then writes without a conditional update.
module messagingRacyAccept {
  import messaging(USERS = Set("arnaud", "marc", "zoe"), MAX_MANDATES = 2, MAX_REQS = 3,
                   MAX_PER_MANDATE = 2, POSTCHECK_SEARCH = true, SEND_CHECKS_PG = true,
                   CHECK_MANDATE_OWNER = true, CONDITIONAL_UPDATES = false).*
}

// Three actors and four requests; the earlier instances stay comparable.
module messagingLarge {
  import messaging(USERS = Set("arnaud", "marc", "zoe"), MAX_MANDATES = 3, MAX_REQS = 4,
                   MAX_PER_MANDATE = 2, POSTCHECK_SEARCH = true, SEND_CHECKS_PG = true,
                   CHECK_MANDATE_OWNER = true, CONDITIONAL_UPDATES = true).*
}
