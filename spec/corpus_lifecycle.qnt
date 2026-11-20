// -*- mode: Bluespec; -*-
/**
 * Corpus builds, releases, bindings and the host's image cache
 * (docs/plan-corpus.md, ADR 023).
 *
 * Two organizations: o1 owns corpus c1, o2 owns c2. Builds b1 and b2 are of
 * c1, b3 of c2. The release names are c1:1, c1:2 and c2:1. Agent a1 is of
 * o1, a2 of o2. One host holds every image in its cache, keyed by digest:
 * two organizations that build the same bytes share one file.
 *
 * A build ends in REVIEW with the digest of its image (in the cache before
 * REVIEW), or FAILED; REVIEW ends PUBLISHED, CANCELED or EXPIRED. QUEUED
 * stands for every state before REVIEW (FETCHING ... PACKAGING). Publishing
 * creates `name:version`; the same version with the same digest answers the
 * existing release. A binding (release, or a build in REVIEW for `try`)
 * changes what the agent mounts at its next boot; a running VM keeps the
 * images its boot resolved (`booted`, the host's record of the boot;
 * `mounted`, what the guest sees). The garbage collector removes only
 * images no pin needs. In this version (ADR 023, D-C9: the host's cache is
 * the only copy) a release neither deprecated nor disabled pins its image.
 *
 * Each action is one PostgreSQL transaction (publication, binding, rollout,
 * deprecation) or one worker step (boot, stop, eviction under the cache
 * lock); they are atomic here. Not modelled: several hosts, quotas, the
 * fetch and conversion steps, the builder agent, agent deletion, mount
 * names, the four-corpora limit, eviction of a build's staging files.
 *
 * Every guard has a switch; each broken instance below disables one, and its
 * invariant must fail (scripts/check-models.py).
 */
module corpusLifecycle {
  // publish answers version_conflict when the version holds another digest.
  const CHECK_VERSION: bool
  // publish needs the build in REVIEW (409 invalid_transition otherwise).
  const CHECK_REVIEW: bool
  // a binding, a try and a rollout name a corpus of the agent's organization.
  const CHECK_ORGANIZATION: bool
  // a binding change applies at the next boot only.
  const AT_BOOT: bool
  // eviction skips pinned images.
  const GC_CHECKS_PINS: bool
  // a release that is not deprecated pins its image (the cache is its only copy).
  const PIN_ACTIVE: bool

  pure val ORGANIZATION_OF_CORPUS = Map("c1" -> "o1", "c2" -> "o2")
  pure val ORGANIZATION_OF_AGENT = Map("a1" -> "o1", "a2" -> "o2")
  pure val CORPUS_OF_BUILD = Map("b1" -> "c1", "b2" -> "c1", "b3" -> "c2")
  pure val CORPUS_OF_RELEASE = Map("c1:1" -> "c1", "c1:2" -> "c1", "c2:1" -> "c2")
  pure val AGENTS = ORGANIZATION_OF_AGENT.keys()
  pure val BUILDS = CORPUS_OF_BUILD.keys()
  pure val RELEASES = CORPUS_OF_RELEASE.keys()
  pure val DIGESTS = Set("d1", "d2")

  // A reference is a release name or, for a try, a build.
  pure def corpusOf(ref: str): str =
    if (BUILDS.contains(ref)) CORPUS_OF_BUILD.get(ref) else CORPUS_OF_RELEASE.get(ref)
  pure def organizationOf(ref: str): str = ORGANIZATION_OF_CORPUS.get(corpusOf(ref))

  type Build = { state: str, digest: str, publications: int }
  type Release = { exists: bool, digest: str, deprecated: bool }
  type Agent = { vm: str, bound: Set[str], booted: Set[(str, str)], mounted: Set[(str, str)] }
  type State = { builds: str -> Build, releases: str -> Release, agents: str -> Agent,
                 cache: Set[str], rollouts: Set[str], published: Set[(str, str)] }
  // published is a ghost: every (release, digest) a publication ever created.
  var s: State

  def digestOf(ref: str): str =
    if (BUILDS.contains(ref)) s.builds.get(ref).digest else s.releases.get(ref).digest
  def active(k: str): bool = s.releases.get(k).exists and not(s.releases.get(k).deprecated)
  def allowed(a: str, ref: str): bool =
    if (CHECK_ORGANIZATION) organizationOf(ref) == ORGANIZATION_OF_AGENT.get(a) else true
  def resolve(refs: Set[str]): Set[(str, str)] = refs.map(r => (r, digestOf(r)))

  // The digests the cache must keep.
  def pinned: Set[str] =
    AGENTS.map(a => s.agents.get(a).bound.map(r => digestOf(r))).flatten()
      .union(AGENTS.map(a => s.agents.get(a).mounted.map(m => m._2)).flatten())
      .union(s.rollouts.map(k => s.releases.get(k).digest))
      .union(BUILDS.filter(b => s.builds.get(b).state == "REVIEW").map(b => s.builds.get(b).digest))
      .union(if (PIN_ACTIVE) RELEASES.filter(k => active(k)).map(k => s.releases.get(k).digest) else Set())

  action init = s' = {
    builds: BUILDS.mapBy(b => { state: "QUEUED", digest: "", publications: 0 }),
    releases: RELEASES.mapBy(k => { exists: false, digest: "", deprecated: false }),
    agents: AGENTS.mapBy(a => { vm: "stopped", bound: Set(), booted: Set(), mounted: Set() }),
    cache: Set(), rollouts: Set(), published: Set(),
  }

  // The worker checks the image and moves it into the cache, then the build
  // turns REVIEW.
  action finish(b: str, d: str): bool = all {
    s.builds.get(b).state == "QUEUED",
    s' = { ...s, builds: s.builds.set(b, { ...s.builds.get(b), state: "REVIEW", digest: d }),
           cache: s.cache.union(Set(d)) },
  }
  action buildFails(b: str): bool = all {
    s.builds.get(b).state == "QUEUED",
    s' = { ...s, builds: s.builds.set(b, { ...s.builds.get(b), state: "FAILED" }) },
  }
  // Canceling or expiring a build in review removes its try bindings; a
  // running VM keeps its mount until it stops.
  def dropTries(b: str): str -> Agent =
    s.agents.keys().mapBy(a => { ...s.agents.get(a), bound: s.agents.get(a).bound.exclude(Set(b)) })
  action cancel(b: str): bool = all {
    Set("QUEUED", "REVIEW").contains(s.builds.get(b).state),
    s' = { ...s, builds: s.builds.set(b, { ...s.builds.get(b), state: "CANCELED" }), agents: dropTries(b) },
  }
  action expire(b: str): bool = all {
    s.builds.get(b).state == "REVIEW",
    s' = { ...s, builds: s.builds.set(b, { ...s.builds.get(b), state: "EXPIRED" }), agents: dropTries(b) },
  }
  // POST /v1/corpus-builds/{id}/publish {version}.
  def publishable(b: str, k: str): bool = and {
    CORPUS_OF_RELEASE.get(k) == CORPUS_OF_BUILD.get(b),
    if (CHECK_REVIEW) s.builds.get(b).state == "REVIEW"
    else Set("REVIEW", "PUBLISHED").contains(s.builds.get(b).state),
    if (CHECK_VERSION) not(s.releases.get(k).exists) or s.releases.get(k).digest == s.builds.get(b).digest
    else true,
  }
  action publish(b: str, k: str): bool = all {
    val build = s.builds.get(b)
    val release = s.releases.get(k)
    all {
      publishable(b, k),
      s' = { ...s,
             builds: s.builds.set(b, { ...build, state: "PUBLISHED", publications: build.publications + 1 }),
             releases: s.releases.set(k, { ...release, exists: true, digest: build.digest }),
             published: s.published.union(Set((k, build.digest))) },
    }
  }
  action deprecate(k: str): bool = all {
    active(k),
    s' = { ...s, releases: s.releases.set(k, { ...s.releases.get(k), deprecated: true }) },
  }
  // One reference per corpus and agent. At the next boot, or at once on a
  // running VM when AT_BOOT is off.
  action rebind(a: str, bound: Set[str]): bool = all {
    val agent = s.agents.get(a)
    s' = { ...s, agents: s.agents.set(a, { ...agent, bound: bound,
             mounted: if (AT_BOOT or agent.vm != "running") agent.mounted else resolve(bound) }) },
  }
  def replacing(a: str, ref: str): Set[str] =
    s.agents.get(a).bound.filter(x => corpusOf(x) != corpusOf(ref)).union(Set(ref))
  // POST /v1/agents/{id}/corpora, or a template's corpora through a rollout step.
  def bindable(a: str, k: str): bool = active(k) and allowed(a, k)
  action bind(a: str, k: str): bool = all { bindable(a, k), rebind(a, replacing(a, k)) }
  // POST /v1/corpus-builds/{id}/try {agent}.
  def triable(a: str, b: str): bool = s.builds.get(b).state == "REVIEW" and allowed(a, b)
  action try(a: str, b: str): bool = all { triable(a, b), rebind(a, replacing(a, b)) }
  action unbind(a: str, ref: str): bool = all {
    s.agents.get(a).bound.contains(ref), rebind(a, s.agents.get(a).bound.exclude(Set(ref))),
  }
  // The worker resolves the bindings to digests and boots only if the cache
  // holds every image.
  action boot(a: str): bool = all {
    val agent = s.agents.get(a)
    all {
      agent.vm == "stopped",
      agent.bound.forall(r => s.cache.contains(digestOf(r))),
      s' = { ...s, agents: s.agents.set(a, { ...agent, vm: "running",
               booted: resolve(agent.bound), mounted: resolve(agent.bound) }) },
    }
  }
  action stop(a: str): bool = all {
    s.agents.get(a).vm == "running",
    s' = { ...s, agents: s.agents.set(a, { ...s.agents.get(a), vm: "stopped", booted: Set(), mounted: Set() }) },
  }
  // A rollout whose template names the release, open until it ends.
  action openRollout(k: str): bool = all {
    active(k), not(s.rollouts.contains(k)), s' = { ...s, rollouts: s.rollouts.union(Set(k)) },
  }
  action closeRollout(k: str): bool = all {
    s.rollouts.contains(k), s' = { ...s, rollouts: s.rollouts.exclude(Set(k)) },
  }
  def evictable(d: str): bool =
    s.cache.contains(d) and (if (GC_CHECKS_PINS) not(pinned.contains(d)) else true)
  action evict(d: str): bool = all { evictable(d), s' = { ...s, cache: s.cache.exclude(Set(d)) } }

  // Each action picks only its own parameters, so TLC does not enumerate the
  // others for it.
  action step = any {
    { nondet b = BUILDS.oneOf() nondet d = DIGESTS.oneOf() finish(b, d) },
    { nondet b = BUILDS.oneOf() any { buildFails(b), cancel(b), expire(b) } },
    { nondet b = BUILDS.oneOf() nondet k = RELEASES.oneOf() publish(b, k) },
    { nondet k = RELEASES.oneOf() any { deprecate(k), openRollout(k), closeRollout(k) } },
    { nondet a = AGENTS.oneOf() nondet k = RELEASES.oneOf() bind(a, k) },
    { nondet a = AGENTS.oneOf() nondet b = BUILDS.oneOf() try(a, b) },
    { nondet a = AGENTS.oneOf() nondet ref = BUILDS.union(RELEASES).oneOf() unbind(a, ref) },
    { nondet a = AGENTS.oneOf() any { boot(a), stop(a) } },
    { nondet d = DIGESTS.oneOf() evict(d) },
  }

  // name:version keeps the digest of its first publication.
  val publishedIsImmutable = s.published.forall(p =>
    s.releases.get(p._1).exists and s.releases.get(p._1).digest == p._2)
  // A VM mounts only corpora of its agent's organization.
  val bootsOnlyBoundCorporaOfItsOrganization = AGENTS.forall(a =>
    s.agents.get(a).mounted.forall(m => organizationOf(m._1) == ORGANIZATION_OF_AGENT.get(a)))
  // A running VM sees what its boot resolved, whatever its bindings became since.
  val bindingChangesAtBootOnly = AGENTS.forall(a =>
    s.agents.get(a).vm == "running" implies s.agents.get(a).mounted == s.agents.get(a).booted)
  // A build is the source of at most one publication.
  val buildPublishesAtMostOnce = BUILDS.forall(b => s.builds.get(b).publications <= 1)
  // Every image a pin needs is in the cache: the collector removes none, and
  // no pin is taken on an image it removed.
  val gcNeverRemovesPinned = pinned.subseteq(s.cache)
  val safety = publishedIsImmutable and bootsOnlyBoundCorporaOfItsOrganization and bindingChangesAtBootOnly
    and buildPublishesAtMostOnce and gcNeverRemovesPinned
}

module corpusLifecycleOk {
  import corpusLifecycle(CHECK_VERSION = true, CHECK_REVIEW = true, CHECK_ORGANIZATION = true,
                         AT_BOOT = true, GC_CHECKS_PINS = true, PIN_ACTIVE = true).*
  // Another digest under a taken version is refused; the same digest answers it.
  run versionConflictTest = init.then(finish("b1", "d1")).then(finish("b2", "d2"))
    .then(publish("b1", "c1:1")).expect(not(publishable("b2", "c1:1")))
    .then(publish("b2", "c1:2")).expect(safety and s.releases.get("c1:1").digest == "d1")
  run sameDigestAnswersTheReleaseTest = init.then(finish("b1", "d1")).then(finish("b2", "d1"))
    .then(publish("b1", "c1:1")).then(publish("b2", "c1:1"))
    .expect(safety and s.builds.get("b2").state == "PUBLISHED")
  run publishedBuildDoesNotPublishAgainTest = init.then(finish("b1", "d1")).then(publish("b1", "c1:1"))
    .expect(safety).then(publish("b1", "c1:2").fail())
  run crossOrganizationBindingRefusedTest = init.then(finish("b3", "d1")).then(publish("b3", "c2:1"))
    .expect(not(bindable("a1", "c2:1")) and not(triable("a1", "b3")))
    .then(bind("a2", "c2:1")).then(boot("a2")).expect(safety and s.agents.get("a2").mounted == Set(("c2:1", "d1")))
  run bindingAppliesAtNextBootTest = init.then(finish("b1", "d1")).then(publish("b1", "c1:1"))
    .then(bind("a1", "c1:1")).then(boot("a1")).then(finish("b2", "d2")).then(publish("b2", "c1:2"))
    .then(bind("a1", "c1:2")).expect(safety and s.agents.get("a1").mounted == Set(("c1:1", "d1")))
    .then(stop("a1")).then(boot("a1")).expect(safety and s.agents.get("a1").mounted == Set(("c1:2", "d2")))
  run tryMountsABuildInReviewTest = init.then(finish("b1", "d1")).then(try("a1", "b1")).then(boot("a1"))
    .expect(not(evictable("d1"))).then(expire("b1"))
    .expect(not(evictable("d1")) and s.agents.get("a1").bound == Set())
    .then(stop("a1")).then(evict("d1")).expect(safety and s.cache == Set())
  // A deprecated release leaves the cache once nothing pins it, never before.
  run deprecatedImageLeavesOnceUnpinnedTest = init.then(finish("b1", "d1")).then(publish("b1", "c1:1"))
    .expect(not(evictable("d1"))).then(bind("a1", "c1:1")).then(boot("a1")).then(deprecate("c1:1"))
    .expect(not(bindable("a1", "c1:1")) and not(evictable("d1"))).then(unbind("a1", "c1:1"))
    .expect(not(evictable("d1"))).then(stop("a1")).then(evict("d1")).expect(safety and s.cache == Set())
  // Two organizations' identical bytes are one file, pinned by either.
  run sharedDigestStaysWhileEitherPinsItTest = init.then(finish("b1", "d1")).then(finish("b3", "d1"))
    .then(publish("b1", "c1:1")).then(publish("b3", "c2:1")).then(bind("a2", "c2:1"))
    .then(deprecate("c1:1")).expect(safety and not(evictable("d1")))
}
module corpusLifecycleNoVersionCheck {
  import corpusLifecycle(CHECK_VERSION = false, CHECK_REVIEW = true, CHECK_ORGANIZATION = true,
                         AT_BOOT = true, GC_CHECKS_PINS = true, PIN_ACTIVE = true).*
}
module corpusLifecycleNoReviewCheck {
  import corpusLifecycle(CHECK_VERSION = true, CHECK_REVIEW = false, CHECK_ORGANIZATION = true,
                         AT_BOOT = true, GC_CHECKS_PINS = true, PIN_ACTIVE = true).*
}
module corpusLifecycleNoOrganizationCheck {
  import corpusLifecycle(CHECK_VERSION = true, CHECK_REVIEW = true, CHECK_ORGANIZATION = false,
                         AT_BOOT = true, GC_CHECKS_PINS = true, PIN_ACTIVE = true).*
}
module corpusLifecycleHotSwap {
  import corpusLifecycle(CHECK_VERSION = true, CHECK_REVIEW = true, CHECK_ORGANIZATION = true,
                         AT_BOOT = false, GC_CHECKS_PINS = true, PIN_ACTIVE = true).*
}
module corpusLifecycleNoPinCheck {
  import corpusLifecycle(CHECK_VERSION = true, CHECK_REVIEW = true, CHECK_ORGANIZATION = true,
                         AT_BOOT = true, GC_CHECKS_PINS = false, PIN_ACTIVE = true).*
}
// The plan's first rule: only agents, open rollouts, builds in review and
// tries pin an image. With the cache as the only copy, an active release no
// one binds is evicted, and a later binding pins an image that is gone.
module corpusLifecycleEvictsActive {
  import corpusLifecycle(CHECK_VERSION = true, CHECK_REVIEW = true, CHECK_ORGANIZATION = true,
                         AT_BOOT = true, GC_CHECKS_PINS = true, PIN_ACTIVE = false).*
}
