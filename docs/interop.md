# Initial INT-01 qualification

The `runtime/interop/` directory
([probe](../runtime/interop/probe), [profile.json](../runtime/interop/profile.json))
qualifies official libraries in an independent Go module. It does not yet
deliver the PaaS adapter and closes neither INT-01 nor G2. The check is
deliberately runnable without Docker, Rust, Elixir, a cloud account or a
secret. The Directory/OASF/SLIM services are not run by this probe. The A2A
client and server use the same upstream SDK: this is a functional check of this
profile, not a conformance certification or a validation between two
independent implementations.

## Versions and sources

| Component | Pinned candidate profile | Scope of the local check |
| --- | --- | --- |
| Go | 1.27.3, Linux amd64 glibc, CGO enabled | Compilation of the four SDKs in one module |
| A2A | [Specification v1.0.1](https://github.com/a2aproject/A2A/releases/tag/v1.0.1), wire `1.0`, [Go SDK v2.8.0](https://github.com/a2aproject/a2a-go/releases/tag/v2.8.0) | Agent Card, JSON-RPC `SendMessage` and `GetTask`, completed task and artifact over real loopback HTTP |
| OASF | [Schema 1.1.0, source v1.1.3](https://github.com/agntcy/oasf/releases/tag/v1.1.0), [Go SDK pkg/v1.1.0](https://github.com/agntcy/oasf-sdk/tree/pkg/v1.1.0) | Versioned decoding; this test does not validate the schema or the taxonomy |
| OASF server | [v2.0.0](https://github.com/agntcy/oasf-server/releases/tag/v2.0.0), declared support of schema 1.1.0 | Not run; requires its Elixir runtime or its official image |
| Directory | [v1.8.0](https://github.com/agntcy/dir/releases/tag/v1.8.0), Go client/api/utils v1.8.0, minimum Go 1.27.2 | Client construction and rejection of an unknown authentication mode; no RPC |
| SLIM | [Node 3.4.6](https://github.com/agntcy/slim/releases/tag/slim-v3.4.6), [Go bindings v3.3.9](https://github.com/agntcy/slim-bindings-go/tree/v3.3.9), [native FFI v3.3.9](https://github.com/agntcy/slim-bindings/releases/tag/slim-bindings-v3.3.9) | Real linking of the native library, ABI/version check, names and configuration parsing; no transport |

Release numbers do not prove interoperability. The
[Cargo.toml of the 3.3.9 FFI bindings](https://github.com/agntcy/slim-bindings/blob/slim-bindings-v3.3.9/rust/Cargo.toml)
nevertheless pins exactly the SLIM crates `3.4.6` of the candidate node. Their
on-the-wire compatibility remains to be measured with a started private node.
The A2A SDK explicitly exports `a2a.Version = "1.0"`: `1.0.1` designates the
specification release, not a value invented for the header or the Agent Card.

`profile.json` contains versions, commits and the SHA256 of the native archive;
`probe/go.mod` and `probe/go.sum` lock the Go graph actually compiled.
Directory selects the most recent transitive gRPC/protobuf/OASF versions of this
graph: the probe compiles A2A and SLIM with these same dependencies.

### Real constraint discovered

A direct import of the Directory client fails:
`github.com/ThalesIgnite/crypto11@v1.6.0` declares a different module path.
The probe reuses the replacement **already present in
[Directory's official go.mod](https://github.com/agntcy/dir/blob/v1.8.0/client/go.mod)**:

```go
replace github.com/ThalesIgnite/crypto11 => github.com/eclipse-keypont/crypto11 v1.6.8
```

Go does not propagate a dependency's `replace` directives to the consuming
module. This replacement stays here; the product's `go.mod` is not modified.
Its adoption, or the choice of a narrower client, must be decided at
integration. The full Directory client notably pulls in Cosign and part of the
Kubernetes graph: measure the binary cost before integrating it.

## Reproduce

Prerequisites: Python 3.11+, Go 1.27.3, a C compiler, Linux amd64 with glibc.
The first run downloads the Go modules and about 90 MB of official native
library, without installing any system component. Allow several minutes to
compile the dependencies. At most two Go processes run at once. Whether the
native archive works with an older glibc than the one you test on is not
established; replaying on the exact image of the target VPS is part of the
production qualification.

```sh
python3 scripts/verify-interop.py \
  --go /path/to/go1.27.3/bin/go \
  --output <output-dir>/interop
```

The output directory must be new. The script copies the sources to a temporary
directory, checks the SHA256 published by GitHub for the SLIM archive, extracts
only the expected library, verifies the modules, then runs the four tests with
no result cache. It keeps the logs and the source digests in `summary.json`. Any
failure, missing test or skip produces a nonzero exit code. A success carries
the status `passed_partial_qualification` with `int01_complete=false` and
`gate_g2_complete=false`.

The cache `$XDG_CACHE_HOME/agentcapsule-interop` (otherwise `~/.cache/...`)
stores the archive and the Go objects; the Go module cache stores the modules.
The script does not run the upstream native installer and installs no global
library. The archive is verified by SHA256; its Sigstore signature is not
verified by this probe. No real data, key or user identity is used.

The published native artifact returns core `3.4.6`, a `release` profile and a
build date, but its `GitSha` field is empty. Its identity is therefore verified
by the pinned SHA256 of the archive and of the extracted library; the probe does
not claim to infer the embedded commit from this incomplete metadata.

The A2A server is the upstream SDK's, on an ephemeral loopback port. Its
executor uses synthetic strings and the SDK's in-memory task store. Assertions
cover the JSON-RPC methods and the correlation of the observed responses, then
the received artifact and the re-reading of the task. This test proves neither
durability, nor ACLs, nor the PaaS's authentication. The timings it reports are
not production benchmarks.

## Proposed profile for the first integration

Start with A2A cards and non-streaming JSON-RPC operations on text tasks with
artifacts. Do not advertise REST, gRPC, streaming, push, cancellation or resume
until their real tests are delivered. The administrative API `/v1/agent-tasks`
and `capsule.v1` remain distinct from the protocol.

`accepted`, `delivered` and `expired` are internal PaaS states/events: explicitly
define their mapping to the normative A2A states before the adapter. A SLIM or
vsock ACK does not become `completed`. The host bridge contains CGO and the
native libraries, without imposing them on the guest harnesses.

`document-review` is here a **synthetic A2A** skill ID. The INT-02 step must
choose valid identifiers in the OASF 1.1.0 taxonomy or declare an authorized
extension, then validate the card through the OASF server. Protobuf decoding
does not establish the validity of this taxonomy.

## Remaining work to close INT-01 / prepare G2

1. Also pin the executable artifacts/images and their digest for the OASF
   server, Directory and SLIM; qualify the dependencies of the official
   Directory deployment. Its `install/docker` directory is not enough to
   guarantee a native installation. The probe imposes no Docker operating
   choice.
2. Start these services privately with minimal reproducible configurations and
   explicit authentication. Forbid exposure and publication in the public
   Directory network; refuse to infer any authorization from OASF, SLIM or an
   Agent Card. The unauthenticated loopback settings of this probe are not a
   production profile.
3. Validate a real OASF card and an invalid one, publish/search through
   Directory, then exchange a message between two endpoints through the SLIM
   node. Capture assertions on the wire, versions and redacted traces; measure
   idle and loaded RAM/CPU. No figure from the probe stands for VPS capacity.
4. After TEN/CAP/EVT, integrate authorization into every interaction, the
   durable mailbox before ACK, B's wake and the SLIM -> bridge -> vsock path.
   Verify cross-tenant refusals, cycles/quotas, failures and durable results
   before G2.

References: product spec ([product.md](product.md)) section 10 inter-agent,
A2A-001 to A2A-012, SDK constraint, Gate G2 and interoperability DoD; work
packages INT-01 to INT-05 of the [roadmap](../ROADMAP.md).
