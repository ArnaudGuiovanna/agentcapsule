# Private corpus builder

The worker invokes this release inside the organization's networkless builder VM. Source decoding, PDF rendering, audio processing and FTS5 indexing run there. Optional model calls use the platform socket and the aliases from the source manifest. Other harnesses can read the resulting Markdown, JSON and SQLite files with their own language's tools.

Build the release from the repository root.

```sh
dagger call corpus-builder export --path=./build/corpus-builder
```

The image includes LibreOffice, Poppler, FFmpeg and e2fsprogs. Its ext4 file is 1,792 MiB. Configure the worker's `registry.max_harness_mib` to at least 1792 before importing it. Publish and sign the package with the ordinary harness registry workflow, import that digest and set `corpus.builder.harness` to its name and version. Use a system image with the `corpus.mount` feature. [Registry workflow](../../docs/registry.md)

One encrypted volume holds the organization's conversion cache and phase checkpoints. Size `corpus.builder.volume_mib` for the expanded source, cached conversions and the image being assembled. A retry of a completed conversion reuses the same checkpoint. Changing one file preserves the other files' cached results. A failed phase leaves a bounded diagnostic at `builder/last-error.json` on that volume.

The release requests `stream.output` for per-file progress. Operators with `corpus:manage` can follow the reported file steps with `agentcapsule corpus-build watch BUILD_ID`.

Operators can inspect the per-build file report before publishing. The report identifies cached files and conversion failures. The image contains a canonical report, so a warm rebuild of identical source and builder can reproduce the original image byte for byte. [Corpus API](../../docs/api/corpora.md)
