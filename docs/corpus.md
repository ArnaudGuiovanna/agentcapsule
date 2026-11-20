# Corpora

A **corpus** is an organization's knowledge from one path of a Git repository:
documents, slides, spreadsheets, audio and video. The platform converts them
to Markdown and data, indexes them, and publishes the result as an immutable
image. Every VM bound to the corpus mounts that image read-only under
`/corpus/<mount>/` and reads it with no network.

This page specifies the two formats a corpus has:

- the **source**: the files in the repository and the manifest
  `agentcapsule-corpus.yaml` beside them (`agentcapsule.corpus-source/v1`),
  which the content author writes;
- the **published layout** in the image (`agentcapsule.corpus/v1`), which
  administrators review and harnesses read.

> **Status.** The formats, the manifest checks, the reproducible image and
> its host checks, and the local commands `corpus init` and `corpus lint`
> are built (corpus lot 1). Fetching from GitHub and GitLab, the builder,
> review, publication and mounting come with the next lots of
> [plan-corpus.md](plan-corpus.md); [ADR 023](adr/023-corpora.md) records
> their decisions.

## Prepare the repository

The content author keeps the documents in a Git repository, with the manifest
at the corpus's path (the repository's root by default). Two commands of the
[CLI](cli.md#prepare-a-corpus-repository) help, on the author's own machine:

```sh
agentcapsule corpus init ./finance-l3 --title "Corporate finance, year 3" --language fr
agentcapsule corpus lint ./finance-l3
```

`corpus init` writes a commented manifest that keeps every file and turns on
no processing step. `corpus lint` reads the manifest and the files as a build
would: which files it keeps, of which type, which it ignores and why, and the
volumes it will process. Fix what it reports, commit, and ask an
administrator to build. To correct a converted document, change the
repository (a `corrections` entry, below) and build again: the platform keeps
no hidden state.

## The manifest: `agentcapsule.corpus-source/v1`

```yaml
schema: agentcapsule.corpus-source/v1
title: "Corporate finance, year 3"
language: fr
include: ["courses/**", "videos/**", "data/**"]
exclude: ["**/drafts/**"]
processing:
  ocr: {alias: ocr, mode: auto}
  transcription: {alias: transcribe-fr}
  vision: {alias: vision, describe_figures: true}
  summaries: {alias: summary}
  embeddings: {alias: embed}
documents:
  - path: courses/chap1.pdf
    title: "Chapter 1: time value of money"
    tags: [discounting, NPV]
corrections:
  - path: videos/session2.mp4
    markdown: corrections/session2.md
```

The file is strict YAML of at most 64 KiB: an unknown field, a duplicate key,
a second YAML document or a value of the wrong type refuses it.

| Field | Required | Rule |
|---|---|---|
| `schema` | yes | `agentcapsule.corpus-source/v1` |
| `title` | yes | 1 to 200 characters, without control characters |
| `language` | yes | the documents' main language, a BCP 47 tag: `fr`, `en-GB` |
| `include` | no | globs of the files to keep, at most 64; default `["**"]`; an empty list is refused |
| `exclude` | no | globs of the files to leave out, at most 64 |
| `processing` | no | the processing steps, below; a step left out is off |
| `documents` | no | metadata of some files: `path`, optional `title` (1 to 200 characters) and `tags` (at most 32, each 1 to 50 characters, once) |
| `corrections` | no | `path` of a document and `markdown`, a `.md` file of the repository that replaces the document's generated Markdown view |

**Paths and globs** are relative to the corpus's path, with `/` between
elements: no leading `/`, no `.` or `..` element, no empty element, no
backslash. In a glob, `*`, `?` and `[...]` match within one element (as Go's
`path.Match`) and an element `**` matches any number of elements, none
included. A glob that matches a directory keeps or leaves out everything in
it: `courses` and `courses/**` are the same. `**/drafts/**` leaves out every
`drafts` directory, at any depth.

### Processing steps

Each step goes through an LLM alias of the organization. Its grants, budgets
and prices apply as for any agent ([api/llm.md](api/llm.md)); an alias is 1
to 100 bytes without spaces.

| Step | Fields | What it does | Without it |
|---|---|---|---|
| `ocr` | `alias`, `mode`: `auto` (default) or `always` | reads the text of pages without native text (`auto`) or of every page (`always`) | pages without native text give no text |
| `transcription` | `alias` | transcribes audio and the sound of video, with timecodes | audio and video files are skipped |
| `vision` | `alias`, `describe_figures` (default `false`) | describes images, and figures in documents when `describe_figures` | images are skipped |
| `summaries` | `alias` | writes a summary of each document, for `INDEX.md` and its `README.md` | summaries are left out |
| `embeddings` | `alias` | computes vectors of the passages, for semantic search | no `search/vectors.*` |

Markdown, text, PDF with text, office documents and spreadsheets need no
step.

### Which files a build keeps

A build, and `corpus lint`, look at every file below the corpus's path and
keep a file only when none of these reasons applies, checked in this order:

| Reason | The file |
|---|---|
| `manifest` | is `agentcapsule-corpus.yaml` itself |
| `hidden` | has a name starting with `.`, or is in such a directory (listed once, as `name/`) |
| `symlink` | is a symbolic link: links are never followed |
| `special_file` | is not a regular file |
| `invalid_name` | has a path that is not printable UTF-8, or holds a backslash |
| `correction` | is the Markdown of a `corrections` entry: it is read with its document |
| `not_included` | matches no `include` glob |
| `excluded` | matches an `exclude` glob |
| `unsupported_type` | has an extension no build converts |
| `step_disabled` | needs a step that is off: audio and video need `transcription`, images need `vision` |

### Types

The type (`kind`) comes from the extension, in any case.

| Kind | Extensions | `corpus lint` measures |
|---|---|---|
| `markdown` | `.md`, `.markdown` | text tokens, about one per 4 bytes |
| `text` | `.txt`, `.text` | text tokens |
| `csv` | `.csv`, `.tsv` | text tokens |
| `pdf` | `.pdf` | pages |
| `docx` | `.docx` | pages, as the editor saved them |
| `odt` | `.odt` | pages, as the editor saved them |
| `pptx` | `.pptx` | slides |
| `xlsx` | `.xlsx` | sheets |
| `image` | `.png`, `.jpg`, `.jpeg`, `.webp`, `.gif` | the number of images |
| `audio` | `.mp3`, `.wav`, `.m4a`, `.flac`, `.ogg`, `.opus` | duration |
| `video` | `.mp4`, `.m4v`, `.mov`, `.webm`, `.mkv` | duration |
| `other` | any other | ignored, `unsupported_type` |

**Git LFS.** Large files can live in Git LFS. A build fetches each object by
its sha256, and checks it, before it converts the file. On a machine without
Git LFS, the file is a pointer: `corpus lint` counts the object's size from
the pointer and warns `lfs_pointer`, without measuring it.

### What `corpus lint` reads, and what it does not

`corpus lint` runs on the author's machine, on the author's own files. It
runs no other program and decodes no audio, video or image. It reads only
headers and indexes: the directory of an office file (a ZIP archive) and the
small part where the editor saved its page count; the page tree of a PDF,
inflating its compressed object streams (at most 64 MiB in all, and only the
first and last 32 MiB of a PDF past 128 MiB); the headers of WAV, MP3, FLAC,
Ogg, MP4 and QuickTime, Matroska and WebM files. A measure it cannot read
that way counts as `unmeasured`: the file is still kept, and the build
measures it. The platform host never runs these readers: only the builder,
in its VM, and the CLI read a corpus's sources.

### Errors and warnings

A build refuses a source for these reasons, which `corpus lint` reports with
the field and a message:

| Code | Meaning |
|---|---|
| `manifest_missing` | no `agentcapsule-corpus.yaml` at the corpus's path |
| `manifest_invalid` | not UTF-8, over 64 KiB, not a regular file, or not valid YAML of the manifest's form |
| `schema_unsupported` | `schema` is not `agentcapsule.corpus-source/v1` |
| `title_invalid`, `language_invalid` | `title` or `language` breaks its rule |
| `pattern_invalid` | an `include` or `exclude` glob breaks its rule |
| `processing_invalid` | an alias, or an OCR mode |
| `document_invalid`, `correction_invalid` | a `documents` or `corrections` entry breaks its rule, or names a path twice |
| `document_missing` | a `documents` or `corrections` entry names a file the build does not keep |
| `correction_missing` | a correction's Markdown is not a regular file of the corpus |
| `no_documents` | the build would keep no file |

Warnings do not stop a build:

| Code | Meaning |
|---|---|
| `pattern_unused` | an `include` glob matches no file, or an `exclude` glob removes no included file |
| `content_mismatch` | the file does not start as its extension says |
| `lfs_pointer` | a Git LFS pointer, not its object |
| `lfs_limit` | the LFS objects pass a worker's default limits: 10,000 objects, 20 GiB |
| `default_manifest` | no usable manifest: the defaults selected the files |

## The published layout: `agentcapsule.corpus/v1`

```
/corpus/<mount>/
  corpus.json          what the image holds (below)
  INDEX.md             the global summary: collections, documents, 2-3 line summaries, paths
  topics/*.md          topic indexes: notion -> sections
  glossary.md          extracted terms, each with a sourced definition
  docs/<id>/
    doc.json           the document in canonical form (below)
    README.md          summary, outline, metadata, source path
    part-001.md ...    the Markdown view, in parts
    pages/*.webp       pages, slides, video key frames
    data/*.csv         data kept as data, each with its .md description
  search/fts.sqlite    contextualized passages (SQLite FTS5)
  search/vectors.*     optional: passage vectors, with embeddings
  report.json          the build report (below)
  ext/                 reserved for enrichers: empty in this version
  lost+found/          made by mkfs.ext4, empty, readable by root only
```

`corpus.json`, `INDEX.md` and `search/fts.sqlite` are required. The image
holds directories and regular files only: no symbolic link, device, FIFO or
socket, no setuid or setgid bit. Every directory has mode 0755, every file
0644, owner root. The originals are not copied: a citation names a
document's source path and the commit, and a client can build the forge
link.

A harness lists `/corpus/` to find its corpora, reads `INDEX.md` first, and
opens `search/fts.sqlite` read-only with `mode=ro&immutable=1`: the mount is
read-only and `noexec`.

### `corpus.json`

| Field | Meaning |
|---|---|
| `schema` | `agentcapsule.corpus/v1` |
| `name`, `title` | the corpus's name and the manifest's title |
| `build_id`, `commit` | the build and the 40-hex commit it converted |
| `source_path` | the corpus's path in the repository, `""` for its root; each document's `path` is relative to it |
| `builder` | the builder release, `name@version` |
| `languages` | BCP 47 tags, the manifest's first |
| `modalities` | what the documents came from: `text`, `image`, `audio`, `video` |
| `tokens` | the documents' tokens, in total |
| `embeddings` | present with `search/vectors.*`: `alias`, `model` and `dimensions`; a harness embeds its queries through the same alias and checks the model |
| `documents` | each document: `id`, `path`, `kind`, `title`, `tokens` |

`corpus.json` names no release version: the image is built before it is
published, and one image can be published under several versions.

### Documents

A document's `<id>` is `d` and 16 hex digits of
`sha256("agentcapsule.corpus-document.v1\0" + path)`, where `path` is its
source path. A document keeps its ID from build to build while its file keeps
its path, so citations stay valid.

`doc.json` (`agentcapsule.corpus-document/v1`) holds `id`, `path`, `kind`,
`title`, and optionally `language`, `tags`, `pages`, `seconds` and
`corrected` (a correction replaced its view), then `elements` in reading
order. Each element has:

| Field | Meaning |
|---|---|
| `id` | stable within the document, `[a-z0-9][a-z0-9_-]{0,62}` |
| `type` | `heading`, `paragraph`, `list`, `table`, `figure`, `caption`, `code`, `formula`, `quote`, `note` or `transcript` |
| `text` | its text, in Markdown |
| `level` | a heading's level, 1 to 6 |
| `page`, `box` | the page or slide, from 1, and the box `[x0, y0, x1, y1]` as fractions of the page, from its top left corner |
| `sheet`, `range` | a spreadsheet's sheet and cells, `B2:F40` |
| `start`, `end` | seconds from the start of audio or video |
| `source` | how its text was obtained: `native`, `ocr`, `transcription`, `vision` or `correction` |
| `confidence` | 0 to 1, when the step that produced it says |
| `part` | the Markdown part that holds it, `part-001.md` |

In the Markdown parts, each element starts with an anchor
`<a id="ELEMENT_ID"></a>`, so a passage of the search index points to its
element and its locator.

### `report.json`: `agentcapsule.corpus-report/v1`

```json
{"schema": "agentcapsule.corpus-report/v1",
 "build_id": "cbd_...", "commit": "<40 hex>",
 "files": [{"path": "courses/chap1.pdf", "kind": "pdf", "status": "converted",
            "doc_id": "d3f1c0a9b2e4d5f60", "bytes": 182340, "tokens": 5120,
            "warnings": ["ocr_low_confidence"], "error": ""}],
 "totals": {"files": 1, "converted": 1, "cached": 0, "skipped": 0, "failed": 0, "tokens": 5120}}
```

The report lists every file the build selected (kept, or skipped for its type
or a step that is off). The worker reads it strictly: unknown fields are
refused, and the totals must be the files' sums.

| `status` | `doc_id` | `error` |
|---|---|---|
| `converted`: converted by this build | the document's | `""` |
| `cached`: from the builder's conversion cache | the document's | `""` |
| `skipped` | `""` | `unsupported_type` or `step_disabled` |
| `failed` | `""` | `unsupported_type`, `too_large`, `malformed`, `inference_failed` or `timeout` |

`warnings` holds, each once: `ocr_low_confidence`,
`transcription_low_confidence`, `no_text`, `truncated` (cut to fit a limit),
`corrected` (a correction replaced the view), `figures_not_described`. Costs
are not in the report: they come from the platform's ledger.

## The image and the host package

The image `corpus.ext4` is an ext4 filesystem built with `mkfs.ext4 -d` from
the layout, as harness images are, without root and without mounting:

- 4 KiB blocks, 256-byte inodes, no reserved blocks, label `corpus`;
- exactly the features `ext_attr`, `dir_index`, `filetype`, `extent`,
  `flex_bg`, `sparse_super`, `large_file`, `huge_file`, `dir_nlink`,
  `extra_isize`, `64bit` and `metadata_csum`: no journal;
- every inode owned by root, with the times 1;
- the UUID, also the directory hash seed, set by the worker before the build:
  the first 16 bytes of
  `sha256("agentcapsule.corpus-uuid.v1\0" + corpus ID + "\0" + commit + "\0" + builder digest)`,
  written as a UUID.

The size, inode count and modes are functions of the layout. The same commit
built by the same builder release therefore gives the same image, byte for
byte, and the same digest, whatever the order in which the builder wrote its
files.

Before the host accepts an image, it checks, without mounting it:

1. the superblock: an ext4 filesystem that fills the file, of 4 KiB blocks,
   labelled `corpus`, with the build's UUID, cleanly made, with the features
   above and no other;
2. the layout, with `debugfs` confined as for harness images
   ([registry.md](registry.md#image-inspection-sandbox)): the required files
   are regular files, `INDEX.md` is at most 64 KiB, `ext/` is empty, and
   every directory, listed one by one (`debugfs ls -p`), holds only
   directories and regular files without setuid or setgid bits, each
   directory reached once. Each listing costs one confined run, about 15 ms.

The worker then keeps the image in its cache, in
`<corpus.cache>/sha256/<hex>/`, where `<hex>` is the image's sha256:

| File | Content |
|---|---|
| `corpus.yaml` | `schema: agentcapsule.corpus/v1`, the corpus's `name`, `build_id`, `commit`, `builder` (`name`, `version`, `digest`), `base: agentcapsule-guest/2`, `uuid`, `bytes` |
| `checksums.json` | the sha256 of `corpus.yaml` and `corpus.ext4` |
| `corpus.ext4` | the image, read-only (mode 0444) |

`corpus.yaml` names no release version either: PostgreSQL maps
`name:version` to the digest.

## Limits

| Limit | Value |
|---|---|
| Manifest | 64 KiB |
| Globs | 64 `include`, 64 `exclude`, 256 bytes each |
| Paths | 1,024 bytes; file names of the layout 255 bytes |
| `INDEX.md` | 64 KiB (a target of 8,000 tokens) |
| `report.json` | 8 MiB |
| Image | 16 GiB by default (`corpus.max_image_mib` of the worker) |
| Directories of an image | 100,000 |
| LFS objects of one build | 10,000 and 20 GiB by default |

[Build, review and publish with the CLI](cli.md#build-and-publish-a-corpus)
