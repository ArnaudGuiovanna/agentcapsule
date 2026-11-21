# Course enricher

This Go harness creates a list of notions and an exercise for each document
in a reviewed course. Both JSON files cite the source document's README.
The learning material is computed once, then shared read-only by the agents
that mount the published corpus.

Build the package with `dagger call course-enricher export --path=./build/course-enricher`.
Use the regular harness signing and import workflow, authorize the release with
`POST /v1/corpus-enrichers`, and request its execution while the build is in
`REVIEW`. The API returns a job ID. When its state is `READY`, publish the
build. A consumer of mount `course` and authorization `tutor` sees
`/corpus/course/ext/tutor/notions.json` and
`/corpus/course/ext/tutor/exercices.json`.

The guest uses the standard capsule.v1 control and platform channels. Its
package includes mkfs.ext4 and debugfs. To exercise the complete guest
exchange and inspect the consumer's mounts on a KVM host, pass
`--course-enricher ./build/course-enricher` to
`scripts/verify-product-guest.py` with the existing product test arguments.
