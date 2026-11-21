package main

import "dagger/agentcapsule/internal/dagger"

// CourseEnricher builds the guest harness that produces notions.json and
// exercices.json from an immutable course corpus.
func (m *Agentcapsule) CourseEnricher() *dagger.Directory {
	tree := m.builder().WithExec([]string{"apk", "add", "--no-cache", "pax-utils"}).
		WithEnvVariable("CGO_ENABLED", "1").
		WithExec([]string{"go", "build", "-buildvcs=false", "-trimpath", "-tags=netgo,osusergo,sqlite_omit_load_extension", "-ldflags=-linkmode external -extldflags '-static'", "-o", "/rootfs/opt/enricher/harness", "./examples/course-enricher"}).
		WithExec([]string{"sh", "-eu", "-c", `
mkdir -p /rootfs/usr/bin /rootfs/etc
for tool in mke2fs debugfs; do
 origin="$(command -v "$tool")"
 cp -L "$origin" "/rootfs/usr/bin/$tool"
 lddtree -l "$origin" | tail -n +2 | while read -r lib; do
   if [ -f "$lib" ]; then mkdir -p "/rootfs$(dirname "$lib")"; cp -L "$lib" "/rootfs$lib"; fi
 done
done
cp /rootfs/usr/bin/mke2fs /rootfs/usr/bin/mkfs.ext4
cp /etc/mke2fs.conf /rootfs/etc/
`}).Directory("/rootfs")
	return m.Pack(tree, m.Source.File("examples/course-enricher/harness.yaml"), 128)
}
