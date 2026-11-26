package main

import (
	"context"
	"fmt"
	"regexp"

	"dagger/agentcapsule/internal/dagger"
)

// PiAgent builds Pi from the locked npm distribution with the corpus and A2A tools.
func (m *Agentcapsule) PiAgent(ctx context.Context,
	// Harness version for an official distribution, e.g. 0.1.6.
	// +optional
	releaseVersion string,
) (*dagger.Directory, error) {
	example := m.Source.Directory("examples/pi-agent")
	manifest, err := releaseManifest(ctx, example.File("harness.yaml"), releaseVersion)
	if err != nil {
		return nil, err
	}
	image := example.DockerBuild(dagger.DirectoryDockerBuildOpts{Platform: platform})
	return m.Adapt(image, example.File("adapter.json"), manifest, 640), nil
}

var releaseVersionPattern = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+(-[A-Za-z0-9][A-Za-z0-9.-]*)?$`)
var manifestVersionLine = regexp.MustCompile(`(?m)^version: [A-Za-z0-9._-]+$`)

// Keep the example's development identity unless the release supplies its version.
func releaseManifest(ctx context.Context, manifest *dagger.File, version string) (*dagger.File, error) {
	if version == "" {
		return manifest, nil
	}
	if len(version) > 100 || !releaseVersionPattern.MatchString(version) {
		return nil, fmt.Errorf("invalid harness release version")
	}
	contents, err := manifest.Contents(ctx)
	if err != nil {
		return nil, err
	}
	if len(manifestVersionLine.FindAllStringIndex(contents, 2)) != 1 {
		return nil, fmt.Errorf("expected one top-level harness version")
	}
	contents = manifestVersionLine.ReplaceAllString(contents, "version: "+version)
	return dag.Directory().WithNewFile("harness.yaml", contents).File("harness.yaml"), nil
}
