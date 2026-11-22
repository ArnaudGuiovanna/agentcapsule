//go:build race

package sandbox

// raceBuild: this executable runs under the race detector (tests only),
// whose shadow memory a program of this executable maps too (RunSelf).
const raceBuild = true
