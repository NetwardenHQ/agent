//go:build windows

package container

// newPodmanCLIClientIfSupported returns a no-op on Windows: Podman there runs
// in a VM with its own socket, so the CLI fallback has nothing to add.
func newPodmanCLIClientIfSupported() RuntimeClient { return &NoOpClient{} }
