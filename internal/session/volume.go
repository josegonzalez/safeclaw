package session

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/josegonzalez/safeclaw/internal/config"
)

// ErrUnsafeVolume is returned for a volume whose host path would expose
// safeclaw's config directory to the container.
var ErrUnsafeVolume = errors.New("would expose safeclaw's config directory")

// CheckVolume expands a host:container[:options] volume spec like
// ExpandVolume and checks its host path, with symlinks resolved. It returns
// an error wrapping ErrUnsafeVolume when the host path is safeclaw's config
// directory, one of its ancestors such as ~ or ~/.config, or a path inside
// it: the directory holds every session's ttyd credential, the dashboard's
// API token, and secrets kept in files, so a container that can read it
// can open other sessions' terminals and drive the dashboard, which can
// create sessions with any mount. Its warnings name every docker or
// container runtime socket the host path is or contains, which give the
// container control of docker and so of the host, but which some setups
// mount on purpose. A host path that is not absolute after expansion is a
// named volume and is not checked.
func CheckVolume(v string) (expanded string, warnings []string, err error) {
	expanded, err = ExpandVolume(v)
	if err != nil {
		return "", nil, err
	}
	host, _, _ := strings.Cut(expanded, ":")
	if !filepath.IsAbs(host) {
		return expanded, nil, nil
	}
	resolved, err := resolvePath(host)
	if err != nil {
		return "", nil, fmt.Errorf("volume %q: %w", v, err)
	}
	dir, err := resolvePath(config.Dir())
	if err != nil {
		return "", nil, fmt.Errorf("checking volume %q against the config directory: %w", v, err)
	}
	how := ""
	switch {
	case covers(resolved, dir) && covers(dir, resolved):
		how = "is that directory"
	case covers(resolved, dir):
		how = "contains it"
	case covers(dir, resolved):
		how = "is inside it"
	}
	if how != "" {
		shown := host
		if resolved != host {
			shown += " (" + resolved + ")"
		}
		return "", nil, fmt.Errorf("volume %q %w %s: the host path %s %s. It holds every session's terminal credential, the dashboard's API token, and secrets kept in files, so the session could open other sessions' terminals and drive the dashboard, which can create sessions with any mount. Mount a project directory instead", v, ErrUnsafeVolume, dir, shown, how)
	}
	// A socket is exposed through the path it was found at, which Docker
	// Desktop binds to its VM's socket, or through its resolved path.
	for _, sock := range runtimeSockets() {
		if covers(resolved, sock.path) || covers(resolved, sock.resolved) {
			warnings = append(warnings, fmt.Sprintf("volume %q exposes the container runtime socket %s, which gives the session control of docker and so of the host", v, sock.path))
		}
	}
	return expanded, warnings, nil
}

// resolvePath returns the absolute path p names with every symlink
// resolved. Docker creates a missing host path, so only its longest
// existing prefix is resolved, and the rest is kept as given. A broken
// symlink is refused, since what docker would create through it can't be
// checked.
func resolvePath(p string) (string, error) {
	p, err := filepath.Abs(p)
	if err != nil {
		return "", err
	}
	var rest []string
	for {
		r, err := filepath.EvalSymlinks(p)
		if err == nil {
			return filepath.Join(append([]string{r}, rest...)...), nil
		}
		if !errors.Is(err, fs.ErrNotExist) {
			return "", err
		}
		if _, lerr := os.Lstat(p); lerr == nil {
			return "", fmt.Errorf("%s is a broken symlink", p)
		}
		parent := filepath.Dir(p)
		if parent == p {
			return "", err
		}
		rest = append([]string{filepath.Base(p)}, rest...)
		p = parent
	}
}

// covers reports whether the resolved path outer is inner or one of its
// ancestors. Paths are compared by name and, where both exist, by file
// identity, so a case-insensitive filesystem's other spellings of a
// directory, or another bind mount of it, count as the same directory.
func covers(outer, inner string) bool {
	outerInfo, outerErr := os.Stat(outer)
	for p := inner; ; {
		if p == outer {
			return true
		}
		if outerErr == nil {
			if info, err := os.Stat(p); err == nil && os.SameFile(info, outerInfo) {
				return true
			}
		}
		parent := filepath.Dir(p)
		if parent == p {
			return false
		}
		p = parent
	}
}

// runtimeSocket is a docker or container runtime socket on the host, by
// the path it was found at and with symlinks resolved.
type runtimeSocket struct {
	path, resolved string
}

// runtimeSockets returns the docker and container runtime sockets that
// exist on the host, once each: the one DOCKER_HOST names, the standard
// system paths, and those Docker Desktop, OrbStack, Colima, Rancher
// Desktop, and rootless docker and podman use.
func runtimeSockets() []runtimeSocket {
	paths := []string{
		"/var/run/docker.sock",
		"/run/docker.sock",
		"/run/containerd/containerd.sock",
		"/run/podman/podman.sock",
		"/run/crio/crio.sock",
	}
	if h, ok := strings.CutPrefix(os.Getenv("DOCKER_HOST"), "unix://"); ok && h != "" {
		paths = append(paths, h)
	}
	if home, err := os.UserHomeDir(); err == nil {
		paths = append(paths,
			filepath.Join(home, ".docker", "run", "docker.sock"),
			filepath.Join(home, ".orbstack", "run", "docker.sock"),
			filepath.Join(home, ".colima", "default", "docker.sock"),
			filepath.Join(home, ".rd", "docker.sock"),
		)
	}
	if d := os.Getenv("XDG_RUNTIME_DIR"); d != "" {
		paths = append(paths,
			filepath.Join(d, "docker.sock"),
			filepath.Join(d, "podman", "podman.sock"),
		)
	}
	var out []runtimeSocket
	seen := map[string]bool{}
	for _, p := range paths {
		r, err := filepath.EvalSymlinks(p)
		if err != nil || seen[r] {
			continue
		}
		seen[r] = true
		out = append(out, runtimeSocket{path: filepath.Clean(p), resolved: r})
	}
	return out
}

// warnVolume prints a volume's warnings.
func (m *Manager) warnVolume(warnings []string) {
	for _, w := range warnings {
		m.printf("Warning: %s\n", w)
	}
}
