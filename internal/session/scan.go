package session

import (
	"bytes"
	"context"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/josegonzalez/safeclaw/internal/config"
	"github.com/josegonzalez/safeclaw/internal/docker"
	"github.com/josegonzalez/safeclaw/internal/scan"
	"github.com/josegonzalez/safeclaw/internal/termtext"
	"github.com/josegonzalez/safeclaw/internal/variant"
)

const (
	// DefaultScanMemory is the least memory a scan or update container
	// gets: clamscan holds the whole signature database in memory (a peak
	// of about 1.1 GB with ClamAV 1.5 and the official databases of
	// November 2026, which keep growing), freshclam loads it once to test
	// an update, and the scan's /tmp tmpfs counts toward the limit too. A
	// sandbox with a higher --memory lends its limit to the scans of files
	// copied out of it.
	DefaultScanMemory = "3g"
	// scanMount is where a cp-out scan container finds the files to scan.
	scanMount = "/scan"
	// scanTmpfs is a scan container's scratch space, where clamscan
	// unpacks archives. It is larger than a sandbox's /tmp, since clamscan
	// unpacks up to 400 MB of each file by default.
	scanTmpfs = "/tmp:rw,nosuid,nodev,noexec,size=512m"
	// updateTmpfs is the update container's scratch space, holding its
	// freshclam.conf.
	updateTmpfs = "/tmp:rw,nosuid,nodev,noexec,size=64m"
	// scanExecMaxOutput caps the output of a `sandbox scan` clamscan,
	// which code in the sandbox can write to: one line per file.
	scanExecMaxOutput = 8 << 20
	// updateNetwork is the network the update container downloads on.
	updateNetwork = "bridge"
)

// ErrScanImage is wrapped by the error returned when the image scans run
// in is missing.
var ErrScanImage = errors.New("malware scanning needs the sandbox variant image")

// ErrNoSignatureMount is returned when `sandbox scan` targets a sandbox
// created before signatures were mounted into sandboxes.
var ErrNoSignatureMount = errors.New("has no malware signatures mounted, since it was created before they were")

func (m *Manager) signaturesDir() string {
	if m.SignaturesDir != "" {
		return m.SignaturesDir
	}
	return config.SignaturesDir()
}

// signaturesMount returns the signature directory every sandbox mounts
// read-only at scan.DatabaseDir, creating it, readable by the sandbox user,
// when it is missing. It exists even before any signatures are installed,
// so sandboxes created then see them once `update-signatures` puts them
// there.
func (m *Manager) signaturesMount() (string, error) {
	dir := m.signaturesDir()
	if err := os.MkdirAll(dir, scan.DirMode); err != nil {
		return "", fmt.Errorf("signatures: %w", err)
	}
	if err := os.Chmod(dir, scan.DirMode); err != nil {
		return "", fmt.Errorf("signatures: %w", err)
	}
	return dir, nil
}

// Signatures returns the installed signatures, or an error wrapping
// scan.ErrNoSignatures that says how to install them.
func (m *Manager) Signatures() (*scan.Signatures, error) {
	s, err := scan.Read(m.signaturesDir())
	if errors.Is(err, scan.ErrNoSignatures) {
		return nil, fmt.Errorf("%w: run `safeclaw sandbox update-signatures`", err)
	}
	return s, err
}

// scanImage returns the checked ID of the sandbox variant's image, which
// has clamscan and freshclam.
func (m *Manager) scanImage(ctx context.Context) (string, error) {
	id, err := m.checkImage(ctx, variant.Sandbox)
	if errors.Is(err, ErrNoImage) {
		return "", fmt.Errorf("%w: run `safeclaw pull --variant %s` or `safeclaw build --variant %s`", ErrScanImage, variant.Sandbox, variant.Sandbox)
	}
	return id, err
}

// hostUser is the --user the scan and update containers run as: the host
// user, so they can read and write the host directories they mount
// whatever their modes, while holding no capabilities.
func hostUser() string {
	return fmt.Sprintf("%d:%d", os.Getuid(), os.Getgid())
}

// helperArgs are the `docker run` flags shared by the scan and update
// containers: removed when done, the host user, no capabilities or new
// privileges, no log, and a read-only root filesystem with tmpfs at /tmp.
func helperArgs(tmpfs string) []string {
	return []string{
		"--rm",
		"--user", hostUser(),
		"--workdir", "/tmp",
		"--env", "HOME=/tmp",
		"--env", "PATH=" + sandboxPath,
		"--cap-drop", "ALL",
		"--security-opt", "no-new-privileges",
		"--log-driver", sandboxLogDriver,
		"--read-only",
		"--tmpfs", tmpfs,
	}
}

// scanMemory returns the larger of limit and DefaultScanMemory, in bytes.
func scanMemory(limit int64) int64 {
	least, _ := ParseSize(DefaultScanMemory)
	return max(limit, least)
}

// UpdateSignatures downloads the latest ClamAV signatures with freshclam
// and installs them in the signature directory. freshclam runs in a
// short-lived container of the sandbox variant with the default bridge
// network, no secrets, and no mount but a staging directory next to the
// signature directory, seeded with the current signatures so only what
// changed is downloaded. The staged signatures replace the old ones only
// once freshclam succeeds and they are complete, so a failed update keeps
// the old ones. Updates are serialized by a lock next to the directory.
func (m *Manager) UpdateSignatures(ctx context.Context) (*scan.Signatures, error) {
	image, err := m.scanImage(ctx)
	if err != nil {
		return nil, err
	}
	dir := m.signaturesDir()
	parent := filepath.Dir(dir)
	unlock, err := lockFileCtx(ctx, parent, filepath.Base(dir)+".lock")
	if err != nil {
		return nil, err
	}
	defer unlock()
	staging, err := os.MkdirTemp(parent, "."+filepath.Base(dir)+"-update-*")
	if err != nil {
		return nil, err
	}
	defer func() { _ = os.RemoveAll(staging) }()
	if err := scan.Seed(dir, staging); err != nil {
		return nil, fmt.Errorf("copy the current signatures: %w", err)
	}
	args := append([]string{"run"}, helperArgs(updateTmpfs)...)
	args = append(args,
		"--network", updateNetwork,
		"--memory", strconv.FormatInt(scanMemory(0), 10),
		"--pids-limit", strconv.Itoa(DefaultSandboxPidsLimit),
		"--mount", writableBind(staging, scan.DatabaseDir),
	)
	args = append(args, imageArgs(variant.Image(variant.Sandbox), image)...)
	args = append(args, scan.FreshclamArgs()...)
	m.printf("Updating malware signatures with freshclam (about 110 MB the first time)\n")
	out, err := m.Docker.R.Output(ctx, nil, args...)
	if len(out) > 0 {
		m.printf("%s\n", strings.TrimRight(termtext.Escape(string(out)), "\n"))
	}
	if err != nil {
		return nil, fmt.Errorf("freshclam failed, so the old signatures were kept: %w", err)
	}
	return scan.Install(staging, dir)
}

// writableBind returns the `docker run --mount` value of a writable bind
// of src at dst, quoted as CSV like ReadOnlyBind.Mount.
func writableBind(src, dst string) string {
	var buf bytes.Buffer
	w := csv.NewWriter(&buf)
	_ = w.Write([]string{"type=bind", "src=" + src, "dst=" + dst, "bind-propagation=rprivate"})
	w.Flush()
	return strings.TrimSuffix(buf.String(), "\n")
}

// scanArgs returns the `docker run` arguments of a container that scans
// paths in the host directory files, mounted read-only at scanMount, with
// the signatures mounted read-only: no network, the host user with no
// capabilities, and the resource limits of the sandbox c, with at least
// DefaultScanMemory of memory.
func scanArgs(c docker.Container, image, signatures, files string, paths []string) []string {
	pids := int64(DefaultSandboxPidsLimit)
	if c.HostConfig.PidsLimit != nil && *c.HostConfig.PidsLimit > 0 {
		pids = *c.HostConfig.PidsLimit
	}
	cpus := DefaultSandboxCPUs
	if c.HostConfig.NanoCpus > 0 {
		cpus = strconv.FormatFloat(float64(c.HostConfig.NanoCpus)/1e9, 'f', -1, 64)
	}
	args := append([]string{"run"}, helperArgs(scanTmpfs)...)
	args = append(args,
		"--network", "none",
		"--memory", strconv.FormatInt(scanMemory(c.HostConfig.Memory), 10),
		"--pids-limit", strconv.FormatInt(pids, 10),
		"--cpus", cpus,
		"--mount", ReadOnlyBind{Source: signatures, Target: scan.DatabaseDir}.Mount(),
		"--mount", ReadOnlyBind{Source: files, Target: scanMount}.Mount(),
	)
	args = append(args, imageArgs(variant.Image(variant.Sandbox), image)...)
	return append(args, scan.ClamscanArgs(paths)...)
}

// scanPrepared is what cp-out checks before copying anything when it is to
// scan: the signatures and the scan image.
type scanPrepared struct {
	sigs  *scan.Signatures
	image string
}

// prepareScan checks that cp-out can scan: signatures are installed and
// the scan image exists.
func (m *Manager) prepareScan(ctx context.Context) (*scanPrepared, error) {
	sigs, err := m.Signatures()
	if err != nil {
		return nil, fmt.Errorf("%w, or pass --no-scan to copy without scanning", err)
	}
	image, err := m.scanImage(ctx)
	if err != nil {
		return nil, fmt.Errorf("%w, or pass --no-scan to copy without scanning", err)
	}
	return &scanPrepared{sigs: sigs, image: image}, nil
}

// scanCopied scans the files names in dir, where cp-out extracted them, in
// a fresh container (see scanArgs), so nothing left running in the sandbox
// can change what is scanned or the result. Each file is linked into a
// directory of its own under a numbered name, so the scan sees exactly the
// bytes to be placed and clamscan's output can't be confused by a name. It
// returns a result for each name, in order, with Path set to the name.
func (m *Manager) scanCopied(ctx context.Context, c docker.Container, p *scanPrepared, dir string, names []string) ([]scan.Result, error) {
	if len(names) == 0 {
		return nil, nil
	}
	// docker needs an absolute path to mount, and dir is relative when
	// cp-out was given a relative HOST_DIR.
	dir, err := filepath.Abs(dir)
	if err != nil {
		return nil, err
	}
	files, err := os.MkdirTemp(dir, "scan-")
	if err != nil {
		return nil, err
	}
	paths := make([]string, len(names))
	byPath := make(map[string]string, len(names))
	for i, n := range names {
		num := strconv.Itoa(i)
		if err := linkOrCopy(filepath.Join(dir, n), filepath.Join(files, num)); err != nil {
			return nil, fmt.Errorf("prepare %q for scanning: %w", n, err)
		}
		paths[i] = path.Join(scanMount, num)
		byPath[paths[i]] = n
	}
	out, runErr := m.Docker.R.Output(ctx, nil, scanArgs(c, p.image, m.signaturesDir(), files, paths)...)
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	results := scan.Parse(out, paths)
	for i := range results {
		results[i].Path = byPath[results[i].Path]
		if results[i].Reason == scan.NoResult && runErr != nil {
			results[i].Reason = scanFailed(runErr)
		}
	}
	return results, nil
}

// scanFailed is the reason given to a file clamscan printed no result for
// when the scan itself failed: the error on one line, since docker's errors
// span several.
func scanFailed(err error) string {
	return "the scan failed: " + strings.Join(strings.Fields(err.Error()), " ")
}

// linkOrCopy hard links from to to, copying it where the host filesystem
// can't link.
func linkOrCopy(from, to string) error {
	if err := os.Link(from, to); err == nil {
		return nil
	}
	in, err := os.Open(from)
	if err != nil {
		return err
	}
	defer func() { _ = in.Close() }()
	out, err := os.OpenFile(to, os.O_WRONLY|os.O_CREATE|os.O_EXCL, copyFileMode)
	if err != nil {
		return err
	}
	_, err = io.Copy(out, in)
	if closeErr := out.Close(); err == nil {
		err = closeErr
	}
	return err
}

// ScanReport is the result of a scan.
type ScanReport struct {
	// Signatures are the signatures the files were scanned with.
	Signatures *scan.Signatures `json:"signatures"`
	// Results are each file's result.
	Results []scan.Result `json:"results"`
}

// Flagged returns the results that are not clean.
func (r *ScanReport) Flagged() []scan.Result {
	var out []scan.Result
	for _, res := range r.Results {
		if res.Flagged() {
			out = append(out, res)
		}
	}
	return out
}

// ScanSandbox runs clamscan on paths inside a running sandbox, as the
// sandbox user, with the signatures the sandbox mounts read-only. Since it
// runs where the untrusted files are, anything they left running there can
// change its result, so it is advisory: cp-out scans what it copies again
// outside the sandbox. A path that is a directory gets a result for each
// file directly in it, named as clamscan printed it.
func (m *Manager) ScanSandbox(ctx context.Context, name string, paths []string) (*ScanReport, error) {
	if len(paths) == 0 {
		return nil, errors.New("at least one path is required")
	}
	c, err := m.runningSandbox(ctx, name)
	if err != nil {
		return nil, err
	}
	name = config.SessionName(name)
	mounted := false
	for _, mt := range c.Mounts {
		if mt.Destination == scan.DatabaseDir {
			mounted = true
		}
	}
	if !mounted {
		return nil, fmt.Errorf("sandbox %q %w: remove it with `safeclaw sandbox rm -f %s` and run it again", name, ErrNoSignatureMount, name)
	}
	sigs, err := m.Signatures()
	if err != nil {
		return nil, err
	}
	opts := copyExec
	opts.MaxOutput = scanExecMaxOutput
	out, runErr := m.Docker.Exec(ctx, config.ContainerName(name), opts, SandboxCommand(scan.ClamscanArgs(paths))...)
	if errors.Is(runErr, docker.ErrOutputTooLarge) {
		return nil, fmt.Errorf("clamscan: %w", runErr)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	results := scan.Parse(out, paths)
	for i := range results {
		if results[i].Reason == scan.NoResult && runErr != nil {
			results[i].Reason = scanFailed(runErr)
		}
	}
	return &ScanReport{Signatures: sigs, Results: results}, nil
}
