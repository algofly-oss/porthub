//go:build darwin

package names

import (
	"bytes"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

const resolverRoot = "/etc/resolver"
const resolverMarker = "# Managed by PortHub private network\n"

var resolverState = struct {
	sync.Mutex
	owned map[int]resolverFile
}{owned: map[int]resolverFile{}}

type resolverFile struct {
	path    string
	content []byte
}

// RegisterLink routes only the workspace suffix to its private DNS server.
// It never changes networksetup, system DNS, search domains, or other VPN files.
func RegisterLink(index int, dns netip.AddrPort, suffix string) error {
	if index <= 0 || !dns.Addr().IsLoopback() || dns.Port() == 0 {
		return errors.New("invalid private DNS interface")
	}
	suffix = strings.TrimSuffix(strings.ToLower(suffix), ".")
	if suffix == "" || len(suffix) > 253 {
		return errors.New("invalid private DNS suffix")
	}
	for _, label := range strings.Split(suffix, ".") {
		if label == "" || len(label) > 63 {
			return errors.New("invalid private DNS suffix")
		}
		for _, r := range label {
			if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-') {
				return errors.New("invalid private DNS suffix")
			}
		}
	}
	resolverState.Lock()
	defer resolverState.Unlock()
	if err := os.MkdirAll(resolverRoot, 0755); err != nil {
		return err
	}
	path := filepath.Join(resolverRoot, suffix)
	if info, err := os.Lstat(path); err == nil {
		if !info.Mode().IsRegular() {
			return errors.New("private resolver path is not a regular file")
		}
		old, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if !bytes.HasPrefix(old, []byte(resolverMarker)) {
			return fmt.Errorf("resolver for %s already exists; refusing to overwrite it", suffix)
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	content := []byte(fmt.Sprintf("%s# interface %d\ndomain %s\nnameserver %s\nport %d\nsearch_order 100\ntimeout 2\n", resolverMarker, index, suffix, dns.Addr(), dns.Port()))
	tmp, err := os.CreateTemp(resolverRoot, ".porthub-")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err = tmp.Chmod(0644); err == nil {
		_, err = tmp.Write(content)
	}
	if err == nil {
		err = tmp.Sync()
	}
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	if err = os.Rename(tmp.Name(), path); err != nil {
		return err
	}
	if old, ok := resolverState.owned[index]; ok && old.path != path {
		removeResolver(old)
	}
	resolverState.owned[index] = resolverFile{path, content}
	return nil
}
func removeResolver(file resolverFile) {
	if data, err := os.ReadFile(file.path); err == nil && bytes.Equal(data, file.content) {
		_ = os.Remove(file.path)
	}
}
func Unregister(index int) {
	resolverState.Lock()
	defer resolverState.Unlock()
	if file, ok := resolverState.owned[index]; ok {
		removeResolver(file)
		delete(resolverState.owned, index)
	}
}
