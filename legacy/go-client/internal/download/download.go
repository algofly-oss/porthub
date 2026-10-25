// Package download replaces the aria2c helper used by `porthub get`:
// parallel byte-range segments, resumable across interruptions, with a
// single-stream fallback for servers that do not support ranges.
package download

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	DefaultConnections = 16
	MinSegment         = 1 << 20
	attempts           = 6
)

type Options struct {
	URL         string
	Dir         string
	Connections int
	Client      *http.Client
	Progress    io.Writer
}

// state is persisted beside the partial file so an interrupted download
// resumes only when the remote file is provably unchanged.
type state struct {
	URL          string    `json:"url"`
	Size         int64     `json:"size"`
	ETag         string    `json:"etag,omitempty"`
	LastModified string    `json:"last_modified,omitempty"`
	Segments     []segment `json:"segments"`
}
type segment struct {
	Start int64 `json:"start"`
	End   int64 `json:"end"` // inclusive
	Done  int64 `json:"done"`
}

type remote struct {
	size                     int64
	ranges                   bool
	etag, lastModified, name string
}

func probe(ctx context.Context, client *http.Client, raw string) (remote, error) {
	var r remote
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, raw, nil)
	if err != nil {
		return r, err
	}
	req.Header.Set("Range", "bytes=0-0")
	resp, err := client.Do(req)
	if err != nil {
		return r, err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1))
	r.etag, r.lastModified = resp.Header.Get("ETag"), resp.Header.Get("Last-Modified")
	if _, params, err := mime.ParseMediaType(resp.Header.Get("Content-Disposition")); err == nil {
		r.name = params["filename"]
	}
	switch resp.StatusCode {
	case http.StatusPartialContent:
		total := resp.Header.Get("Content-Range")
		if i := strings.LastIndexByte(total, '/'); i >= 0 {
			if r.size, err = strconv.ParseInt(total[i+1:], 10, 64); err == nil && r.size > 0 {
				r.ranges = true
			}
		}
		if !r.ranges {
			r.size = -1
		}
	case http.StatusOK:
		r.size = resp.ContentLength
	default:
		return r, fmt.Errorf("server returned %s", resp.Status)
	}
	return r, nil
}

// fileName picks a safe local name: never a path, never hidden traversal.
func fileName(raw, disposition string) string {
	name := filepath.Base(disposition)
	if disposition == "" || name == "." || name == "/" {
		u, _ := url.Parse(raw)
		name = path.Base(u.Path)
	}
	if name == "/" || name == "." {
		name = ""
	}
	name = strings.TrimLeft(strings.Map(func(r rune) rune {
		if r == '/' || r == '\\' || r < 32 {
			return '_'
		}
		return r
	}, name), ".")
	if name == "" {
		return "index.html"
	}
	return name
}

// available mirrors aria2c's auto-renaming: an existing complete file is
// never overwritten; an unfinished download of the same name is resumed.
func available(dir, name string) string {
	ext := filepath.Ext(name)
	stem := strings.TrimSuffix(name, ext)
	for i := 0; ; i++ {
		candidate := name
		if i > 0 {
			candidate = fmt.Sprintf("%s.%d%s", stem, i, ext)
		}
		target := filepath.Join(dir, candidate)
		if _, err := os.Stat(target + ".porthub-part"); err == nil {
			return target
		}
		if _, err := os.Stat(target); os.IsNotExist(err) {
			return target
		}
	}
}

// Get downloads to Dir and returns the final path.
func Get(ctx context.Context, o Options) (string, error) {
	u, err := url.Parse(o.URL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return "", errors.New("an http(s) URL is required")
	}
	client := o.Client
	if client == nil {
		client = &http.Client{}
	}
	if o.Connections < 1 {
		o.Connections = DefaultConnections
	}
	info, err := probe(ctx, client, o.URL)
	if err != nil {
		return "", err
	}
	target := available(o.Dir, fileName(o.URL, info.name))
	part, control := target+".porthub-part", target+".porthub-part.json"
	if !info.ranges {
		if err = single(ctx, client, o.URL, part, o.Progress); err != nil {
			return "", err
		}
		return target, finish(part, control, target)
	}
	s := resume(control, o.URL, info)
	if s == nil {
		s = plan(o.URL, info, o.Connections)
		_ = os.Remove(part)
	}
	f, err := os.OpenFile(part, os.O_CREATE|os.O_RDWR, 0644)
	if err != nil {
		return "", err
	}
	defer f.Close()
	if err = f.Truncate(s.Size); err != nil {
		return "", err
	}
	if err = parallel(ctx, client, f, s, control, o.Progress); err != nil {
		return "", err
	}
	if err = f.Sync(); err != nil {
		return "", err
	}
	if err = f.Close(); err != nil {
		return "", err
	}
	return target, finish(part, control, target)
}
func finish(part, control, target string) error {
	if _, err := os.Stat(target); err == nil {
		return fmt.Errorf("%s appeared during download; keeping %s", target, part)
	}
	if err := os.Rename(part, target); err != nil {
		return err
	}
	_ = os.Remove(control)
	return nil
}
func resume(control, raw string, info remote) *state {
	b, err := os.ReadFile(control)
	if err != nil {
		return nil
	}
	var s state
	if json.Unmarshal(b, &s) != nil || s.URL != raw || s.Size != info.size {
		return nil
	}
	// Without a validator equality cannot be proven; start over.
	if (s.ETag == "" && s.LastModified == "") || s.ETag != info.etag || s.LastModified != info.lastModified {
		return nil
	}
	for _, g := range s.Segments {
		if g.Done < 0 || g.Start+g.Done > g.End+1 {
			return nil
		}
	}
	return &s
}
func plan(raw string, info remote, connections int) *state {
	s := &state{URL: raw, Size: info.size, ETag: info.etag, LastModified: info.lastModified}
	size := max(int64(MinSegment), (info.size+int64(connections)-1)/int64(connections))
	for start := int64(0); start < info.size; start += size {
		s.Segments = append(s.Segments, segment{Start: start, End: min(start+size, info.size) - 1})
	}
	return s
}
func save(control string, s *state) error {
	b, err := json.Marshal(s)
	if err != nil {
		return err
	}
	tmp := control + ".tmp"
	if err = os.WriteFile(tmp, b, 0644); err != nil {
		return err
	}
	return os.Rename(tmp, control)
}

func parallel(ctx context.Context, client *http.Client, f *os.File, s *state, control string, progress io.Writer) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var mu sync.Mutex
	errs := make(chan error, len(s.Segments))
	var wg sync.WaitGroup
	for i := range s.Segments {
		if s.Segments[i].Start+s.Segments[i].Done > s.Segments[i].End {
			continue
		}
		wg.Add(1)
		go func(g *segment) {
			defer wg.Done()
			if err := fetch(ctx, client, f, s, g, &mu); err != nil {
				errs <- err
				cancel()
			}
		}(&s.Segments[i])
	}
	finished := make(chan struct{})
	go func() { wg.Wait(); close(finished) }()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	started, base := time.Now(), downloaded(s, &mu)
	for {
		select {
		case <-finished:
			mu.Lock()
			err := save(control, s)
			mu.Unlock()
			select {
			case e := <-errs:
				return e
			default:
			}
			report(progress, s, &mu, started, base, true)
			return err
		case <-ticker.C:
			mu.Lock()
			_ = save(control, s)
			mu.Unlock()
			report(progress, s, &mu, started, base, false)
		}
	}
}
func downloaded(s *state, mu *sync.Mutex) int64 {
	mu.Lock()
	defer mu.Unlock()
	var n int64
	for _, g := range s.Segments {
		n += g.Done
	}
	return n
}
func report(w io.Writer, s *state, mu *sync.Mutex, started time.Time, base int64, final bool) {
	if w == nil {
		return
	}
	n := downloaded(s, mu)
	rate := float64(n-base) / max(time.Since(started).Seconds(), 0.001)
	end := "\r"
	if final {
		end = "\n"
	}
	fmt.Fprintf(w, "[porthub-get] %.1f/%.1f MiB (%.0f%%) %.1f MiB/s%s", float64(n)/(1<<20), float64(s.Size)/(1<<20), float64(n)*100/float64(max(s.Size, 1)), rate/(1<<20), end)
}

// fetch downloads one segment, retrying from its last written byte. A server
// that ignores Range or reports a different file aborts instead of corrupting.
func fetch(ctx context.Context, client *http.Client, f *os.File, s *state, g *segment, mu *sync.Mutex) error {
	var last error
	for attempt := 0; attempt < attempts; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(time.Duration(1<<attempt) * 250 * time.Millisecond):
			}
		}
		mu.Lock()
		offset := g.Start + g.Done
		mu.Unlock()
		if offset > g.End {
			return nil
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.URL, nil)
		if err != nil {
			return err
		}
		req.Header.Set("Range", fmt.Sprintf("bytes=%d-%d", offset, g.End))
		if s.ETag != "" {
			req.Header.Set("If-Range", s.ETag)
		} else if s.LastModified != "" {
			req.Header.Set("If-Range", s.LastModified)
		}
		resp, err := client.Do(req)
		if err != nil {
			last = err
			continue
		}
		if resp.StatusCode != http.StatusPartialContent || !strings.HasPrefix(resp.Header.Get("Content-Range"), fmt.Sprintf("bytes %d-%d/%d", offset, g.End, s.Size)) {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusPartialContent {
				return errors.New("remote file changed during download; run the command again to restart")
			}
			last = fmt.Errorf("server returned %s", resp.Status)
			if resp.StatusCode < 500 && resp.StatusCode != http.StatusTooManyRequests {
				return last
			}
			continue
		}
		buf := make([]byte, 256*1024)
		for {
			n, rerr := resp.Body.Read(buf)
			if n > 0 {
				mu.Lock()
				at := g.Start + g.Done
				mu.Unlock()
				if at+int64(n) > g.End+1 {
					resp.Body.Close()
					return errors.New("server sent more data than requested")
				}
				if _, err := f.WriteAt(buf[:n], at); err != nil {
					resp.Body.Close()
					return err
				}
				mu.Lock()
				g.Done += int64(n)
				mu.Unlock()
			}
			if rerr == io.EOF {
				break
			}
			if rerr != nil {
				last = rerr
				break
			}
		}
		resp.Body.Close()
		mu.Lock()
		complete := g.Start+g.Done > g.End
		mu.Unlock()
		if complete {
			return nil
		}
		if last == nil {
			last = io.ErrUnexpectedEOF
		}
	}
	return fmt.Errorf("segment %d-%d failed: %w", g.Start, g.End, last)
}

// single streams servers without range support; a restart begins again.
func single(ctx context.Context, client *http.Client, raw, part string, progress io.Writer) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, raw, nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("server returned %s", resp.Status)
	}
	f, err := os.Create(part)
	if err != nil {
		return err
	}
	n, err := io.Copy(f, resp.Body)
	if err == nil && resp.ContentLength >= 0 && n != resp.ContentLength {
		err = io.ErrUnexpectedEOF
	}
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil && progress != nil {
		fmt.Fprintf(progress, "[porthub-get] %.1f MiB (server does not support ranges; single stream)\n", float64(n)/(1<<20))
	}
	return err
}
