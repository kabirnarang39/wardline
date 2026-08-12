package reload

import (
	"log/slog"
	"path/filepath"
	"time"

	"github.com/fsnotify/fsnotify"
)

// WatchTarget names one file whose changes should trigger a reload --
// Fn is the exact same closure a manual reload trigger (POST
// /dashboard/api/reload/{domain}) already calls; the watcher is a
// second way to invoke it, not a second implementation of what
// "reload" means for that domain.
type WatchTarget struct {
	Path string       // absolute or relative path to the file to watch
	Name string       // domain name, for logging ("policy", "rbac", "budget")
	Fn   func() error // the reload closure to call on change
}

// debounceWindow coalesces a burst of filesystem events (many editors
// write+chmod+rename in quick succession for one logical save) into a
// single reload call -- the same debounce discipline every real
// production file-watcher (Consul-template, Envoy's file-based xDS,
// Kubernetes ConfigMap projection watchers) applies for the same
// reason: reacting to every individual event in a save burst would
// call Fn several times for one edit, and could observe a
// partially-written intermediate file mid-burst.
const debounceWindow = 300 * time.Millisecond

// WatchFiles watches every distinct directory containing a target's
// Path and calls that target's Fn (debounced) whenever its file
// changes, until stop is closed. Errors from Fn are logged via logger,
// never fatal -- the same non-fatal-reload posture the manual POST
// /dashboard/api/reload/{domain} endpoint already has: a bad edit on
// disk must not crash the running proxy, just fail to apply.
//
// Watches the ENCLOSING DIRECTORY of each target, not the file itself,
// and filters events by filename -- fsnotify's own documented pattern
// for surviving an atomic replace-by-rename save (vim, and most
// editors' "write to a temp file, then rename over the original"
// default save mode, and how Kubernetes projects a ConfigMap volume):
// a watch on the file's own inode is silently orphaned the moment that
// rename happens, since the watched inode is now the OLD content under
// a name nothing points to anymore, and no further event for the new
// file (a different inode) would ever arrive on that watch.
//
// More than one target may share a directory (policy.yaml and
// rbac.yaml side by side) or even the exact same Path (config.yaml
// backs policy/rbac/budget settings all at once) -- both cases call
// every matching target's own Fn independently when that file changes.
func WatchFiles(logger *slog.Logger, targets []WatchTarget, stop <-chan struct{}) error {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return err
	}

	byDir := make(map[string][]WatchTarget)
	for _, t := range targets {
		if t.Path == "" {
			continue
		}
		abs, err := filepath.Abs(t.Path)
		if err != nil {
			logger.Warn("config file watcher: could not resolve path, not watching", "domain", t.Name, "path", t.Path, "error", err)
			continue
		}
		dir := filepath.Dir(abs)
		byDir[dir] = append(byDir[dir], WatchTarget{Path: abs, Name: t.Name, Fn: t.Fn})
	}
	if len(byDir) == 0 {
		_ = watcher.Close()
		return nil
	}
	for dir := range byDir {
		if err := watcher.Add(dir); err != nil {
			logger.Warn("config file watcher: failed to watch directory", "dir", dir, "error", err)
		}
	}

	go func() {
		defer func() { _ = watcher.Close() }()
		pending := make(map[string]bool) // directories with a debounced change pending
		var timer *time.Timer
		var timerC <-chan time.Time
		for {
			select {
			case <-stop:
				if timer != nil {
					timer.Stop()
				}
				return
			case event, ok := <-watcher.Events:
				if !ok {
					return
				}
				// Write and Create both mean "something changed" here --
				// Create covers the rename-over-original save pattern
				// (the new file lands via a Create event on the watched
				// directory, not a Write on the now-gone old inode).
				// Remove/Rename-of-the-old-name alone are ignored: the
				// mid-save window where the old file briefly doesn't
				// exist yet isn't a real change to react to on its own.
				if event.Op&(fsnotify.Write|fsnotify.Create) == 0 {
					continue
				}
				abs, err := filepath.Abs(event.Name)
				if err != nil {
					continue
				}
				dir := filepath.Dir(abs)
				matched := false
				for _, t := range byDir[dir] {
					if t.Path == abs {
						matched = true
						break
					}
				}
				if !matched {
					continue
				}
				pending[dir] = true
				if timer == nil {
					timer = time.NewTimer(debounceWindow)
				} else {
					if !timer.Stop() {
						select {
						case <-timer.C:
						default:
						}
					}
					timer.Reset(debounceWindow)
				}
				timerC = timer.C
			case <-timerC:
				for dir := range pending {
					for _, t := range byDir[dir] {
						if err := t.Fn(); err != nil {
							logger.Warn("config file watcher: auto-reload failed", "domain", t.Name, "path", t.Path, "error", err)
						} else {
							logger.Info("config file watcher: auto-reload applied", "domain", t.Name, "path", t.Path)
						}
					}
				}
				pending = make(map[string]bool)
				timerC = nil
			case err, ok := <-watcher.Errors:
				if !ok {
					return
				}
				logger.Warn("config file watcher: fsnotify error", "error", err)
			}
		}
	}()
	return nil
}
