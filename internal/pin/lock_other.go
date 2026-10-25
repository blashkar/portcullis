//go:build !unix

package pin

// lockFile is a no-op where flock isn't available; the Store's mutex still
// serializes updates within one process.
func lockFile(string) (func(), error) {
	return func() {}, nil
}
