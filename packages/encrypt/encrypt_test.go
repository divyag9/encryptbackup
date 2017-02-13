package encrypt

import "testing"

var directoryPaths = []struct {
	source string
	target string
}{
	{
		"/cmd/server/",
		"/cmd/client",
	},
}

func TestCheckSourceAndTargetDirectories(t *testing.T) {
	for _, path := range directoryPaths {
		err := checkSourceAndTargetDirectories(path.source, path.target)
		if err == nil {
			t.Errorf("Expected: Invalid paths")
		}
	}
}
