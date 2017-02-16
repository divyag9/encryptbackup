package encrypt

import "testing"

var directoryPaths = []struct {
	source string
	target string
}{
	{
		"cmd\\server",
		"target",
	},
	{
		"source",
		"test.txt",
	},
}

var pgpKeys = []struct {
	sgp string
	mid string
}{
	{
		"D://Users//dmuppaneni//Documents//moran.key",
		"D://Users//dmuppaneni//Documents//midland.key",
	},
}

func TestCheckSourceAndTargetDirectories(t *testing.T) {
	for _, path := range directoryPaths {
		err := checkSourceAndTargetDirectories(path.source, path.target)
		if err == nil {
			t.Errorf("Expected: invalid source or target directory")
		}
	}
}

func TestCreateEntityList(t *testing.T) {
	for _, pgpKeys := range pgpKeys {
		_, err := createEntityList(pgpKeys.mid, pgpKeys.sgp)
		if err != nil {
			t.Errorf("Expected: no error creating the entitylist")
		}
	}
}
