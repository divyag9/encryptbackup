package encrypt

import (
	"bytes"
	"testing"

	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
)

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

var sourceDirectories = []struct {
	directory string
}{
	{
		"source",
	},
}

var finalTragetPaths = []struct {
	sourceFile     string
	target         string
	targetFileName string
}{
	{
		"cmd\\server\\test1.txt",
		"target",
		"target\\cmd\\server\\test1.txt",
	},
}

var writePaths = []struct {
	sourceFile           string
	targetFile           string
	finalTargetDirectory string
	pgpBuf               *bytes.Buffer
}{
	{
		"cmd\\server",
		"target",
		"",
		bytes.NewBuffer(nil),
	},
}

var encryptPaths = []struct {
	fileList        []string
	targetDirectory string
}{
	{
		[]string{"cmd\\server\\test.txt",
			"cmd\\server\\test1.txt",
		},
		"target",
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

func TestGetEntityListForKey(t *testing.T) {
	for _, pgpKeys := range pgpKeys {
		_, err := getEntityListForKey(pgpKeys.mid)
		if err != nil {
			t.Errorf("Expected: no error getting entitylist")
		}
	}
}

func TestGetAllNonPgpFilePathsFromSource(t *testing.T) {
	for _, sourceDirectories := range sourceDirectories {
		_, err := getAllNonPgpFilePathsFromSource(sourceDirectories.directory)
		if err != nil {
			t.Errorf("Expected: no error getting list of files")
		}
	}
}

func TestGetTargetDirectoryWithSourceAndFileName(t *testing.T) {
	for _, path := range finalTragetPaths {
		_, targetFileName := getTargetDirectoryWithSourceAndFileName(path.sourceFile, path.target)
		if targetFileName != path.targetFileName {
			t.Errorf("Returned: %v, Expected: %v", targetFileName, path.targetFileName)
		}
	}
}

func TestWriteEncryptedData(t *testing.T) {
	for _, writePaths := range writePaths {
		err := writeEncryptedData(writePaths.sourceFile, writePaths.targetFile, writePaths.finalTargetDirectory, writePaths.pgpBuf)
		if err != nil {
			t.Errorf("Expected: no error writing encrypted data")
		}
	}
}

func TestEncryptDataAndWrite(t *testing.T) {
	entityList, _ := createEntityList("D://Users//dmuppaneni//Documents//midland.key", "D://Users//dmuppaneni//Documents//moran.key")
	for _, encryptPaths := range encryptPaths {
		err := encryptDataAndWrite(encryptPaths.fileList, entityList, encryptPaths.targetDirectory)
		if err != nil {
			t.Errorf("Expected: no error encrypting and writing data")
		}
	}
}

func TestReadSourceFileAndEncrypt(t *testing.T) {
	entityList, _ := createEntityList("D://Users//dmuppaneni//Documents//midland.key", "D://Users//dmuppaneni//Documents//moran.key")
	pgpBuf := bytes.NewBuffer(nil)
	arm, _ := armor.Encode(pgpBuf, "PGP MESSAGE", nil)
	fileHints := &openpgp.FileHints{}
	fileHints.IsBinary = true
	pgpWriter, _ := openpgp.Encrypt(arm, entityList, nil, fileHints, nil)
	for _, finalTragetPaths := range finalTragetPaths {
		err := readSourceFileAndEncrypt(finalTragetPaths.sourceFile, &pgpWriter)
		if err != nil {
			t.Errorf("Expected: no error encrypting and writing data")
		}
	}
}
