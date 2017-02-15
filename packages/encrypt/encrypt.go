package encrypt

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"

	"io/ioutil"

	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
)

// Data encrypts the data passed
func Data(sourceDirectory, targetDirectory, sgpKey, midKey string) error {

	err := checkSourceAndTargetDirectories(sourceDirectory, targetDirectory)
	if err != nil {
		return err
	}

	entityList, err := createEntityList(midKey, sgpKey)
	if err != nil {
		return fmt.Errorf("Error creating entity list: %s", err.Error())
	}

	fileList, err := getAllNonPgpFilePathsFromSource(sourceDirectory)
	if err != nil {
		return fmt.Errorf("Error parsing the sourceDirectory to get all non pgp files: %s", err.Error())
	}

	err = encryptDataAndWrite(fileList, entityList, targetDirectory)
	if err != nil {
		return fmt.Errorf("Error encryting and writing: %s", err.Error())
	}

	return nil
}

// Check if source and target directory exists. Create if target does not exist
func checkSourceAndTargetDirectories(sourceDirectory, targetDirectory string) error {
	if _, err := os.Stat(sourceDirectory); os.IsNotExist(err) {
		return fmt.Errorf("Source directory does not exist: %s", err.Error())
	}

	stat, err := os.Stat(targetDirectory)
	if os.IsNotExist(err) {
		err := os.MkdirAll(targetDirectory, 0777)
		if err != nil {
			return fmt.Errorf("Unable to create target directory: %s", err.Error())
		}
	} else {
		if !stat.IsDir() {
			return errors.New("The target directory passed is not a directory")
		}
	}

	return nil
}

func createEntityList(midKey, sgpKey string) (openpgp.EntityList, error) {
	//Read the midland key
	entitylistMid, err := getEntityListForKey(midKey)
	if err != nil {
		return nil, err
	}
	//Read the safeguard key
	entitylistSgp, err := getEntityListForKey(sgpKey)
	if err != nil {
		return nil, err
	}
	entitylist := append(entitylistMid, entitylistSgp...)

	return entitylist, nil
}

func getEntityListForKey(key string) (openpgp.EntityList, error) {
	buf, err := ioutil.ReadFile(key)
	if err != nil {
		return nil, fmt.Errorf("Error reading key file: %s. Error: %s", key, err.Error())
	}
	entitylist, err := openpgp.ReadArmoredKeyRing(bytes.NewBuffer(buf))
	if err != nil {
		return nil, fmt.Errorf("Error creating entity list for key: %s. Error: %s", key, err.Error())
	}
	return entitylist, nil
}

// Get all non pgp files in directory
func getAllNonPgpFilePathsFromSource(sourceDirectory string) ([]string, error) {
	fileList := []string{}
	err := filepath.Walk(sourceDirectory, func(path string, info os.FileInfo, err error) error {
		if !info.IsDir() && !strings.Contains(path, ".pgp") {
			fileList = append(fileList, path)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("error parsing directory: %s", err.Error())
	}
	return fileList, nil
}

func encryptDataAndWrite(fileList []string, entityList openpgp.EntityList, targetDirectory string) error {

	//Encrypt data and write
	for _, sourceFile := range fileList {
		finalTargetDirectory, targetFileName := getTargetDirectoryWithSourceAndFileName(sourceFile, targetDirectory)
		if _, err := os.Stat(targetFileName); os.IsNotExist(err) {
			// Encrypt message using public keys
			pgpBuf := bytes.NewBuffer(nil)
			arm, err := armor.Encode(pgpBuf, "PGP MESSAGE", nil)
			if err != nil {
				return err
			}
			pgpWriter, err := openpgp.Encrypt(arm, entityList, nil, nil, nil)
			if err != nil {
				return err
			}

			// Reading file contents
			err = readSourceFileAndEncrypt(sourceFile, &pgpWriter)
			pgpWriter.Close()
			arm.Close()
			if err != nil {
				continue
			}

			// Write the encrypted data to file
			err = writeEncryptedData(sourceFile, targetFileName, finalTargetDirectory, pgpBuf)
			if err != nil {
				continue
			}
			log.Println("Encrypted file: ", sourceFile, " at: ", targetFileName)
		}
	}

	return nil
}

func readSourceFileAndEncrypt(sourceFile string, pgpWriter *io.WriteCloser) error {
	fs, err := os.Open(sourceFile)
	if err != nil {
		return fmt.Errorf("Error opening file: %s. Error: %s. Continuing with other files", sourceFile, err)
	}
	bufferedReader := bufio.NewReader(fs)
	buf := make([]byte, 1024)
	for {
		n, err := bufferedReader.Read(buf[0:])
		if err != nil {
			if err == io.EOF {
				break
			}
			fs.Close()
			return fmt.Errorf("Error reading file: %s. Error: %s. Continuing with other files", sourceFile, err)
		}
		// Encrypting the file contents
		_, err = (*pgpWriter).Write(buf[0:n])
		if err != nil {
			fs.Close()
			return fmt.Errorf("Error writing pgpbytes for file: %s. Error: %s. Continuing with other files", sourceFile, err)
		}
	}
	fs.Close()

	return nil
}

func getTargetDirectoryWithSourceAndFileName(sourceFile, targetDirectory string) (string, string) {
	sourceDirectoryPath, fullFileName := filepath.Split(sourceFile)
	exttension := filepath.Ext(sourceFile)
	fileName := strings.TrimSuffix(fullFileName, exttension)
	outFileName := fileName + ".pgp"
	// In case of windows path removing the driver info
	if strings.Contains(sourceDirectoryPath, ":") {
		sourceDirectoryPath = strings.Split(sourceDirectoryPath, ":")[1]
	}
	finalTargetDirectory := filepath.Join(targetDirectory, sourceDirectoryPath)
	targetFileName := filepath.Join(finalTargetDirectory, outFileName)
	return finalTargetDirectory, targetFileName
}

func writeEncryptedData(sourceFile string, targetFile string, finalTargetDirectory string, pgpBuf *bytes.Buffer) error {
	// Create the target directory with the source base if not present
	if _, err := os.Stat(finalTargetDirectory); os.IsNotExist(err) {
		err := os.MkdirAll(finalTargetDirectory, 0777)
		if err != nil {
			return fmt.Errorf("Unable to create target directory with source base: %s. Error: %s. Continuing with other files", finalTargetDirectory, err)
		}
	}
	fo, err := os.Create(targetFile)
	if err != nil {
		return fmt.Errorf("Error creating output file: %s. Error: %s. Continuing with other files", targetFile, err)
	}
	bufferedWriter := bufio.NewWriter(fo)
	fmt.Fprintln(bufferedWriter, pgpBuf.String())
	bufferedWriter.Flush()
	fo.Close()

	return nil
}
