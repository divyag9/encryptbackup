package encrypt

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"log"

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
		log.Println("error creating entity list")
		return err
	}

	fileList, err := getAllNonPgpFilePathsFromSource(sourceDirectory)
	if err != nil {
		log.Println("error parsing the sourceDirectory to get files list")
		return err
	}

	err = encryptDataAndWrite(fileList, entityList, targetDirectory)
	if err != nil {
		log.Println("error encryting and writing")
		return err
	}

	return nil
}

// Check if source and target directory exists. Create if target does not exist
func checkSourceAndTargetDirectories(sourceDirectory, targetDirectory string) error {
	if _, err := os.Stat(sourceDirectory); os.IsNotExist(err) {
		log.Println("Source directory does not exist")
		return err
	}

	stat, err := os.Stat(targetDirectory)
	if os.IsNotExist(err) {
		err := os.MkdirAll(targetDirectory, 0777)
		if err != nil {
			log.Println("Unable to create target directory")
			return err
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
	midBuf, err := ioutil.ReadFile(midKey)
	if err != nil {
		log.Println("error reading midland key file: ", midKey)
		return nil, err
	}
	entitylistMid, err := openpgp.ReadArmoredKeyRing(bytes.NewBuffer(midBuf))
	if err != nil {
		log.Println("error reading the midland key")
		return nil, err
	}

	//Read the safeguard key
	sgpBuf, err := ioutil.ReadFile(sgpKey)
	if err != nil {
		log.Println("error reading safeguard key file: ", sgpKey)
		return nil, err
	}
	entitylistSgp, err := openpgp.ReadArmoredKeyRing(bytes.NewBuffer(sgpBuf))
	if err != nil {
		log.Println("error reading the safeguard key")
		return nil, err
	}
	entitylist := append(entitylistMid, entitylistSgp...)

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
		log.Println("error parsing directory")
		return nil, err
	}
	return fileList, nil
}

func encryptDataAndWrite(fileList []string, entityList openpgp.EntityList, targetDirectory string) error {

	//Encrypt data and write
	for _, sourceFile := range fileList {
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
		finalTargetDirectory, targetFileName := getTargetDirectoryWithSourceAndFileName(sourceFile, targetDirectory)
		err = writeEncryptedData(sourceFile, targetFileName, finalTargetDirectory, pgpBuf)
		if err != nil {
			continue
		}
	}
	log.Println("Encrypted all the data")

	return nil
}

func readSourceFileAndEncrypt(sourceFile string, pgpWriter *io.WriteCloser) error {
	fs, err := os.Open(sourceFile)
	if err != nil {
		log.Println("error opening: ", sourceFile, ". Error: ", err, "continuing with other files")
		return err
	}
	bufferedReader := bufio.NewReader(fs)
	buf := make([]byte, 1024)
	for {
		n, err := bufferedReader.Read(buf[0:])
		if err != nil {
			if err == io.EOF {
				break
			}
			log.Println("error reading file: ", sourceFile, ". Error: ", err, "continuing with other files")
			fs.Close()
			return err
		}
		// Encrypting the file contents
		_, err = (*pgpWriter).Write(buf[0:n])
		if err != nil {
			log.Println("error writing pgpbytes for file: ", sourceFile, ". Error: ", err, "continuing with other files")
			fs.Close()
			return err
		}
	}
	fs.Close()

	return nil
}

func getTargetDirectoryWithSourceAndFileName(file, targetDirectory string) (string, string) {
	sourceDirectoryPath, fullFileName := filepath.Split(file)
	exttension := filepath.Ext(file)
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
	if _, err := os.Stat(targetFile); os.IsNotExist(err) {
		// Create the target directory with the source base if not present
		if _, err := os.Stat(finalTargetDirectory); os.IsNotExist(err) {
			err := os.MkdirAll(finalTargetDirectory, 0777)
			if err != nil {
				log.Println("Unable to create target directory with source base: ", finalTargetDirectory, ". Error: ", err, "continuing with other files")
				return err
			}
		}
		fo, err := os.Create(targetFile)
		if err != nil {
			log.Println("error creating output file: ", targetFile, ". Error: ", err, "continuing with other files")
			return err
		}
		bufferedWriter := bufio.NewWriter(fo)
		fmt.Fprintln(bufferedWriter, pgpBuf.String())
		bufferedWriter.Flush()
		fo.Close()
	} else {
		log.Println("File was already encrypted: ", sourceFile, " at: ", targetFile)
	}

	return nil
}
