package encrypt

import (
	"bufio"
	"bytes"
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

	// Check if target directory exists if not create
	if _, err := os.Stat(targetDirectory); os.IsNotExist(err) {
		err := os.MkdirAll(targetDirectory, 0755)
		if err != nil {
			log.Println("Unable to create target directory")
			return err
		}
	}

	entityList, err := createEntityList(midKey, sgpKey)
	if err != nil {
		log.Println("error creating entity list")
		return err
	}

	fileList, err := getFiles(sourceDirectory)
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
func getFiles(sourceDirectory string) ([]string, error) {
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
OUTER:
	for _, file := range fileList {
		// Encrypt message using public keys
		pgpBuf := bytes.NewBuffer(nil)
		arm, err := armor.Encode(pgpBuf, "PGP MESSAGE", nil)
		if err != nil {
			return err
		}
		w, err := openpgp.Encrypt(arm, entityList, nil, nil, nil)
		if err != nil {
			return err
		}

		// Reading file contents
		fs, err := os.Open(file)
		if err != nil {
			log.Println("error opening: ", file, ". Error: ", err, "continuing with other files")
			continue OUTER
		}

		bufferedReader := bufio.NewReader(fs)
		buf := make([]byte, 1024)
		for {
			n, err := bufferedReader.Read(buf[0:])
			if err != nil {
				if err == io.EOF {
					break
				}
				log.Println("error reading file: ", file, ". Error: ", err, "continuing with other files")
				continue OUTER
			}
			// Encrypting the file contents
			_, err = w.Write(buf[0:n])
			if err != nil {
				log.Println("error writing pgpbytes for file: ", file, ". Error: ", err, "continuing with other files")
				continue OUTER
			}
		}
		fs.Close()
		if err != nil {
			log.Println("error closing read filehandle. Error: ", err)
			return err
		}
		err = w.Close()
		if err != nil {
			log.Println("error closing pgp buffer for file: ", file, ". Error: ", err)
			return err
		}
		arm.Close()
		if err != nil {
			log.Println("error closing armor. Error: ", err)
			return err
		}

		// Write the encrypted data to file
		_, fullFileName := filepath.Split(file)
		exttension := filepath.Ext(file)
		fileName := strings.TrimSuffix(fullFileName, exttension)
		outFileName := fileName + ".pgp"
		outFile := filepath.Join(targetDirectory, outFileName)
		fo, err := os.Create(outFile)
		if err != nil {
			log.Println("error creating output file: ", outFile, ". Error: ", err, "continuing with other files")
			continue OUTER
		}

		bufferedWriter := bufio.NewWriter(fo)
		fmt.Fprintln(bufferedWriter, pgpBuf.String())
		bufferedWriter.Flush()
		fo.Close()
	}
	log.Println("Encrypted all the data")

	return nil
}
