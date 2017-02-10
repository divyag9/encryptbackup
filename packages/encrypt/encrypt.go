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
)

// Data encrypts the data passed
func Data(sourceDirectory, targetDirectory, sgpKey, midKey string) error {

	//Read the midland key
	midBuf, err := ioutil.ReadFile(midKey)
	if err != nil {
		log.Println("error reading midland key file: ", midKey)
		return err
	}
	entitylistMid, err := openpgp.ReadArmoredKeyRing(bytes.NewBuffer(midBuf))
	if err != nil {
		log.Println("error reading the midland key")
		return err
	}

	//Read the safeguard key
	sgpBuf, err := ioutil.ReadFile(sgpKey)
	if err != nil {
		log.Println("error reading safeguard key file: ", sgpKey)
		return err
	}
	entitylistSgp, err := openpgp.ReadArmoredKeyRing(bytes.NewBuffer(sgpBuf))
	if err != nil {
		log.Println("error reading the safeguard key")
		return err
	}
	entitylist := append(entitylistMid, entitylistSgp...)

	// Encrypt message using public keys
	pgpBuf := new(bytes.Buffer)
	w, err := openpgp.Encrypt(pgpBuf, entitylist, nil, nil, nil)
	if err != nil {
		return err
	}

	// Get all files in directory
	fileList := []string{}
	err = filepath.Walk(sourceDirectory, func(path string, info os.FileInfo, err error) error {
		if !info.IsDir() && !strings.Contains(path, ".pgp") {
			fileList = append(fileList, path)
		}
		return nil
	})
	if err != nil {
		log.Println("error parsing directory")
		return err
	}

	//Read files and ecrypt all the non pgp files
OUTER:
	for _, file := range fileList {

		// Reading file contents
		fs, err := os.Open(file)

		if err != nil {
			log.Println("error opening: ", file, ". Error: ", err, "continuing with other files")
			continue OUTER
		}

		defer fs.Close()
		var result []byte
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
			result = append(result, buf[0:n]...)
		}
		//filenam := filepath.Join(targetDirectory, "testencrypt")
		//err = ioutil.WriteFile(filenam, result, 0644)
		// Encrypting the file contents
		_, err = w.Write(result)
		if err != nil {
			log.Println("error writing pgpbytes for file: ", file, ". Error: ", err, "continuing with other files")
			continue OUTER
		}
		err = w.Close()
		if err != nil {
			log.Println("error closing pgp buffer for file: ", file, ". Error: ", err, "continuing with other files")
			continue OUTER
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
		defer fo.Close()
		bufferedWriter := bufio.NewWriter(fo)
		//bytes, err := ioutil.ReadAll(pgpBuf)
		//str := base64.StdEncoding.EncodeToString(bytes)
		fmt.Fprintln(bufferedWriter, pgpBuf)
		bufferedWriter.Flush()
	}
	log.Println("Encrypted all the data")
	return nil
}
