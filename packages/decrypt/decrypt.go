package decrypt

import (
	"bytes"
	"io/ioutil"
	"log"
	"path/filepath"

	"golang.org/x/crypto/openpgp"
)

// Data decrypts the contents of file passed
func Data(privateKey, fileName, targetDirectory string) error {
	log.Println("private jey: ", privateKey)
	privBuf, err := ioutil.ReadFile(privateKey)
	if err != nil {
		log.Println("error reading private key: ", privateKey)
		return err
	}
	log.Println("privBuf :", privBuf)
	entitylist, err := openpgp.ReadArmoredKeyRing(bytes.NewBuffer(privBuf))
	if err != nil {
		return err
	}
	result, err := ioutil.ReadFile(fileName)

	md, err := openpgp.ReadMessage(bytes.NewBuffer(result), entitylist, nil, nil)
	if err != nil {
		log.Println("error reading message", err)
		return err
	}

	bytes, err := ioutil.ReadAll(md.UnverifiedBody)
	if err != nil {
		log.Println("error decrypting message", err)
		return err
	}
	filenam := filepath.Join(targetDirectory, "testdecrypt")
	err = ioutil.WriteFile(filenam, bytes, 0644)
	if err != nil {
		log.Println("error writing decrypted file", err)
		return err
	}

	log.Println("decrypted contents")

	return nil
}
