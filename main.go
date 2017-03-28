package main

import (
	"flag"
	"fmt"

	"github.com/divyag9/encryptbackup/packages/encrypt"
)

func main() {
	// Parsing the command line arguments
	sourceDirectory := flag.String("sd", "", "Source directory of files to encrypt")
	targetDirectory := flag.String("td", "", "Target directory of encrypted files")
	sgpKey := flag.String("sgpkey", "", "Safeguard pgp key")
	midKey := flag.String("midkey", "", "Midland pgp key")

	flag.Parse()

	if *sourceDirectory == "" || *targetDirectory == "" || *sgpKey == "" || *midKey == "" {
		panic("please pass the required flags: -sd(source directory) -td(target directory) -sgpkey(safeguard key) -midkey(midland key)")
	}

	err := encrypt.Data(*sourceDirectory, *targetDirectory, *sgpKey, *midKey)
	if err != nil {
		fmt.Println("Error occured while encrypting: ", err)
	} else {
		fmt.Println("Done encrypting")
	}
}
