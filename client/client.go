package client

import (
	"encoding/hex"
	"encoding/json"

	userlib "github.com/cs161-staff/project2-userlib"
	"github.com/google/uuid"

	// hex.EncodeToString(...) is useful for converting []byte to string

	// Useful for string manipulation
	"strings"

	// Useful for formatting strings (e.g. `fmt.Sprintf`).
	"fmt"

	// Useful for creating new error messages to return using errors.New("...")
	"errors"

	// Optional.
	_ "strconv"
)

// This serves two purposes: it shows you a few useful primitives,
// and suppresses warnings for imports not being used. It can be
// safely deleted!
func someUsefulThings() {

	// Creates a random UUID.
	randomUUID := uuid.New()

	// Prints the UUID as a string. %v prints the value in a default format.
	// See https://pkg.go.dev/fmt#hdr-Printing for all Golang format string flags.
	userlib.DebugMsg("Random UUID: %v", randomUUID.String())

	// Creates a UUID deterministically, from a sequence of bytes.
	hash := userlib.Hash([]byte("user-structs/alice"))
	deterministicUUID, err := uuid.FromBytes(hash[:16])
	if err != nil {
		// Normally, we would `return err` here. But, since this function doesn't return anything,
		// we can just panic to terminate execution. ALWAYS, ALWAYS, ALWAYS check for errors! Your
		// code should have hundreds of "if err != nil { return err }" statements by the end of this
		// project. You probably want to avoid using panic statements in your own code.
		panic(errors.New("An error occurred while generating a UUID: " + err.Error()))
	}
	userlib.DebugMsg("Deterministic UUID: %v", deterministicUUID.String())

	// Declares a Course struct type, creates an instance of it, and marshals it into JSON.
	type Course struct {
		name      string
		professor []byte
	}

	course := Course{"CS 161", []byte("Nicholas Weaver")}
	courseBytes, err := json.Marshal(course)
	if err != nil {
		panic(err)
	}

	userlib.DebugMsg("Struct: %v", course)
	userlib.DebugMsg("JSON Data: %v", courseBytes)

	// Generate a random private/public keypair.
	// The "_" indicates that we don't check for the error case here.
	var pk userlib.PKEEncKey
	var sk userlib.PKEDecKey
	pk, sk, _ = userlib.PKEKeyGen()
	userlib.DebugMsg("PKE Key Pair: (%v, %v)", pk, sk)

	// Here's an example of how to use HBKDF to generate a new key from an input key.
	// Tip: generate a new key everywhere you possibly can! It's easier to generate new keys on the fly
	// instead of trying to think about all of the ways a key reuse attack could be performed. It's also easier to
	// store one key and derive multiple keys from that one key, rather than
	originalKey := userlib.RandomBytes(16)
	derivedKey, err := userlib.HashKDF(originalKey, []byte("mac-key"))
	if err != nil {
		panic(err)
	}
	userlib.DebugMsg("Original Key: %v", originalKey)
	userlib.DebugMsg("Derived Key: %v", derivedKey)

	// A couple of tips on converting between string and []byte:
	// To convert from string to []byte, use []byte("some-string-here")
	// To convert from []byte to string for debugging, use fmt.Sprintf("hello world: %s", some_byte_arr).
	// To convert from []byte to string for use in a hashmap, use hex.EncodeToString(some_byte_arr).
	// When frequently converting between []byte and string, just marshal and unmarshal the data.
	//
	// Read more: https://go.dev/blog/strings

	// Here's an example of string interpolation!
	_ = fmt.Sprintf("%s_%d", "file", 1)
}

/* Global Constants */
var blockSize int = 256

// This is the type definition for the User struct.
// A Go struct is like a Python or Java class - it can have attributes
// (e.g. like the Username attribute) and methods (e.g. like the StoreFile method below).
type User struct {
	Username string

	// You can add other attributes here if you want! But note that in order for attributes to
	// be included when this struct is serialized to/from JSON, they must be capitalized.
	// On the flipside, if you have an attribute that you want to be able to access from
	// this struct's methods, but you DON'T want that value to be included in the serialized value
	// of this struct that's stored in datastore, then you can use a "private" variable (e.g. one that
	// begins with a lowercase letter).

	RSAPrivateKey       userlib.PrivateKeyType
	SignKey             userlib.PrivateKeyType
	UserFileMappingInfo FileMappingInfo
}

type FileMappingInfo struct {
	FileMappingEncKey  []byte
	FileMappingHMACKey []byte
}

type FileMapping struct {
	Filename              string
	AccessTreeEncKeyUUID  userlib.UUID
	AccessTreeHMACKeyUUID userlib.UUID
}

type AccessTreeHeader struct {
	// First block information
	FirstBlockUUID userlib.UUID
	FirstEncKey    []byte
	FirstHMACKey   []byte

	// Last block information
	LastBlockRemainingBytes int
	LastBlockUUID           userlib.UUID
	LastEncKey              []byte
	LastHMACKey             []byte

	// File general information
	SharedSignKey userlib.PrivateKeyType
	RootUUID      userlib.UUID
}

type AccessTreeNode struct {
	Username              string
	Filename              string
	AccessTreeEncKeyUUID  userlib.UUID
	AccessTreeHMACKeyUUID userlib.UUID
	Branches              map[string]userlib.UUID
}

type Invitation struct {
	SharerUsername        string
	AccessTreeEncKeyUUID  userlib.UUID
	AccessTreeHMACKeyUUID userlib.UUID
	KeyStoreKeyBytes      []byte
}

type File struct {
	BlockNo          int
	Content          []byte
	NextBlockUUID    userlib.UUID
	NextBlockEncKey  []byte
	NextBlockHMACKey []byte
}

/* Datastore JSON structs - dummy - */

type UserJSON struct {
	Salt                []byte
	EncryptedUserStruct []byte
	UserStructHMAC      []byte
}

type HMACedJSON struct {
	EncryptedJSON []byte
	JSONHMAC      []byte
}

type SignedJSON struct {
	EncryptedJSON []byte
	JSONSign      []byte
}

type InvitationJSON struct {
	EncryptedInvitation     HMACedJSON
	InvitationStructEncKey  SignedJSON
	InvitationStructHMACKey SignedJSON
}


func InitUser(username string, password string) (userdataptr *User, err error) {
	var userdata User
	userdata.Username = username

	// Check if the username is empty
	if len(username) == 0 {
		return nil, errors.New("empty username")
	}

	// Check if the user already exists
	keyStoreRSAKey := username + "PKEEncKey"
	keyStoreDSKey := username + "DSVerifyKey"
	_, ok := userlib.KeystoreGet(keyStoreRSAKey)
	if ok {
		return nil, errors.New("user already exists")
	}

	// Generate a new RSA keypair for the user - store the public at KeyStore
	RSAPublicKey, RSAPrivateKey, err := userlib.PKEKeyGen()
	if err != nil {
		return nil, errors.New("error generating RSA keypair")
	}
	err = userlib.KeystoreSet(keyStoreRSAKey, RSAPublicKey)
	if err != nil {
		return nil, errors.New("error storing RSA public key")
	}
	userdata.RSAPrivateKey = RSAPrivateKey

	// Generate a new DSA keypair for the user - store the public at KeyStore
	DSPrivateKey, DSPublicKey, err := userlib.DSKeyGen()
	if err != nil {
		return nil, errors.New("error generating DSA keypair")
	}
	err = userlib.KeystoreSet(keyStoreDSKey, DSPublicKey)
	if err != nil {
		return nil, errors.New("error storing DSA public key")
	}
	userdata.SignKey = DSPrivateKey

	// Generate a new file mapping info thing
	fileMappingEncKey := userlib.RandomBytes(16)
	fileMappingHMACKey := userlib.RandomBytes(16)
	userdata.UserFileMappingInfo = FileMappingInfo{
		FileMappingEncKey:  fileMappingEncKey,
		FileMappingHMACKey: fileMappingHMACKey,
	}

	err = storeUser(username, password, &userdata)
	if err != nil {
		return nil, err
	}

	return &userdata, nil
}

func GetUser(username string, password string) (userdataptr *User, err error) {
	// var userdata User
	// userdataptr = &userdata

	// Check if the user already exists
	keyStoreRSAKey := username + "PKEEncKey"
	_, ok := userlib.KeystoreGet(keyStoreRSAKey)
	if !ok {
		return nil, errors.New("username doesn't exist")
	}

	userdataptr, err = retrieveUser(username, password)
	if err != nil {
		return nil, err
	}

	return userdataptr, nil
}

func (userdata *User) StoreFile(filename string, content []byte) (err error) {
	// 1. Take the values from userdata
	username := userdata.Username
	FileMappingInfo := userdata.UserFileMappingInfo
	FileMappingEncKey := FileMappingInfo.FileMappingEncKey
	FileMappingHMACKey := FileMappingInfo.FileMappingHMACKey

	// 2. Generate random AccessTreeEncKey and AccessTreeHMACKey
	accessTreeEncKeyUUID := uuid.New()
	accessTreeHMACKeyUUID := uuid.New()
	accessTreeEncKey := userlib.RandomBytes(16)
	accessTreeHMACKey := userlib.RandomBytes(16)
	hashedAccessTreeEncKey := userlib.Hash(accessTreeEncKey)
	accessTreeHeaderUUID, err := uuid.FromBytes(hashedAccessTreeEncKey[:16])
	if err != nil {
		return errors.New("error generating access tree header uuid")
	}

	// Shared DS Verify Key
	DSPrivateKey, DSPublicKey, err := userlib.DSKeyGen()
	if err != nil {
		return errors.New("error generating DSA keypair")
	}
	keyStoreDSKey := hex.EncodeToString(userlib.RandomBytes(16))
	keyStoreDSKeyMarshalJSON, err := json.Marshal(keyStoreDSKey)
	if err != nil {
		return errors.New("error marshalling key store ds key")
	}
	dataStoreDSKey, err := getSharedVerificationKeyUUID(filename, username)
	if err != nil {
		return errors.New("error generating shared ds verify key uuid")
	}
	userlib.DatastoreSet(dataStoreDSKey, keyStoreDSKeyMarshalJSON)
	err = userlib.KeystoreSet(keyStoreDSKey, DSPublicKey)
	if err != nil {
		return errors.New("error storing DSA public key")
	}
	accessTreeHeader := AccessTreeHeader{}
	accessTreeHeader.SharedSignKey = DSPrivateKey

	// 3. Encrpyt AccessTreeEncKey and AccessTreeHMACKey with your RSAPublicKey
	keyStoreRSAKey := username + "PKEEncKey"
	RSAPublicKey, ok := userlib.KeystoreGet(keyStoreRSAKey)
	if !ok {
		return errors.New("error getting RSA public key")
	}
	encryptedAccessTreeEncKey, accessTreeEncKeySign, err := PKEEncAndSign(accessTreeEncKey, RSAPublicKey, accessTreeHeader.SharedSignKey, "access tree enc key")
	if err != nil {
		return err
	}
	encryptedAccessTreeHMACKey, accessTreeHMACKeySign, err := PKEEncAndSign(accessTreeHMACKey, RSAPublicKey, accessTreeHeader.SharedSignKey, "access tree hmac key")
	if err != nil {
		return err
	}

	// 6. Store the keys in the Datastore
	err = storeSignedJSON(accessTreeEncKeyUUID, encryptedAccessTreeEncKey, accessTreeEncKeySign, "accessTreeEncKey")
	if err != nil {
		return err
	}
	err = storeSignedJSON(accessTreeHMACKeyUUID, encryptedAccessTreeHMACKey, accessTreeHMACKeySign, "accessTreeHMACKey")
	if err != nil {
		return err
	}

	// 5. Generate FileMapping object and store it in datastore
	fileMapping := FileMapping{
		Filename:              filename,
		AccessTreeEncKeyUUID:  accessTreeEncKeyUUID,
		AccessTreeHMACKeyUUID: accessTreeHMACKeyUUID,
	}
	fileMappingInfoUUID, err := uuid.FromBytes(userlib.Hash([]byte(filename + username))[:16])
	if err != nil {
		return err
	}
	encryptedFileMapping, fileMappingHMAC, err := symEncAndHMACEval(fileMapping, FileMappingEncKey, FileMappingHMACKey, "file mapping")
	if err != nil {
		return err
	}
	err = storeHMACedJSON(fileMappingInfoUUID, encryptedFileMapping, fileMappingHMAC, "fileMappingInfo")
	if err != nil {
		return err
	}

	// 9. Chunk the File into 1KB sized blocks - Here is the psuedocode
	nextBlockUUID := uuid.New()
	nextBlockEncKey := userlib.RandomBytes(16)
	nextBlockHMACKey := userlib.RandomBytes(16)
	err = chunkFileContent(
		&accessTreeHeader,
		0,
		content,
		nextBlockUUID,
		nextBlockEncKey,
		nextBlockHMACKey,
		true,
	)
	if err != nil {
		return err
	}

	// 11. Generate AccessTree for the owner node and encrpyt struct AccessTree and struct AccessTreeHeader with AccessTreeEncKey and take the HMAC of it with AccessTreeHMACKey
	accessTreeRootUUID := uuid.New()
	accessTreeHeader.RootUUID = accessTreeRootUUID
	accessTreeOwner := AccessTreeNode{
		Username:              username,
		Filename:              filename,
		AccessTreeEncKeyUUID:  accessTreeEncKeyUUID,
		AccessTreeHMACKeyUUID: accessTreeHMACKeyUUID,
		Branches:              make(map[string]userlib.UUID),
	}
	encryptedAccessTreeOwner, encryptedAccessTreeOwnerHMAC, err := symEncAndHMACEval(accessTreeOwner, accessTreeEncKey, accessTreeHMACKey, "access tree owner")
	if err != nil {
		return err
	}
	err = storeHMACedJSON(accessTreeRootUUID, encryptedAccessTreeOwner, encryptedAccessTreeOwnerHMAC, "accessTreeOwner")
	if err != nil {
		return err
	}

	// Store the access tree header
	encryptedAccessTreeHeader, encryptedAccessTreeHeaderHMAC, err := symEncAndHMACEval(accessTreeHeader, accessTreeEncKey, accessTreeHMACKey, "access tree header")
	if err != nil {
		return err
	}
	err = storeHMACedJSON(accessTreeHeaderUUID, encryptedAccessTreeHeader, encryptedAccessTreeHeaderHMAC, "accessTreeHeader")
	if err != nil {
		return err
	}
	return
}

func (userdata *User) AppendToFile(filename string, content []byte) error {
	// 1. Take the struct User
	// 2. Call FileRetrieval helper function (steps 2-5) which gets you all the necessary UUIDs to read your file (LastBlock*).
	_, accessTreeHeader, accessTreeEncKey, accessTreeHMACKey, err := getAccessTreeHeader(userdata, filename)
	if err != nil {
		return err
	}
	lastBlockUUID := accessTreeHeader.LastBlockUUID
	blockEncKey := accessTreeHeader.LastEncKey
	blockHMACKey := accessTreeHeader.LastHMACKey

	// 3. Fill AccessTreeHeader.LastBlockRemainingBytes of bytes to the last block - call the helper function readBlock, writeBlock
	// Get the last block and write the first AccessTreeHeader.LastBlockRemainingBytes bytes to it
	var currentLastBlockData File
	err = retrieveHMACedJSON(&currentLastBlockData, lastBlockUUID, blockEncKey, blockHMACKey, "last block")
	if err != nil {
		return err
	}

	// Delete the last accessTreeHeader.LastBlockRemainingBytes bytes from the currentLastBlockData.Content
	currentLastBlockData.Content = currentLastBlockData.Content[:blockSize-accessTreeHeader.LastBlockRemainingBytes]

	// Append the first AccessTreeHeader.LastBlockRemainingBytes bytes to the block
	// Edge case where the data appended is less than the remaining bytes
	sizeOfContentToCurrentLastBlock := accessTreeHeader.LastBlockRemainingBytes
	if len(content) < sizeOfContentToCurrentLastBlock {
		sizeOfContentToCurrentLastBlock = len(content)
		accessTreeHeader.LastBlockRemainingBytes -= len(content)
	}
	currentLastBlockData.Content = append(currentLastBlockData.Content, content[:sizeOfContentToCurrentLastBlock]...)
	// Fill the remaining bytes of blockContent with 0s
	for j := 0; len(content) < sizeOfContentToCurrentLastBlock && j < accessTreeHeader.LastBlockRemainingBytes; j++ {
		currentLastBlockData.Content = append(currentLastBlockData.Content, 'a')
	}

	// If you have more data chunk the remaining bytes into blocks - similar to StoreFile
	// If not, just store the last block and continue as usual
	if len(content) > sizeOfContentToCurrentLastBlock {
		content = content[sizeOfContentToCurrentLastBlock:]
		nextBlockUUID := uuid.New()
		nextBlockEncKey := userlib.RandomBytes(16)
		nextBlockHMACKey := userlib.RandomBytes(16)
		// Bind the new blocks info to the last block
		currentLastBlockData.NextBlockUUID = nextBlockUUID
		currentLastBlockData.NextBlockEncKey = nextBlockEncKey
		currentLastBlockData.NextBlockHMACKey = nextBlockHMACKey
		err = chunkFileContent(
			accessTreeHeader,
			currentLastBlockData.BlockNo+1,
			content,
			nextBlockUUID,
			nextBlockEncKey,
			nextBlockHMACKey,
			false,
		)
		if err != nil {
			return err
		}
	}

	// Save the changed last block
	encryptedBlock, encryptedBlockHMAC, err := symEncAndHMACEval(currentLastBlockData, blockEncKey, blockHMACKey, "last block")
	if err != nil {
		return err
	}
	err = storeHMACedJSON(lastBlockUUID, encryptedBlock, encryptedBlockHMAC, "last block")
	if err != nil {
		return err
	}

	// Store the updated AccessTreeHeader
	accessTreeHeaderUUID, err := uuid.FromBytes(userlib.Hash(accessTreeEncKey)[:16])
	if err != nil {
		return err
	}
	encryptedAccessTreeHeader, encryptedAccessTreeHeaderHMAC, err := symEncAndHMACEval(accessTreeHeader, accessTreeEncKey, accessTreeHMACKey, "access tree header")
	if err != nil {
		return err
	}
	err = storeHMACedJSON(accessTreeHeaderUUID, encryptedAccessTreeHeader, encryptedAccessTreeHeaderHMAC, "accessTreeHeader")
	if err != nil {
		return err
	}

	return nil
}

func (userdata *User) LoadFile(filename string) (content []byte, err error) {
	_, accessTreeHeader, _, _, err := getAccessTreeHeader(userdata, filename)
	if err != nil {
		return nil, err
	}

	// 5. Use the AccessTreeHeader to get all the necessary information to read your desired file!
	blockUUID := accessTreeHeader.FirstBlockUUID
	blockEncKey := accessTreeHeader.FirstEncKey
	blockHMACKey := accessTreeHeader.FirstHMACKey

	// 6. Iterate over all block (in a linked list structure) until the last block where the next block uuid is set to nil
	// Cumulate all the bytes in the blocks to get the file contents
	currentBlockNo := 0
	var fileContent []byte
	for blockUUID != uuid.Nil {
		// 	For every block, read the content and append it to the file content
		var blockData File
		err = retrieveHMACedJSON(&blockData, blockUUID, blockEncKey, blockHMACKey, "block data")
		if err != nil {
			return nil, err
		}
		if blockData.BlockNo != currentBlockNo {
			return nil, errors.New("error reading file")
		}
		// If this is the last block, we need to only read the first AccessTreeHeader.LastBlockRemainingBytes bytes
		if blockData.NextBlockUUID == uuid.Nil {
			fileContent = append(fileContent, blockData.Content[:(blockSize-accessTreeHeader.LastBlockRemainingBytes)]...)
			break
		}
		fileContent = append(fileContent, blockData.Content...)
		blockUUID = blockData.NextBlockUUID
		blockEncKey = blockData.NextBlockEncKey
		blockHMACKey = blockData.NextBlockHMACKey
		currentBlockNo++
	}

	return fileContent, nil
}

func (userdata *User) CreateInvitation(filename string, recipientUsername string) (
	invitationPtr uuid.UUID, err error) {
	_, accessTreeHeader, accessTreeEncKey, accessTreeHMACKey, err := getAccessTreeHeader(userdata, filename)
	if err != nil {
		return uuid.Nil, err
	}

	// 8. Generate random NewAccessTreeEncKeyUUID and NewAccessTreeHMACKeyUUID for the RecipientUser
	newAccessTreeEncKeyUUID, err := uuid.FromBytes(userlib.RandomBytes(16))
	if err != nil {
		return uuid.Nil, err
	}
	newAccessTreeHMACKeyUUID, err := uuid.FromBytes(userlib.RandomBytes(16))
	if err != nil {
		return uuid.Nil, err
	}

	// 9. Get RSAPublicKey of the RecipientUser from the KeyStore and Encrpyt AccessTreeEncKey and the AccessTreeHMACKey
	// 	with this RSAPublicKey
	keyStoreRSAKey := recipientUsername + "PKEEncKey"
	recipientRSAPublicKey, ok := userlib.KeystoreGet(keyStoreRSAKey)
	if !ok {
		return uuid.Nil, errors.New("error getting RSA public key")
	}
	encryptedAccessTreeEncKey, accessTreeEncKeySign, err := PKEEncAndSign(accessTreeEncKey, recipientRSAPublicKey, accessTreeHeader.SharedSignKey, "access tree enc key")
	if err != nil {
		return uuid.Nil, err
	}
	encryptedAccessTreeHMACKey, accessTreeHMACKeySign, err := PKEEncAndSign(accessTreeHMACKey, recipientRSAPublicKey, accessTreeHeader.SharedSignKey, "access tree hmac key")
	if err != nil {
		return uuid.Nil, err
	}

	// 11. Call DataStoreSet(NewAccessTreeEncKeyUUID, {EncrpytedAccessTreeEncKey, EncrpytedAccessTreeEncKeySharerSignature})
	err = storeSignedJSON(newAccessTreeEncKeyUUID, encryptedAccessTreeEncKey, accessTreeEncKeySign, "create invitation access tree enc key")
	if err != nil {
		return uuid.Nil, err
	}
	// 12. Call DataStoreSet(NewAccessTreeHMACKeyUUID, {EncrpytedAccessTreeHMACKey, EncrpytedAccessTreeHMACKeySharerSignature})
	err = storeSignedJSON(newAccessTreeHMACKeyUUID, encryptedAccessTreeHMACKey, accessTreeHMACKeySign, "create invitation access tree hmac key")
	if err != nil {
		return uuid.Nil, err
	}

	// 13. Generate random InvitationPtr
	invitationPtr = uuid.New()
	dataStoreDSKey, err := getSharedVerificationKeyUUID(filename, userdata.Username)
	if err != nil {
		return uuid.Nil, err
	}
	keyStoreKeyBytes, ok := userlib.DatastoreGet(dataStoreDSKey)
	if !ok {
		return uuid.Nil, errors.New("error getting shared DSA public key")
	}
	invitation := Invitation{
		SharerUsername:        userdata.Username,
		AccessTreeEncKeyUUID:  newAccessTreeEncKeyUUID,
		AccessTreeHMACKeyUUID: newAccessTreeHMACKeyUUID,
		KeyStoreKeyBytes:      keyStoreKeyBytes,
	}

	// 15. Encrpyt struct Invitation with the RSAPublicKey of RecipientUser
	invitationStructEncKey := userlib.RandomBytes(16)
	invitationStructHMACKey := userlib.RandomBytes(16)
	encryptedInvitation, invitationStructHMAC, err := symEncAndHMACEval(invitation, invitationStructEncKey, invitationStructHMACKey, "create invitation")
	if err != nil {
		return uuid.Nil, err
	}
	encryptedInvitationStructEncKey, invitationStructEncKeySign, err := PKEEncAndSign(invitationStructEncKey, recipientRSAPublicKey, userdata.SignKey, "create invitation")
	if err != nil {
		return uuid.Nil, err
	}
	encryptedInvitationStructHMACKey, invitationStructHMACKeySign, err := PKEEncAndSign(invitationStructHMACKey, recipientRSAPublicKey, userdata.SignKey, "create invitation")
	if err != nil {
		return uuid.Nil, err
	}
	invitationJSON := InvitationJSON{
		EncryptedInvitation: HMACedJSON{
			EncryptedJSON: encryptedInvitation,
			JSONHMAC:      invitationStructHMAC,
		},
		InvitationStructEncKey: SignedJSON{
			EncryptedJSON: encryptedInvitationStructEncKey,
			JSONSign:      invitationStructEncKeySign,
		},
		InvitationStructHMACKey: SignedJSON{
			EncryptedJSON: encryptedInvitationStructHMACKey,
			JSONSign:      invitationStructHMACKeySign,
		},
	}
	invitationBytes, err := json.Marshal(invitationJSON)
	if err != nil {
		return uuid.Nil, err
	}
	userlib.DatastoreSet(invitationPtr, invitationBytes)

	// Add the new access tree node to the sharer's access tree
	newAccessTreeNodeUUID := uuid.New()
	newAccessTreeNode := AccessTreeNode{
		Username:              recipientUsername,
		Filename:              "",
		AccessTreeEncKeyUUID:  newAccessTreeEncKeyUUID,
		AccessTreeHMACKeyUUID: newAccessTreeHMACKeyUUID,
		Branches:              make(map[string]userlib.UUID),
	}
	rootNodeUUID := accessTreeHeader.RootUUID
	nodeUUID, err := findAccessTreeNode(userdata.Username, rootNodeUUID, accessTreeEncKey, accessTreeHMACKey)
	if err != nil {
		return uuid.Nil, err
	}
	var foundNode AccessTreeNode
	err = retrieveHMACedJSON(&foundNode, nodeUUID, accessTreeEncKey, accessTreeHMACKey, "found node")
	if err != nil {
		return uuid.Nil, err
	}
	foundNode.Branches[recipientUsername] = newAccessTreeNodeUUID

	// Store the changed node and the newly created node
	encryptedFoundNode, encryptedFoundNodeHMAC, err := symEncAndHMACEval(foundNode, accessTreeEncKey, accessTreeHMACKey, "found node")
	if err != nil {
		return uuid.Nil, err
	}
	err = storeHMACedJSON(nodeUUID, encryptedFoundNode, encryptedFoundNodeHMAC, "found node")
	if err != nil {
		return uuid.Nil, err
	}
	encryptedNewAccessTreeNode, encryptedNewAccessTreeNodeHMAC, err := symEncAndHMACEval(newAccessTreeNode, accessTreeEncKey, accessTreeHMACKey, "new access tree node")
	if err != nil {
		return uuid.Nil, err
	}
	err = storeHMACedJSON(newAccessTreeNodeUUID, encryptedNewAccessTreeNode, encryptedNewAccessTreeNodeHMAC, "new access tree node")
	if err != nil {
		return uuid.Nil, err
	}

	return invitationPtr, nil
}

func (userdata *User) AcceptInvitation(senderUsername string, invitationPtr uuid.UUID, filename string) error {
	// 1. Take the struct User
	// 2. Call DataStoreGet(InvitationPtr)
	invitationBytes, ok := userlib.DatastoreGet(invitationPtr)
	if !ok {
		return errors.New("error getting invitation")
	}
	var invitationJSON InvitationJSON
	err := json.Unmarshal(invitationBytes, &invitationJSON)
	if err != nil {
		return errors.New("error unmarshalling invitation")
	}
	encryptedInvitation := invitationJSON.EncryptedInvitation.EncryptedJSON
	invitationHMAC := invitationJSON.EncryptedInvitation.JSONHMAC
	encryptedInvitationStructEncKey := invitationJSON.InvitationStructEncKey.EncryptedJSON
	invitationStructEncKeySign := invitationJSON.InvitationStructEncKey.JSONSign
	encryptedInvitationStructHMACKey := invitationJSON.InvitationStructHMACKey.EncryptedJSON
	invitationStructHMACKeySign := invitationJSON.InvitationStructHMACKey.JSONSign

	// 3. Get the keys
	keyStoreDSKey := senderUsername + "DSVerifyKey"
	senderDSVerifyKey, ok := userlib.KeystoreGet(keyStoreDSKey)
	if !ok {
		return errors.New("error getting sender DS verify key")
	}

	invitationStructEncKey, err := retrieveSignedJSON(encryptedInvitationStructEncKey, senderDSVerifyKey, invitationStructEncKeySign, userdata.RSAPrivateKey, "invitation struct enc key")
	if err != nil {
		return err
	}
	invitationStructHMACKey, err := retrieveSignedJSON(encryptedInvitationStructHMACKey, senderDSVerifyKey, invitationStructHMACKeySign, userdata.RSAPrivateKey, "invitation struct enc key")
	if err != nil {
		return err
	}

	// 4. HMAC check
	actualHMAC, err := userlib.HMACEval(invitationStructHMACKey, encryptedInvitation)
	if err != nil {
		return errors.New("error evaluating invitation hmac")
	}
	if !userlib.HMACEqual(invitationHMAC, actualHMAC) {
		return errors.New("error verifying invitation hmac")
	}

	// 5. Decrypt struct Invitation using Recipient.RSAPrivateKey - Now you have access to SharerUserame, AccessTreeEncKeyUUID, AccessTreeHMACKeyUUID
	invitation := userlib.SymDec(invitationStructEncKey, encryptedInvitation)
	var invitationStruct Invitation
	err = json.Unmarshal(invitation, &invitationStruct)
	if err != nil {
		return errors.New("error unmarshalling invitation")
	}

	// 6. Store this information at User.FileMappingInfo[FileName] = {SharerUserame, AccessTreeEncKeyUUID, AccessTreeHMACKeyUUID}
	FileMappingInfo := userdata.UserFileMappingInfo
	FileMappingEncKey := FileMappingInfo.FileMappingEncKey
	FileMappingHMACKey := FileMappingInfo.FileMappingHMACKey
	fileMapping := FileMapping{
		Filename:              filename,
		AccessTreeEncKeyUUID:  invitationStruct.AccessTreeEncKeyUUID,
		AccessTreeHMACKeyUUID: invitationStruct.AccessTreeHMACKeyUUID,
	}
	fileMappingUUID, err := uuid.FromBytes(userlib.Hash([]byte(filename + userdata.Username))[:16])
	if err != nil {
		return err
	}
	// Check if the user already has this file in their namespace
	_, ok = userlib.DatastoreGet(fileMappingUUID)
	if ok {
		return errors.New("file already exists")
	}

	encryptedFileMapping, fileMappingHMAC, err := symEncAndHMACEval(fileMapping, FileMappingEncKey, FileMappingHMACKey, "file mapping")
	if err != nil {
		return err
	}
	err = storeHMACedJSON(fileMappingUUID, encryptedFileMapping, fileMappingHMAC, "fileMappingInfo")
	if err != nil {
		return err
	}

	// 8. Create a new struct AccessTree instance {RecipientUsername, AccessTreeEncKeyUUID, AccessTreeHMACKeyUUID, Branches=[]}
	dataStoreDSKey, err := getSharedVerificationKeyUUID(filename, userdata.Username)
	if err != nil {
		return err
	}
	userlib.DatastoreSet(dataStoreDSKey, invitationStruct.KeyStoreKeyBytes)

	// 7. Call FileRetrieval helper function (steps 2-5) which gets you all the necessary UUIDs to read your file.
	_, accessTreeHeader, accessTreeEncKey, accessTreeHMACKey, err := getAccessTreeHeader(userdata, filename)
	if err != nil {
		return err
	}

	// 9. Find SharerUsername at tree and add the new struct AccessTree to the .branches/.children of the SharerAccessTreeNode
	rootNodeUUID := accessTreeHeader.RootUUID
	nodeUUID, err := findAccessTreeNode(userdata.Username, rootNodeUUID, accessTreeEncKey, accessTreeHMACKey)
	if err != nil {
		return err
	}
	var foundNode AccessTreeNode
	err = retrieveHMACedJSON(&foundNode, nodeUUID, accessTreeEncKey, accessTreeHMACKey, "found node")
	if err != nil {
		return err
	}
	foundNode.Filename = filename

	// Store the changed node and the newly created node
	encryptedFoundNode, encryptedFoundNodeHMAC, err := symEncAndHMACEval(foundNode, accessTreeEncKey, accessTreeHMACKey, "found node")
	if err != nil {
		return err
	}
	err = storeHMACedJSON(nodeUUID, encryptedFoundNode, encryptedFoundNodeHMAC, "found node")
	if err != nil {
		return err
	}
	return nil
}

func findAccessTreeNode(username string, nodeUUID userlib.UUID, accessTreeEncKey []byte, accessTreeHMACKey []byte) (userlib.UUID, error) {
	var node AccessTreeNode
	err := retrieveHMACedJSON(&node, nodeUUID, accessTreeEncKey, accessTreeHMACKey, "access tree node")
	if err != nil {
		return uuid.Nil, err
	}
	if node.Username == username {
		return nodeUUID, nil
	}
	for _, childUUID := range node.Branches {
		childNodeUUID, err := findAccessTreeNode(username, childUUID, accessTreeEncKey, accessTreeHMACKey)
		if err != nil {
			return uuid.Nil, err
		}
		if childNodeUUID != uuid.Nil {
			return childNodeUUID, nil
		}
	}
	return uuid.Nil, nil
}

func (userdata *User) RevokeAccess(filename string, recipientUsername string) error {
	accessTreeHeaderUUID, accessTreeHeader, accessTreeEncKey, accessTreeHMACKey, err := getAccessTreeHeader(userdata, filename)
	if err != nil {
		return err
	}
	rootNodeUUID := accessTreeHeader.RootUUID
	nodeUUID, err := findAccessTreeNode(userdata.Username, rootNodeUUID, accessTreeEncKey, accessTreeHMACKey)
	if err != nil {
		return err
	}
	var node AccessTreeNode
	err = retrieveHMACedJSON(&node, nodeUUID, accessTreeEncKey, accessTreeHMACKey, "access tree node")
	if err != nil {
		return err
	}
	if node.Branches[recipientUsername] == uuid.Nil {
		return errors.New("revoking from a non-existant user")
	}
	delete(node.Branches, recipientUsername)
	encryptedNode, encryptedNodeHMAC, err := symEncAndHMACEval(node, accessTreeEncKey, accessTreeHMACKey, "access tree node")
	if err != nil {
		return err
	}
	err = storeHMACedJSON(nodeUUID, encryptedNode, encryptedNodeHMAC, "access tree node")
	if err != nil {
		return err
	}

	content, err := userdata.LoadFile(filename)
	if err != nil {
		return err
	}
	// After loading the file, delete the old blocks since they are now going to be
	// replace by the new chunking loop
	blockUUID := accessTreeHeader.FirstBlockUUID
	blockEncKey := accessTreeHeader.FirstEncKey
	blockHMACKey := accessTreeHeader.FirstHMACKey
	for blockUUID != uuid.Nil {
		// 	For every block, read the content and append it to the file content
		var blockData File
		err = retrieveHMACedJSON(&blockData, blockUUID, blockEncKey, blockHMACKey, "block data")
		if err != nil {
			return err
		}

		// Delete the block
		userlib.DatastoreDelete(blockUUID)

		blockUUID = blockData.NextBlockUUID
		blockEncKey = blockData.NextBlockEncKey
		blockHMACKey = blockData.NextBlockHMACKey
	}

	nextBlockUUID := uuid.New()
	nextBlockEncKey := userlib.RandomBytes(16)
	nextBlockHMACKey := userlib.RandomBytes(16)
	err = chunkFileContent(
		accessTreeHeader,
		0,
		content,
		nextBlockUUID,
		nextBlockEncKey,
		nextBlockHMACKey,
		true,
	)
	if err != nil {
		return err
	}

	// Iterate over all the existing access tree nodes, go to their accesstreekey uuids, and update them
	DSPrivateKey, DSPublicKey, err := userlib.DSKeyGen()
	if err != nil {
		return errors.New("error generating DSA keypair")
	}
	keyStoreDSKey := hex.EncodeToString(userlib.RandomBytes(16))
	keyStoreDSKeyMarshalJSON, err := json.Marshal(keyStoreDSKey)
	if err != nil {
		return errors.New("error marshalling key store ds key")
	}
	err = userlib.KeystoreSet(keyStoreDSKey, DSPublicKey)
	if err != nil {
		return errors.New("error storing DSA public key")
	}
	accessTreeHeader.SharedSignKey = DSPrivateKey
	newAccessTreeHeaderEncKey := userlib.RandomBytes(16)
	newAccessTreeHeaderHMACKey := userlib.RandomBytes(16)
	err = traverseAccessTree(accessTreeHeader.RootUUID, accessTreeHeader.SharedSignKey, keyStoreDSKeyMarshalJSON, accessTreeEncKey, accessTreeHMACKey, newAccessTreeHeaderEncKey, newAccessTreeHeaderHMACKey)
	if err != nil {
		return err
	}

	// Store the accessTreeHeader with the new UUID
	newAccessTreeHeaderUUID, err := uuid.FromBytes(userlib.Hash(newAccessTreeHeaderEncKey)[:16])
	if err != nil {
		return err
	}
	encryptedNewAccessTreeHeader, encryptedNewAccessTreeHeaderHMAC, err := symEncAndHMACEval(accessTreeHeader, newAccessTreeHeaderEncKey, newAccessTreeHeaderHMACKey, "access tree header")
	if err != nil {
		return err
	}
	err = storeHMACedJSON(newAccessTreeHeaderUUID, encryptedNewAccessTreeHeader, encryptedNewAccessTreeHeaderHMAC, "accessTreeHeader")
	if err != nil {
		return err
	}

	// Delete the old accessTreeHeader
	userlib.DatastoreDelete(accessTreeHeaderUUID)
	return nil
}

func traverseAccessTree(
	nodeUUID userlib.UUID,
	sharedSignKey userlib.PrivateKeyType,
	keyStoreDSKeyMarshalJSON []byte,
	accessTreeEncKey []byte,
	accessTreeHMACKey []byte,
	newAccessTreeHeaderEncKey []byte,
	newAccessTreeHeaderHMACKey []byte,
) (err error) {
	var node AccessTreeNode
	err = retrieveHMACedJSON(&node, nodeUUID, accessTreeEncKey, accessTreeHMACKey, "access tree node")
	if err != nil {
		return err
	}

	// Get the accessTreeKeyUUIDs and update them (replace them with the new keys
	// and store them in the datastore (sign it with the shared verification key)))
	username := node.Username
	filename := node.Filename
	accessTreeEncKeyUUID := node.AccessTreeEncKeyUUID
	accessTreeHMACKeyUUID := node.AccessTreeHMACKeyUUID

	// Get the RSA Public Key of the user
	keyStoreRSAKey := username + "PKEEncKey"
	RSAPublicKey, ok := userlib.KeystoreGet(keyStoreRSAKey)
	if !ok {
		return errors.New("error getting RSA public key")
	}

	// Store the shared verify key store string key JSON
	dataStoreDSKey, err := getSharedVerificationKeyUUID(filename, username)
	if err != nil {
		return err
	}
	userlib.DatastoreSet(dataStoreDSKey, keyStoreDSKeyMarshalJSON)

	encryptedNewAccessTreeEncKey, newAccessTreeEncKeySign, err := PKEEncAndSign(newAccessTreeHeaderEncKey, RSAPublicKey, sharedSignKey, "traverse access tree enc key")
	if err != nil {
		return err
	}
	encryptedNewAccessTreeHMACKey, newAccessTreeHMACKeySign, err := PKEEncAndSign(newAccessTreeHeaderHMACKey, RSAPublicKey, sharedSignKey, "traverse access tree hmac key")
	if err != nil {
		return err
	}
	// Store the new access tree keys
	err = storeSignedJSON(accessTreeEncKeyUUID, encryptedNewAccessTreeEncKey, newAccessTreeEncKeySign, "traverse access tree enc key")
	if err != nil {
		return err
	}
	err = storeSignedJSON(accessTreeHMACKeyUUID, encryptedNewAccessTreeHMACKey, newAccessTreeHMACKeySign, "traverse access tree hmac key")
	if err != nil {
		return err
	}
	// Recursively traverse the tree
	for _, childUUID := range node.Branches {
		err = traverseAccessTree(
			childUUID,
			sharedSignKey,
			keyStoreDSKeyMarshalJSON,
			accessTreeEncKey,
			accessTreeHMACKey,
			newAccessTreeHeaderEncKey,
			newAccessTreeHeaderHMACKey,
		)
		if err != nil {
			return err
		}
	}
	return nil
}

/* General helper methods */
func storeHMACedJSON(uuid userlib.UUID, encryptedJSON []byte, jsonHMAC []byte, infoMsg string) error {
	var HMACedJSON HMACedJSON
	HMACedJSON.EncryptedJSON = encryptedJSON
	HMACedJSON.JSONHMAC = jsonHMAC
	HMACedJSONBytes, err := json.Marshal(HMACedJSON)
	if err != nil {
		return errors.New("error marshalling HMACedJSON: " + infoMsg)
	}
	userlib.DatastoreSet(uuid, HMACedJSONBytes)
	return nil
}

func storeSignedJSON(uuid userlib.UUID, encryptedJSON []byte, jsonSign []byte, infoMsg string) error {
	var signedJSON SignedJSON
	signedJSON.EncryptedJSON = encryptedJSON
	signedJSON.JSONSign = jsonSign
	SignedJSONBytes, err := json.Marshal(signedJSON)
	if err != nil {
		return errors.New("error marshalling HMACedJSON: " + infoMsg)
	}
	userlib.DatastoreSet(uuid, SignedJSONBytes)
	return nil
}

func retrieveHMACedJSON(v interface{}, uuid userlib.UUID, symKey []byte, HMACKey []byte, infoMsg string) (err error) {
	HMACedJSONBytes, ok := userlib.DatastoreGet(uuid)
	if !ok {
		return errors.New("error retrieving HMACedJSON: " + infoMsg)
	}
	var varHMACedJSON HMACedJSON
	err = json.Unmarshal(HMACedJSONBytes, &varHMACedJSON)
	if err != nil {
		return errors.New("error unmarshalling HMACedJSON: " + infoMsg)
	}
	encryptedJSON := varHMACedJSON.EncryptedJSON
	jsonHMAC := varHMACedJSON.JSONHMAC
	actualHMAC, err := userlib.HMACEval(HMACKey, encryptedJSON)
	if err != nil {
		return errors.New("error HMACing encryptedJSON: " + infoMsg)
	}
	if !userlib.HMACEqual(actualHMAC, jsonHMAC) {
		return errors.New("encryptedJSON hmac value is incorrect: " + infoMsg)
	}
	encryptedJSONBytes := userlib.SymDec(symKey, encryptedJSON)
	err = json.Unmarshal(encryptedJSONBytes, v)
	if err != nil {
		return errors.New("error unmarshalling encryptedJSON: " + infoMsg)
	}
	return nil
}

func retrieveSignedJSON(ciphertext []byte, verifyKey userlib.PublicKeyType, sign []byte, RSAPrivateKey userlib.PrivateKeyType, infoMsg string) (plaintext []byte, err error) {
	err = userlib.DSVerify(verifyKey, ciphertext, sign)
	if err != nil {
		return nil, errors.New("error verifying invitation enc key: " + infoMsg)
	}
	plaintext, err = userlib.PKEDec(RSAPrivateKey, ciphertext)
	if err != nil {
		return nil, errors.New("error decrypting invitation struct enc key: " + infoMsg)
	}
	return plaintext, nil
}

func symEncAndHMACEval(plaintext interface{}, symKey []byte, HMACKey []byte, infoMsg string) (ciphertext []byte, ciphertextHMAC []byte, err error) {
	// Json Marshall the content
	plaintextJSON, err := json.Marshal(plaintext)
	if err != nil {
		return nil, nil, errors.New("error marshalling plaintext: " + infoMsg)
	}

	// Encrypt the plaintext
	iv := userlib.RandomBytes(16)
	ciphertext = userlib.SymEnc(symKey, iv, plaintextJSON)

	// HMAC the ciphertext
	ciphertextHMAC, err = userlib.HMACEval(HMACKey, ciphertext)
	if err != nil {
		return nil, nil, errors.New("error HMACing ciphertext: " + infoMsg)
	}

	return ciphertext, ciphertextHMAC, nil
}

func PKEEncAndSign(plaintext interface{}, RSAPublicKey userlib.PublicKeyType, signKey userlib.PrivateKeyType, errMsg string) (ciphertext []byte, signedCiphertext []byte, err error) {
	// json marshal
	var plaintextBytes []byte
	switch v := plaintext.(type) {
	case []byte:
		plaintextBytes = v
	default:
		plaintextBytes, err = json.Marshal(plaintext)
		if err != nil {
			return nil, nil, errors.New("error marshalling plaintext " + errMsg)
		}
	}
	// RSA encryption
	ciphertext, err = userlib.PKEEnc(RSAPublicKey, plaintextBytes)
	if err != nil {
		return nil, nil, err
	}
	// Signing
	signedCiphertext, err = userlib.DSSign(signKey, ciphertext)
	if err != nil {
		return nil, nil, errors.New("error signing " + errMsg)
	}

	return ciphertext, signedCiphertext, nil
}

/* Helper methods for File Operations */

func getSharedVerificationKeyUUID(filename string, username string) (userlib.UUID, error) {
	return uuid.FromBytes(userlib.Hash([]byte(filename + username + "SharedDSVerifyKey"))[:16])
}

func getSharedVerificationKey(filename string, username string) (verifyKey *userlib.PublicKeyType, err error) {
	dataStoreDSKey, err := getSharedVerificationKeyUUID(filename, username)
	if err != nil {
		return nil, err
	}
	keyStoreKeyBytes, ok := userlib.DatastoreGet(dataStoreDSKey)
	if !ok {
		return nil, errors.New("error getting shared DSA public key")
	}
	var keyStoreKey string
	err = json.Unmarshal(keyStoreKeyBytes, &keyStoreKey)
	if err != nil {
		return nil, err
	}
	verifyKeyTemp, ok := userlib.KeystoreGet(keyStoreKey)
	if !ok {
		return nil, errors.New("SharedVerifyKey doesn't exist in KeystoreGet")
	}

	return &verifyKeyTemp, nil
}

func getAccessTreeHeader(userdata *User, filename string) (accessTreeHeaderUUID userlib.UUID, accessTreeHeader *AccessTreeHeader, accessTreeEncKey []byte, accessTreeHMACKey []byte, err error) {
	accessTreeEncKey, accessTreeHMACKey, err = getAccessTreeKeys(userdata, filename)
	if err != nil {
		return uuid.Nil, nil, nil, nil, err
	}

	accessTreeHeaderUUID, err = uuid.FromBytes(userlib.Hash(accessTreeEncKey)[:16])
	if err != nil {
		return uuid.Nil, nil, nil, nil, err
	}
	var temp AccessTreeHeader
	err = retrieveHMACedJSON(&temp, accessTreeHeaderUUID, accessTreeEncKey, accessTreeHMACKey, "access tree header")
	if err != nil {
		return uuid.Nil, nil, nil, nil, err
	}
	return accessTreeHeaderUUID, &temp, accessTreeEncKey, accessTreeHMACKey, nil
}

func getAccessTreeKeys(userdata *User, filename string) (accessTreeEncKey []byte, accessTreeHMACKey []byte, err error) {
	accessTreeEncKeyUUID, accessTreeHMACKeyUUID, err := getAccessKeyUUIDs(userdata, filename)
	if err != nil {
		return nil, nil, err
	}
	verifyKey, err := getSharedVerificationKey(filename, userdata.Username)
	if err != nil {
		return nil, nil, err
	}
	accessTreeEncKey, err = getAccessTreeKey(accessTreeEncKeyUUID, userdata.RSAPrivateKey, verifyKey)
	if err != nil {
		return nil, nil, err
	}
	accessTreeHMACKey, err = getAccessTreeKey(accessTreeHMACKeyUUID, userdata.RSAPrivateKey, verifyKey)
	if err != nil {
		return nil, nil, err
	}
	return accessTreeEncKey, accessTreeHMACKey, nil
}

func getAccessKeyUUIDs(userdata *User, filename string) (accessTreeEncKeyUUID userlib.UUID, accessTreeHMACKeyUUID userlib.UUID, err error) {
	username := userdata.Username
	FileMappingInfo := userdata.UserFileMappingInfo
	FileMappingEncKey := FileMappingInfo.FileMappingEncKey
	FileMappingHMACKey := FileMappingInfo.FileMappingHMACKey

	// Get the file mapping information
	fileMappingInfoUUID, err := uuid.FromBytes(userlib.Hash([]byte(filename + username))[:16])
	if err != nil {
		return uuid.Nil, uuid.Nil, err
	}
	var fileMapping FileMapping
	err = retrieveHMACedJSON(&fileMapping, fileMappingInfoUUID, FileMappingEncKey, FileMappingHMACKey, "file mapping")
	if err != nil {
		return uuid.Nil, uuid.Nil, err
	}
	accessTreeEncKeyUUID = fileMapping.AccessTreeEncKeyUUID
	accessTreeHMACKeyUUID = fileMapping.AccessTreeHMACKeyUUID

	return accessTreeEncKeyUUID, accessTreeHMACKeyUUID, nil
}

func getAccessTreeKey(accessTreeKeyUUID userlib.UUID, RSAPrivateKey userlib.PrivateKeyType, verifyKey *userlib.PublicKeyType) (accessTreeKey []byte, err error) {
	encryptedAccessTreeEncKeyDataStoreJSONBytes, ok := userlib.DatastoreGet(accessTreeKeyUUID)
	if !ok {
		return nil, errors.New(strings.ToTitle("file not found"))
	}
	var encryptedAccessTreeEncKeyDataStoreJSON SignedJSON
	err = json.Unmarshal(encryptedAccessTreeEncKeyDataStoreJSONBytes, &encryptedAccessTreeEncKeyDataStoreJSON)
	if err != nil {
		return nil, errors.New("error unmarshalling encryptedAccessTreeEncKeyDataStoreJSON")
	}
	encryptedAccessTreeEncKey := encryptedAccessTreeEncKeyDataStoreJSON.EncryptedJSON
	accessTreeEncKeySign := encryptedAccessTreeEncKeyDataStoreJSON.JSONSign
	accessTreeKey, err = retrieveSignedJSON(encryptedAccessTreeEncKey, *verifyKey, accessTreeEncKeySign, RSAPrivateKey, "access tree enc key")
	if err != nil {
		return nil, err
	}
	return accessTreeKey, nil
}

func chunkFileContent(
	accessTreeHeaderPtr *AccessTreeHeader,
	blockNo int,
	content []byte,
	nextBlockUUID userlib.UUID,
	nextBlockEncKey []byte,
	nextBlockHMACKey []byte,
	shouldUpdateFirstBlockInfo bool,
) (err error) {
	// Chunk the File into 1KB sized blocks - Here is the psuedocode
	for i := 0; i < len(content); i, blockNo = i+blockSize, blockNo+1 {
		// 	Generate random UUIDs: BlockUUID
		// 	Generate random keys: BlockRandomIV, BlockContentEncKey, BlockContentHMACKey
		blockUUID := nextBlockUUID
		// blockRandomIV := nextBlockRandomIV
		blockEncKey := nextBlockEncKey
		blockHMACKey := nextBlockHMACKey
		// Get the current block content
		endIndex := i + blockSize
		if endIndex > len(content) {
			endIndex = len(content)
		}
		blockContent := content[i:endIndex]

		// New next block values
		nextBlockUUID = uuid.New()
		nextBlockEncKey = userlib.RandomBytes(16)
		nextBlockHMACKey = userlib.RandomBytes(16)

		// 	Store this information to struct AccessTreeHeader
		if shouldUpdateFirstBlockInfo && i == 0 {
			accessTreeHeaderPtr.FirstBlockUUID = blockUUID
			accessTreeHeaderPtr.FirstEncKey = blockEncKey
			accessTreeHeaderPtr.FirstHMACKey = blockHMACKey
		}
		if i >= len(content)-blockSize {
			accessTreeHeaderPtr.LastBlockUUID = blockUUID
			accessTreeHeaderPtr.LastEncKey = blockEncKey
			accessTreeHeaderPtr.LastHMACKey = blockHMACKey
			accessTreeHeaderPtr.LastBlockRemainingBytes = blockSize - (endIndex - i)

			// Fill the remaining bytes of blockContent with 0s
			for j := 0; j < accessTreeHeaderPtr.LastBlockRemainingBytes; j++ {
				blockContent = append(blockContent, 'a')
			}

			// Edge case: The last block has nil for all its next block fields
			nextBlockUUID = uuid.Nil
		}

		var fileBlockData File
		fileBlockData.Content = blockContent
		fileBlockData.BlockNo = blockNo
		fileBlockData.NextBlockUUID = nextBlockUUID
		fileBlockData.NextBlockEncKey = nextBlockEncKey
		fileBlockData.NextBlockHMACKey = nextBlockHMACKey
		encryptedBlock, encryptedBlockHMAC, err := symEncAndHMACEval(fileBlockData, blockEncKey, blockHMACKey, "block data")
		if err != nil {
			return err
		}
		// Store the file block at the datastore
		// pre := userlib.DatastoreGetBandwidth()
		err = storeHMACedJSON(blockUUID, encryptedBlock, encryptedBlockHMAC, "block")
		if err != nil {
			return err
		}
		// post := userlib.DatastoreGetBandwidth()
		// difference := post - pre
		// fmt.Printf("storeHMACedJSON in chunk - Bandwidth used: %d, content size: %d, \n", difference, len(blockContent))

	}
	return
}

/* Helper methods for User Authentication */

func storeUser(username string, password string, userdata *User) error {
	// Create the JSON object that is going to be stored in the datastore
	var userDataStoreJSON UserJSON

	// Encrpyt the user struct
	salt := userlib.RandomBytes(16)
	startingKey := userlib.Argon2Key([]byte(password), salt, 16)
	userEncKey, err := userlib.HashKDF(startingKey, []byte("EncKey"))
	if err != nil {
		return errors.New("error generating encrpytion key")
	}
	userHMACKey, err := userlib.HashKDF(startingKey, []byte("HMACKey"))
	if err != nil {
		return errors.New("error generating HMAC key")
	}
	encryptedUserStruct, encrpytedUserStructHMAC, err := symEncAndHMACEval(userdata, userEncKey[:16], userHMACKey[:16], "user struct")
	if err != nil {
		return err
	}
	userDataStoreJSON.Salt = salt
	userDataStoreJSON.EncryptedUserStruct = encryptedUserStruct
	userDataStoreJSON.UserStructHMAC = encrpytedUserStructHMAC

	// Generate the UUID for the user
	userUUID, err := uuid.FromBytes(userlib.Argon2Key([]byte(password), []byte(username), 16))
	if err != nil {
		return errors.New("error generating user UUID")
	}

	// Store the user at Datastore
	userDataStoreJSONBytes, err := json.Marshal(userDataStoreJSON)
	if err != nil {
		return errors.New("error marshalling userDataStoreJSON")
	}
	userlib.DatastoreSet(userUUID, userDataStoreJSONBytes)
	return nil
}

func retrieveUser(username string, password string) (userdataptr *User, err error) {
	// Check if userUUID exists
	userUUID := userlib.Argon2Key([]byte(password), []byte(username), 16)
	userUUIDBytes, err := uuid.FromBytes(userUUID)
	if err != nil {
		return nil, errors.New("error generating user UUID")
	}
	userDataStoreJSONBytes, ok := userlib.DatastoreGet(userUUIDBytes)
	if !ok {
		return nil, errors.New("user doesn't exist")
	}

	// Check if the user json is correct
	var userDataStoreJSON UserJSON
	err = json.Unmarshal(userDataStoreJSONBytes, &userDataStoreJSON)
	if err != nil {
		return nil, errors.New("error unmarshalling userDataStoreJSON")
	}

	// Get the values of the json
	salt := userDataStoreJSON.Salt
	encryptedUserStruct := userDataStoreJSON.EncryptedUserStruct
	expectedHMAC := userDataStoreJSON.UserStructHMAC

	// Check the hmac
	startingKey := userlib.Argon2Key([]byte(password), salt, 16)
	userHMACKey, err := userlib.HashKDF(startingKey, []byte("HMACKey"))
	if err != nil {
		return nil, errors.New("error generating HMAC key")
	}
	actualHMAC, err := userlib.HMACEval(userHMACKey[:16], encryptedUserStruct)
	if err != nil {
		return nil, errors.New("error HMACing the encrypted user struct")
	}
	if !userlib.HMACEqual(expectedHMAC, actualHMAC) {
		return nil, errors.New("user hmac value is incorrect")
	}

	// Decrypt the user struct
	var userdata User
	userEncKey, err := userlib.HashKDF(startingKey, []byte("EncKey"))
	if err != nil {
		return nil, errors.New("error generating encrpytion key")
	}
	userStructBytes := userlib.SymDec(userEncKey[:16], encryptedUserStruct)
	err = json.Unmarshal(userStructBytes, &userdata)
	if err != nil {
		return nil, errors.New("error unmarshalling user struct")
	}

	return &userdata, nil
}