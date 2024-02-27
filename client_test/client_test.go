package client_test

// You MUST NOT change these default imports.  ANY additional imports may
// break the autograder and everyone will be sad.

import (
	// Some imports use an underscore to prevent the compiler from complaining
	// about unused imports.
	_ "encoding/hex"
	_ "errors"
	_ "strconv"
	_ "strings"
	"testing"

	// A "dot" import is used here so that the functions in the ginko and gomega
	// modules can be used without an identifier. For example, Describe() and
	// Expect() instead of ginko.Describe() and gomega.Expect().
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	userlib "github.com/cs161-staff/project2-userlib"

	"github.com/cs161-staff/project2-starter-code/client"
)

func TestSetupAndExecution(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Client Tests")
}

// ================================================
// Global Variables (feel free to add more!)
// ================================================
const defaultPassword = "This is an inbreakable password"
const emptyString = ""
const emptyStringLong = "          "
const kita1 = "Bugün pazar.Bugün beni ilk defa güneşe cikardilar. Ve ben ömrümde ilk defa gökyüzününbu kadar benden uzakbu kadar mavibu kadar geniş olduğuna şaşarakkimildamadan durdum."
const kita2 = "Sonra saygiyla toprağa oturdum,dayadim sirtimi duvara. "
const kita3 = "Bu anda ne düşmek dalgalara, bu anda ne kavga, ne hürriyet, ne karim. Toprak, güneş ve ben...Bahtiyarim..."

// ================================================
// Describe(...) blocks help you organize your tests
// into functional categories. They can be nested into
// a tree-like structure.
// ================================================

var _ = Describe("Client Tests", func() {

	// A few user declarations that may be used for . Remember to initialize these before you
	// attempt to use them!
	var kerem *client.User
	var eren *client.User
	var tayyip *client.User

	// These declarations may be useful for multi-session .
	var keremIPhone *client.User
	var keremSamsung *client.User
	var keremXiaomi *client.User

	var err error

	// A bunch of filenames that may be useful.
	keremDocument := "keremDocument.txt"
	erenDocument := "erenDocument.txt"
	tayyipDocument := "tayyipDocument.txt"

	BeforeEach(func() {
		// This runs before each test within this Describe block (including nested tests).
		// Here, we reset the state of Datastore and Keystore so that tests do not interfere with each other.
		// We also initialize
		userlib.DatastoreClear()
		userlib.KeystoreClear()
	})

	Describe("Basic Tests", func() {

		Specify("Basic Test: Testing InitUser/GetUser on a single user.", func() {
			kerem, err = client.InitUser("kerem", defaultPassword)
			Expect(err).To(BeNil())
			keremSamsung, err = client.GetUser("kerem", defaultPassword)
			Expect(err).To(BeNil())
		})

		Specify("Basic Test: Testing Single User Tests for File Operations.", func() {
			kerem, err = client.InitUser("kerem", defaultPassword)
			Expect(err).To(BeNil())
			err = kerem.StoreFile(keremDocument, []byte(kita1))
			Expect(err).To(BeNil())
			err = kerem.AppendToFile(keremDocument, []byte(kita2))
			Expect(err).To(BeNil())
			err = kerem.AppendToFile(keremDocument, []byte(kita3))
			Expect(err).To(BeNil())
			filecontent, err := kerem.LoadFile(keremDocument)
			Expect(err).To(BeNil())
			Expect(filecontent).To(Equal([]byte(kita1 + kita2 + kita3)))
		})

		Specify("Basic Test: Testing Create/Accept Invite Functionality with multiple users and multiple instances.", func() {
			keremXiaomi, err = client.InitUser("kerem", defaultPassword)
			Expect(err).To(BeNil())
			eren, err = client.InitUser("eren", defaultPassword)
			Expect(err).To(BeNil())
			keremSamsung, err = client.GetUser("kerem", defaultPassword)
			Expect(err).To(BeNil())
			err = keremXiaomi.StoreFile(keremDocument, []byte(kita1))
			Expect(err).To(BeNil())
			invite, err := keremSamsung.CreateInvitation(keremDocument, "eren")
			Expect(err).To(BeNil())
			err = eren.AcceptInvitation("kerem", invite, erenDocument)
			Expect(err).To(BeNil())
			err = eren.AppendToFile(erenDocument, []byte(kita2))
			Expect(err).To(BeNil())
			err = keremXiaomi.AppendToFile(keremDocument, []byte(kita3))
			Expect(err).To(BeNil())
			filecontent, err := keremXiaomi.LoadFile(keremDocument)
			Expect(err).To(BeNil())
			Expect(filecontent).To(Equal([]byte(kita1 + kita2 + kita3)))
			filecontent, err = keremSamsung.LoadFile(keremDocument)
			Expect(err).To(BeNil())
			Expect(filecontent).To(Equal([]byte(kita1 + kita2 + kita3)))
			filecontent, err = eren.LoadFile(erenDocument)
			Expect(err).To(BeNil())
			Expect(filecontent).To(Equal([]byte(kita1 + kita2 + kita3)))
			keremIPhone, err = client.GetUser("kerem", defaultPassword)
			Expect(err).To(BeNil())
			filecontent, err = keremIPhone.LoadFile(keremDocument)
			Expect(err).To(BeNil())
			Expect(filecontent).To(Equal([]byte(kita1 + kita2 + kita3)))
		})

		Specify("Basic Test: Testing Revoke Functionality", func() {
			kerem, err = client.InitUser("kerem", defaultPassword)
			Expect(err).To(BeNil())
			eren, err = client.InitUser("eren", defaultPassword)
			Expect(err).To(BeNil())
			tayyip, err = client.InitUser("tayyip", defaultPassword)
			Expect(err).To(BeNil())
			kerem.StoreFile(keremDocument, []byte(kita1))
			invite, err := kerem.CreateInvitation(keremDocument, "eren")
			Expect(err).To(BeNil())
			err = eren.AcceptInvitation("kerem", invite, erenDocument)
			Expect(err).To(BeNil())
			filecontent, err := kerem.LoadFile(keremDocument)
			Expect(err).To(BeNil())
			Expect(filecontent).To(Equal([]byte(kita1)))
			filecontent, err = eren.LoadFile(erenDocument)
			Expect(err).To(BeNil())
			Expect(filecontent).To(Equal([]byte(kita1)))
			invite, err = eren.CreateInvitation(erenDocument, "tayyip")
			Expect(err).To(BeNil())
			err = tayyip.AcceptInvitation("eren", invite, tayyipDocument)
			Expect(err).To(BeNil())
			filecontent, err = eren.LoadFile(erenDocument)
			Expect(err).To(BeNil())
			Expect(filecontent).To(Equal([]byte(kita1)))
			filecontent, err = tayyip.LoadFile(tayyipDocument)
			Expect(err).To(BeNil())
			Expect(filecontent).To(Equal([]byte(kita1)))
			err = kerem.RevokeAccess(keremDocument, "eren")
			Expect(err).To(BeNil())
			filecontent, err = kerem.LoadFile(keremDocument)
			Expect(err).To(BeNil())
			Expect(filecontent).To(Equal([]byte(kita1)))
			_, err = eren.LoadFile(erenDocument)
			Expect(err).ToNot(BeNil())
			_, err = tayyip.LoadFile(tayyipDocument)
			Expect(err).ToNot(BeNil())
			err = eren.AppendToFile(erenDocument, []byte(kita2))
			Expect(err).ToNot(BeNil())
			err = tayyip.AppendToFile(tayyipDocument, []byte(kita2))
			Expect(err).ToNot(BeNil())
		})
	})

	Describe("Test for File Operation 1", func() {

		Specify("Tests for File Operations 1: file doesn't exist - load", func() {
			kerem, err = client.InitUser("kerem", defaultPassword)
			Expect(err).To(BeNil())
			_, err = kerem.LoadFile(keremDocument)
			Expect(err).ToNot(BeNil(), "file doesn't exist")
		})

		Specify("Tests for File Operations 2: the file name is empty", func() {
			kerem, err = client.InitUser("kerem", defaultPassword)
			Expect(err).To(BeNil())
			err = kerem.StoreFile(emptyString, []byte(kita1))
			Expect(err).To(BeNil())
			err = kerem.AppendToFile(emptyString, []byte(kita2))
			Expect(err).To(BeNil())
			err = kerem.AppendToFile(emptyString, []byte(kita3))
			Expect(err).To(BeNil())
			fileContent, err := kerem.LoadFile(emptyString)
			Expect(err).To(BeNil())
			Expect(fileContent).To(Equal([]byte(kita1 + kita2 + kita3)))
			keremSamsung, err = client.GetUser("kerem", defaultPassword)
			Expect(err).To(BeNil())
			fileContent, err = keremSamsung.LoadFile(emptyString)
			Expect(err).To(BeNil())
			Expect(fileContent).To(Equal([]byte(kita1 + kita2 + kita3)))
		})
	})

	Describe("Tests for File Operations with Revocation 1", func() {
		Specify("Tests for File Operations with Sharing + Revocation: revoke before even it is accepted", func() {
			kerem, err = client.InitUser("kerem", defaultPassword)
			Expect(err).To(BeNil())
			err = kerem.StoreFile(keremDocument, []byte(kita1))
			Expect(err).To(BeNil())
			eren, err = client.InitUser("eren", defaultPassword)
			Expect(err).To(BeNil())
			invitation, err := kerem.CreateInvitation(keremDocument, "eren")
			Expect(err).To(BeNil())
			err = kerem.RevokeAccess(keremDocument, "eren")
			Expect(err).To(BeNil())
			err = eren.AcceptInvitation("kerem", invitation, keremDocument)
			Expect(err).ToNot(BeNil())
		})

		Specify("Tests for File Operations with Sharing + Revocation: user doesn't exist", func() {
			kerem, err = client.InitUser("kerem", defaultPassword)
			Expect(err).To(BeNil())
			err = kerem.StoreFile(keremDocument, []byte(kita1))
			Expect(err).To(BeNil())
			err = kerem.RevokeAccess(keremDocument, "eren")
			Expect(err).ToNot(BeNil())
		})

		Specify("Tests for File Operations with Sharing + Revocation: across device accept", func() {
			kerem, err = client.InitUser("kerem", defaultPassword)
			Expect(err).To(BeNil())
			err = kerem.StoreFile(keremDocument, []byte(kita1))
			Expect(err).To(BeNil())
			eren, err = client.InitUser("eren", defaultPassword)
			Expect(err).To(BeNil())
			erenSamsung, err := client.GetUser("eren", defaultPassword)
			Expect(err).To(BeNil())
			invitation, err := kerem.CreateInvitation(keremDocument, "eren")
			Expect(err).To(BeNil())
			err = erenSamsung.AcceptInvitation("kerem", invitation, keremDocument)
			Expect(err).To(BeNil())
			_, err = eren.LoadFile(keremDocument)
			Expect(err).To(BeNil())
		})
	})

	Describe("Tests for User Authentication", func() {
		Specify("Tests for User Authentication: empty username.", func() {
			kerem, err = client.InitUser(emptyString, defaultPassword)
			Expect(err).ToNot(BeNil())
		})

		Specify("Tests for User Authentication: wrong password.", func() {
			kerem, err = client.InitUser("kerem", defaultPassword)
			Expect(err).To(BeNil())
			kerem, err = client.GetUser("kerem", "customPassword")
			Expect(err).ToNot(BeNil())
		})

		Specify("Tests for User Authentication: wrong username-password combination.", func() {
			kerem, err = client.InitUser("kerem", "keremPassword")
			Expect(err).To(BeNil())
			eren, err = client.InitUser("eren", "erenPassword")
			Expect(err).To(BeNil())
			kerem, err = client.GetUser("eren", "keremPassword")
			Expect(err).ToNot(BeNil())
		})

		Specify("Tests for User Authentication: empty password.", func() {
			kerem, err = client.InitUser("kerem", emptyString)
			Expect(err).To(BeNil())
			kerem, err = client.GetUser("kerem", emptyString)
			Expect(err).To(BeNil())
		})

		Specify("Tests for User Authentication: username doesn't exist", func() {
			keremSamsung, err = client.GetUser("kerem", defaultPassword)
			Expect(err).ToNot(BeNil())
		})

		Specify("Tests for User Authentication: password is wrong", func() {
			kerem, err = client.InitUser("kerem", defaultPassword)
			Expect(err).To(BeNil())
			keremSamsung, err = client.GetUser("kerem", "wrong password")
			Expect(err).ToNot(BeNil(), "HMAC was tampered")
		})
	})

	Describe("Test for File Operation 3", func() {
		Specify("Tests for File Operations 3: clearing the datastore", func() {
			kerem, err = client.InitUser("kerem", defaultPassword)
			Expect(err).To(BeNil())
			err = kerem.StoreFile(keremDocument, []byte(kita1))
			Expect(err).To(BeNil())
			err = kerem.AppendToFile(keremDocument, []byte(kita2))
			Expect(err).To(BeNil())
			fileContent, err := kerem.LoadFile(keremDocument)
			Expect(err).To(BeNil())
			Expect(fileContent).To(Equal([]byte(kita1 + kita2)))
			userlib.DatastoreClear()
			fileContent, err = kerem.LoadFile(keremDocument)
			Expect(err).ToNot(BeNil())
		})

		Specify("Tests for File Operations 3: user doesn't have the corresponding filemapping", func() {
			kerem, err = client.InitUser("kerem", defaultPassword)
			Expect(err).To(BeNil())
			_, err = kerem.LoadFile(keremDocument)
			Expect(err).ToNot(BeNil(), "file doesn't exist")
		})

		Specify("Tests for File Operations 3: content is empty", func() {
			kerem, err = client.InitUser("kerem", defaultPassword)
			Expect(err).To(BeNil())
			err = kerem.StoreFile(keremDocument, []byte(kita1))
			Expect(err).To(BeNil())
			err = kerem.AppendToFile(keremDocument, []byte(emptyString))
			Expect(err).To(BeNil(), "The filecontent is empty")
		})

		Specify("Tests for File Operations with Sharing + Revocation: revoke can only be called by the owner", func() {
			kerem, err = client.InitUser("kerem", defaultPassword)
			Expect(err).To(BeNil())
			err = kerem.StoreFile(keremDocument, []byte(kita1))
			Expect(err).To(BeNil())
			eren, err = client.InitUser("eren", defaultPassword)
			Expect(err).To(BeNil())
			tayyip, err = client.InitUser("tayyip", defaultPassword)
			Expect(err).To(BeNil())
			invitation, err := kerem.CreateInvitation(keremDocument, "eren")
			Expect(err).To(BeNil())
			err = eren.AcceptInvitation("kerem", invitation, keremDocument)
			Expect(err).To(BeNil())
			invitation, err = eren.CreateInvitation(keremDocument, "tayyip")
			Expect(err).To(BeNil())
			err = tayyip.AcceptInvitation("eren", invitation, keremDocument)
			Expect(err).To(BeNil())
			err = kerem.RevokeAccess(keremDocument, "tayyip")
			Expect(err).ToNot(BeNil())
		})
	})

	Describe("Tests for File Operations with Sharing 1", func() {
		Specify("Tests for File Operations with Sharing: duplicate filenames are allowed", func() {
			kerem, err = client.InitUser("kerem", defaultPassword)
			Expect(err).To(BeNil())
			err = kerem.StoreFile(keremDocument, []byte(kita1))
			Expect(err).To(BeNil())
			eren, err = client.InitUser("eren", defaultPassword)
			Expect(err).To(BeNil())
			invitation, err := kerem.CreateInvitation(keremDocument, "eren")
			Expect(err).To(BeNil())
			err = eren.AcceptInvitation("kerem", invitation, keremDocument)
			Expect(err).To(BeNil())
			fileContent, err := eren.LoadFile(keremDocument)
			Expect(err).To(BeNil())
			Expect(fileContent).To(Equal([]byte(kita1)))
		})

		Specify("Tests for File Operations with Sharing 1: differnet names with after-update are allowed", func() {
			kerem, err = client.InitUser("kerem", defaultPassword)
			Expect(err).To(BeNil())
			err = kerem.StoreFile(keremDocument, []byte(kita1))
			Expect(err).To(BeNil())
			err = kerem.AppendToFile(keremDocument, []byte(kita2))
			Expect(err).To(BeNil())
			eren, err = client.InitUser("eren", defaultPassword)
			Expect(err).To(BeNil())
			invitation, err := kerem.CreateInvitation(keremDocument, "eren")
			Expect(err).To(BeNil())
			err = eren.AcceptInvitation("kerem", invitation, "erenDocument")
			Expect(err).To(BeNil())
			fileContent, err := eren.LoadFile("erenDocument")
			Expect(err).To(BeNil())
			Expect(fileContent).To(Equal([]byte(kita1 + kita2)))
		})

		Specify("Tests for File Operations 2: filemapping malicious", func() {
			kerem, err = client.InitUser("kerem", defaultPassword)
			Expect(err).To(BeNil())
			err = kerem.StoreFile(keremDocument, []byte(kita1))
			Expect(err).To(BeNil())
			err = kerem.AppendToFile(keremDocument, []byte(kita2))
			Expect(err).To(BeNil())
			fileContent, err := kerem.LoadFile(keremDocument)
			Expect(err).To(BeNil())
			Expect(fileContent).To(Equal([]byte(kita1 + kita2)))
		})

		Specify("Tests for File Operations with Sharing 1: non-existent invitation", func() {
			kerem, err = client.InitUser("kerem", defaultPassword)
			Expect(err).To(BeNil())
			err = kerem.StoreFile(keremDocument, []byte(kita1))
			Expect(err).To(BeNil())
			eren, err = client.InitUser("eren", defaultPassword)
			Expect(err).To(BeNil())
		})

		Specify("Tests for File Operations with Sharing 3: updates to files after are allowed", func() {
			kerem, err = client.InitUser("kerem", defaultPassword)
			Expect(err).To(BeNil())
			err = kerem.StoreFile(keremDocument, []byte(kita1))
			Expect(err).To(BeNil())
			err = kerem.AppendToFile(keremDocument, []byte(kita2))
			Expect(err).To(BeNil())
			eren, err = client.InitUser("eren", defaultPassword)
			Expect(err).To(BeNil())
			invitation, err := kerem.CreateInvitation(keremDocument, "eren")
			Expect(err).To(BeNil())
			err = eren.AcceptInvitation("kerem", invitation, keremDocument)
			Expect(err).To(BeNil())
			fileContent, err := eren.LoadFile(keremDocument)
			Expect(err).To(BeNil())
			Expect(fileContent).To(Equal([]byte(kita1 + kita2)))
		})

		Specify("Tests for common bugs and malicious activity: case-sensitive usernames.", func() {
			kerem, err = client.InitUser("kerem", defaultPassword)
			Expect(err).To(BeNil())
			eren, err = client.InitUser("Kerem", defaultPassword)
			Expect(err).To(BeNil())
			kerem, err = client.GetUser("kerem", defaultPassword)
			Expect(err).To(BeNil())
			Kerem, err := client.GetUser("kerem", defaultPassword)
			Expect(err).To(BeNil())
			Expect(Kerem == kerem).To(BeFalse())
		})

	})

	Describe("Tests for File Operations with Revocation 2", func() {
		Specify("Tests for File Operations with Sharing + Revocation: revoke immidiately", func() {
			kerem, err = client.InitUser("kerem", defaultPassword)
			Expect(err).To(BeNil())
			err = kerem.StoreFile(keremDocument, []byte(kita1))
			Expect(err).To(BeNil())
			eren, err = client.InitUser("eren", defaultPassword)
			Expect(err).To(BeNil())
			invitation, err := kerem.CreateInvitation(keremDocument, "eren")
			Expect(err).To(BeNil())
			err = eren.AcceptInvitation("kerem", invitation, keremDocument)
			Expect(err).To(BeNil())
			err = kerem.RevokeAccess(keremDocument, "eren")
			Expect(err).To(BeNil())
			err = eren.AppendToFile(keremDocument, []byte(kita2))
			Expect(err).ToNot(BeNil())
		})

		Specify("Tests for File Operations with Sharing + Revocation: file doesn't exist", func() {
			kerem, err = client.InitUser("kerem", defaultPassword)
			Expect(err).To(BeNil())
			err = kerem.StoreFile(keremDocument, []byte(kita1))
			Expect(err).To(BeNil())
			eren, err = client.InitUser("eren", defaultPassword)
			Expect(err).To(BeNil())
			err = kerem.RevokeAccess(keremDocument, "eren")
			Expect(err).ToNot(BeNil())
		})

		Specify("Tests for File Operations with Sharing + Revocation: tree with different devices", func() {
			kerem, err = client.InitUser("kerem", defaultPassword)
			Expect(err).To(BeNil())
			eren, err = client.InitUser("eren", defaultPassword)
			Expect(err).To(BeNil())
			erenSamsung, err := client.GetUser("eren", defaultPassword)
			Expect(err).To(BeNil())
			abdulkadiRRR, err := client.InitUser("abdulkadiRRR", defaultPassword)
			Expect(err).To(BeNil())
			_, err = client.InitUser("fenaSikerim", defaultPassword)
			Expect(err).To(BeNil())
			fenaSikerimSamsung, err := client.GetUser("fenaSikerim", defaultPassword)
			Expect(err).To(BeNil())
			fenaSikerimIPhone, err := client.GetUser("fenaSikerim", defaultPassword)
			Expect(err).To(BeNil())
			behlul, err := client.InitUser("behlul", defaultPassword)
			Expect(err).To(BeNil())
			tayyip, err := client.InitUser("tayyip", defaultPassword)
			Expect(err).To(BeNil())
			tayyipSamsung, err := client.GetUser("tayyip", defaultPassword)
			Expect(err).To(BeNil())
			cumhuriyet, err := client.InitUser("cumhuriyet", defaultPassword)
			Expect(err).To(BeNil())
			err = kerem.StoreFile(keremDocument, []byte(kita1))
			Expect(err).To(BeNil())
			invite, err := kerem.CreateInvitation(keremDocument, "eren")
			Expect(err).To(BeNil())
			err = erenSamsung.AcceptInvitation("kerem", invite, keremDocument)
			Expect(err).To(BeNil())
			invite, err = eren.CreateInvitation(keremDocument, "abdulkadiRRR")
			Expect(err).To(BeNil())
			err = abdulkadiRRR.AcceptInvitation("eren", invite, keremDocument)
			Expect(err).To(BeNil())
			invite, err = abdulkadiRRR.CreateInvitation(keremDocument, "fenaSikerim")
			Expect(err).To(BeNil())
			err = fenaSikerimSamsung.AcceptInvitation("abdulkadiRRR", invite, keremDocument)
			Expect(err).To(BeNil())
			invite, err = eren.CreateInvitation(keremDocument, "behlul")
			Expect(err).To(BeNil())
			err = behlul.AcceptInvitation("eren", invite, keremDocument)
			Expect(err).To(BeNil())
			invite, err = kerem.CreateInvitation(keremDocument, "tayyip")
			Expect(err).To(BeNil())
			err = tayyipSamsung.AcceptInvitation("kerem", invite, keremDocument)
			Expect(err).To(BeNil())
			invite, err = tayyip.CreateInvitation(keremDocument, "cumhuriyet")
			Expect(err).To(BeNil())
			err = cumhuriyet.AcceptInvitation("tayyip", invite, keremDocument)
			Expect(err).To(BeNil())
			err = kerem.RevokeAccess(keremDocument, "eren")
			Expect(err).To(BeNil())
			_, err = erenSamsung.LoadFile(keremDocument)
			Expect(err).ToNot(BeNil())
			_, err = abdulkadiRRR.LoadFile(keremDocument)
			Expect(err).ToNot(BeNil())
			_, err = behlul.LoadFile(keremDocument)
			Expect(err).ToNot(BeNil())
			_, err = fenaSikerimIPhone.LoadFile(keremDocument)
			Expect(err).ToNot(BeNil())
			fileContent, err := tayyip.LoadFile(keremDocument)
			Expect(err).To(BeNil())
			Expect(fileContent).To(Equal([]byte(kita1)))
			fileContent, err = cumhuriyet.LoadFile(keremDocument)
			Expect(err).To(BeNil())
			Expect(fileContent).To(Equal([]byte(kita1)))
		})

		Specify("Tests for File Operations with Sharing + Revocation: invitation doesn't exist", func() {
			kerem, err = client.InitUser("kerem", defaultPassword)
			Expect(err).To(BeNil())
			err = kerem.StoreFile(keremDocument, []byte(kita1))
			Expect(err).To(BeNil())
			eren, err = client.InitUser("eren", defaultPassword)
			Expect(err).To(BeNil())
			err = kerem.RevokeAccess(keremDocument, "eren")
			Expect(err).ToNot(BeNil())
		})

		Specify("Tests for common bugs and malicious activity: non-existant username.", func() {
			kerem, err = client.GetUser("kerem", defaultPassword)
			Expect(err).ToNot(BeNil())
		})

		Specify("Tests for common bugs and malicious activity: no password.", func() {
			kerem, err = client.InitUser("kerem", defaultPassword)
			Expect(err).To(BeNil())
			kerem, err = client.GetUser("kerem", emptyString)
			Expect(err).ToNot(BeNil())
		})

		Specify("Tests for File Operations: one user with many devices testing for file operations", func() {
			kerem, err = client.InitUser("kerem", defaultPassword)
			Expect(err).To(BeNil())
			err = kerem.StoreFile(keremDocument, []byte(kita1))
			Expect(err).To(BeNil())
			err = kerem.AppendToFile(keremDocument, []byte(kita2))
			Expect(err).To(BeNil())
			err = kerem.AppendToFile(keremDocument, []byte(kita3))
			Expect(err).To(BeNil())
			fileContent, err := kerem.LoadFile(keremDocument)
			Expect(err).To(BeNil())
			Expect(fileContent).To(Equal([]byte(kita1 + kita2 + kita3)))
			keremSamsung, err = client.GetUser("kerem", defaultPassword)
			Expect(err).To(BeNil())
			fileContent, err = keremSamsung.LoadFile(keremDocument)
			Expect(err).To(BeNil())
			Expect(fileContent).To(Equal([]byte(kita1 + kita2 + kita3)))
		})

		Specify("Tests for File Operations 1: can't access if no access", func() {
			kerem, err = client.InitUser("kerem", defaultPassword)
			Expect(err).To(BeNil())
			err = kerem.StoreFile(keremDocument, []byte(kita1))
			Expect(err).To(BeNil())
			fileContent, err := kerem.LoadFile(keremDocument)
			Expect(err).To(BeNil())
			Expect(fileContent).To(Equal([]byte(kita1)))
			eren, err = client.InitUser("eren", defaultPassword)
			Expect(err).To(BeNil())
			fileContent, err = eren.LoadFile(keremDocument)
			Expect(err).ToNot(BeNil())
		})
	})

	Describe("Tests for File Operations with Sharing 3", func() {

		Specify("Tests for File Operations with Sharing 3: update file", func() {
			kerem, err = client.InitUser("kerem", defaultPassword)
			Expect(err).To(BeNil())
			err = kerem.StoreFile(keremDocument, []byte(kita1))
			Expect(err).To(BeNil())
			err = kerem.AppendToFile(keremDocument, []byte(kita2))
			Expect(err).To(BeNil())
			eren, err = client.InitUser("eren", defaultPassword)
			Expect(err).To(BeNil())
			invitation, err := kerem.CreateInvitation(keremDocument, "eren")
			Expect(err).To(BeNil())
			err = eren.AcceptInvitation("kerem", invitation, "erenDocument")
			Expect(err).To(BeNil())
			fileContent, err := eren.LoadFile("erenDocument")
			Expect(err).To(BeNil())
			Expect(fileContent).To(Equal([]byte(kita1 + kita2)))
			err = eren.AppendToFile("erenDocument", []byte(kita3))
			Expect(err).To(BeNil())
			fileContent, err = eren.LoadFile("erenDocument")
			Expect(err).To(BeNil())
			Expect(fileContent).To(Equal([]byte(kita1 + kita2 + kita3)))
			fileContent, err = kerem.LoadFile(keremDocument)
			Expect(err).To(BeNil())
			Expect(fileContent).To(Equal([]byte(kita1 + kita2 + kita3)))
		})

		Specify("Tests for File Operations with Sharing 3: user doesn't exist", func() {
			kerem, err = client.InitUser("kerem", defaultPassword)
			Expect(err).To(BeNil())
			err = kerem.StoreFile(keremDocument, []byte(kita1))
			Expect(err).To(BeNil())
			_, err := kerem.CreateInvitation(keremDocument, "eren")
			Expect(err).ToNot(BeNil())
		})

	})

	Describe("Tests for File Operations with Revocation 3", func() {
		Specify("Tests for File Operations with Sharing + Revocation: file doesn't exist", func() {
			kerem, err = client.InitUser("kerem", defaultPassword)
			Expect(err).To(BeNil())
			eren, err = client.InitUser("eren", defaultPassword)
			Expect(err).To(BeNil())
			err = kerem.RevokeAccess(keremDocument, "eren")
			Expect(err).ToNot(BeNil())
		})

		Specify("Tests for File Operations with Sharing + Revocation: the whole tree is removed", func() {
			kerem, err = client.InitUser("kerem", defaultPassword)
			Expect(err).To(BeNil())
			eren, err = client.InitUser("eren", defaultPassword)
			Expect(err).To(BeNil())
			abdulkadiRRR, err := client.InitUser("abdulkadiRRR", defaultPassword)
			Expect(err).To(BeNil())
			fenaSikerim, err := client.InitUser("fenaSikerim", defaultPassword)
			Expect(err).To(BeNil())
			behlul, err := client.InitUser("behlul", defaultPassword)
			Expect(err).To(BeNil())
			tayyip, err := client.InitUser("tayyip", defaultPassword)
			Expect(err).To(BeNil())
			cumhuriyet, err := client.InitUser("cumhuriyet", defaultPassword)
			Expect(err).To(BeNil())
			err = kerem.StoreFile(keremDocument, []byte(kita1))
			Expect(err).To(BeNil())
			invite, err := kerem.CreateInvitation(keremDocument, "eren")
			Expect(err).To(BeNil())
			err = eren.AcceptInvitation("kerem", invite, keremDocument)
			Expect(err).To(BeNil())
			invite, err = eren.CreateInvitation(keremDocument, "abdulkadiRRR")
			Expect(err).To(BeNil())
			err = abdulkadiRRR.AcceptInvitation("eren", invite, keremDocument)
			Expect(err).To(BeNil())
			invite, err = abdulkadiRRR.CreateInvitation(keremDocument, "fenaSikerim")
			Expect(err).To(BeNil())
			err = fenaSikerim.AcceptInvitation("abdulkadiRRR", invite, keremDocument)
			Expect(err).To(BeNil())
			invite, err = eren.CreateInvitation(keremDocument, "behlul")
			Expect(err).To(BeNil())
			err = behlul.AcceptInvitation("eren", invite, keremDocument)
			Expect(err).To(BeNil())
			invite, err = kerem.CreateInvitation(keremDocument, "tayyip")
			Expect(err).To(BeNil())
			err = tayyip.AcceptInvitation("kerem", invite, keremDocument)
			Expect(err).To(BeNil())
			invite, err = tayyip.CreateInvitation(keremDocument, "cumhuriyet")
			Expect(err).To(BeNil())
			err = cumhuriyet.AcceptInvitation("tayyip", invite, keremDocument)
			Expect(err).To(BeNil())
			err = kerem.RevokeAccess(keremDocument, "eren")
			Expect(err).To(BeNil())
			_, err = eren.LoadFile(keremDocument)
			Expect(err).ToNot(BeNil())
			_, err = abdulkadiRRR.LoadFile(keremDocument)
			Expect(err).ToNot(BeNil())
			_, err = behlul.LoadFile(keremDocument)
			Expect(err).ToNot(BeNil())
			_, err = fenaSikerim.LoadFile(keremDocument)
			Expect(err).ToNot(BeNil())
			fileContent, err := tayyip.LoadFile(keremDocument)
			Expect(err).To(BeNil())
			Expect(fileContent).To(Equal([]byte(kita1)))
			fileContent, err = cumhuriyet.LoadFile(keremDocument)
			Expect(err).To(BeNil())
			Expect(fileContent).To(Equal([]byte(kita1)))
		})

		Specify("Tests for File Operations with Sharing 2: file doesn't exist", func() {
			kerem, err = client.InitUser("kerem", defaultPassword)
			Expect(err).To(BeNil())
			eren, err = client.InitUser("eren", defaultPassword)
			Expect(err).To(BeNil())
			_, err := kerem.CreateInvitation(keremDocument, "eren")
			Expect(err).ToNot(BeNil())
		})

	})

	Describe("Test for File Operation 2", func() {

		Specify("Tests for File Operations with Sharing 2: update file upon accept", func() {
			kerem, err = client.InitUser("kerem", defaultPassword)
			Expect(err).To(BeNil())
			err = kerem.StoreFile(keremDocument, []byte(kita1))
			Expect(err).To(BeNil())
			err = kerem.AppendToFile(keremDocument, []byte(kita2))
			Expect(err).To(BeNil())
			eren, err = client.InitUser("eren", defaultPassword)
			Expect(err).To(BeNil())
			invitation, err := kerem.CreateInvitation(keremDocument, "eren")
			Expect(err).To(BeNil())
			err = eren.AcceptInvitation("kerem", invitation, "erenDocument")
			Expect(err).To(BeNil())
			fileContent, err := eren.LoadFile("erenDocument")
			Expect(err).To(BeNil())
			Expect(fileContent).To(Equal([]byte(kita1 + kita2)))
			err = kerem.AppendToFile(keremDocument, []byte(kita3))
			Expect(err).To(BeNil())
			fileContent, err = eren.LoadFile("erenDocument")
			Expect(err).To(BeNil())
			Expect(fileContent).To(Equal([]byte(kita1 + kita2 + kita3)))
		})

		Specify("Tests for File Operations 2: same filenames - overwrite", func() {
			kerem, err = client.InitUser("kerem", defaultPassword)
			Expect(err).To(BeNil())
			err = kerem.StoreFile(keremDocument, []byte(kita1))
			Expect(err).To(BeNil())
			eren, err = client.InitUser("eren", defaultPassword)
			Expect(err).To(BeNil())
			err = eren.StoreFile(keremDocument, []byte(kita2))
			Expect(err).To(BeNil())
			fileContent, err := kerem.LoadFile(keremDocument)
			Expect(err).To(BeNil())
			Expect(fileContent).To(Equal([]byte(kita1)))
			fileContent, err = eren.LoadFile(keremDocument)
			Expect(err).To(BeNil())
			Expect(fileContent).To(Equal([]byte(kita2)))
		})

		Specify("Tests for File Operations 2: file doesn't exist - append", func() {
			kerem, err = client.InitUser("kerem", defaultPassword)
			Expect(err).To(BeNil())
			err = kerem.AppendToFile(keremDocument, []byte(kita2))
			Expect(err).ToNot(BeNil(), "file doesn't exist")
		})
	})

	Describe("Tests for common bugs and malicious activity", func() {

		Specify("Tests for common bugs and malicious activity: existing username.", func() {
			kerem, err = client.InitUser("kerem", defaultPassword)
			Expect(err).To(BeNil())
			kerem, err = client.InitUser("kerem", defaultPassword)
			Expect(err).ToNot(BeNil())
		})

		Specify("Tests for common bugs and malicious activity: simple init and get", func() {
			kerem, err = client.InitUser(emptyStringLong, defaultPassword)
			Expect(err).To(BeNil(), "Username empty")
			kerem, err = client.InitUser("kerem", defaultPassword)
			Expect(err).To(BeNil())
			keremSamsung, err = client.GetUser("kerem", defaultPassword)
			Expect(err).To(BeNil())
			eren, err = client.InitUser("kerem", "random password")
			Expect(err).ToNot(BeNil(), "Username exists")
		})

		Specify("Tests for File Operations 1: the contents are overwritten", func() {
			kerem, err = client.InitUser("kerem", defaultPassword)
			Expect(err).To(BeNil())
			err = kerem.StoreFile(keremDocument, []byte(kita1))
			Expect(err).To(BeNil())
			err = kerem.StoreFile(keremDocument, []byte(kita2))
			Expect(err).To(BeNil())
			fileContent, err := kerem.LoadFile(keremDocument)
			Expect(err).To(BeNil())
			Expect(fileContent).To(Equal([]byte(kita2)))
		})

		Specify("Tests for common bugs and malicious activity: username malicious", func() {
			kerem, err = client.InitUser("kerem", defaultPassword)
			Expect(err).To(BeNil())
			counter := 0
			keys := userlib.DatastoreGetMap()
			for len(keys) > 0 {
				for k := range keys {
					if counter == 0 {
						userlib.DatastoreDelete(k)
					}
					counter++
				}
				keys = userlib.DatastoreGetMap()
			}
			keremSamsung, err = client.GetUser("kerem", defaultPassword)
			Expect(err).ToNot(BeNil(), "username was tempered")
		})
	})

	Describe("Tests for File Operations with Sharing 2", func() {

		Specify("Tests for File Operations with Sharing 2: different file names are allowed", func() {
			kerem, err = client.InitUser("kerem", defaultPassword)
			Expect(err).To(BeNil())
			err = kerem.StoreFile(keremDocument, []byte(kita1))
			Expect(err).To(BeNil())
			eren, err = client.InitUser("eren", defaultPassword)
			Expect(err).To(BeNil())
			invitation, err := kerem.CreateInvitation(keremDocument, "eren")
			Expect(err).To(BeNil())
			err = eren.AcceptInvitation("kerem", invitation, "erenDocument")
			Expect(err).To(BeNil())
			fileContent, err := eren.LoadFile("erenDocument")
			Expect(err).To(BeNil())
			Expect(fileContent).To(Equal([]byte(kita1)))
		})

		Specify("Tests for User Authentication: password is wrong: HMAC malicious", func() {
			counter := 0
			keys := userlib.DatastoreGetMap()
			for len(keys) > 0 {
				for k := range keys {
					if counter == 0 {
						userlib.DatastoreSet(k, userlib.RandomBytes(16))
					}
					counter++
				}
				keys = userlib.DatastoreGetMap()
			}
			keremSamsung, err = client.GetUser("kerem", defaultPassword)
			Expect(err).ToNot(BeNil(), "HMAC was tampered")
		})

		Specify("Tests for File Operations with Sharing + Revocation: you need to create an invitation first", func() {
			kerem, err = client.InitUser("kerem", defaultPassword)
			Expect(err).To(BeNil())
			eren, err = client.InitUser("eren", defaultPassword)
			Expect(err).To(BeNil())
			tayyip, err = client.InitUser("tayyip", defaultPassword)
			Expect(err).To(BeNil())
			err = kerem.StoreFile(keremDocument, []byte(kita1))
			Expect(err).To(BeNil())
			_, err = kerem.CreateInvitation(keremDocument, "eren")
			Expect(err).To(BeNil())
			_, err = eren.CreateInvitation(keremDocument, "tayyip")
			Expect(err).ToNot(BeNil())
		})

		Specify("Tests for File Operations with Sharing + Revocation: across device create", func() {
			kerem, err = client.InitUser("kerem", defaultPassword)
			Expect(err).To(BeNil())
			err = kerem.StoreFile(keremDocument, []byte(kita1))
			Expect(err).To(BeNil())
			eren, err = client.InitUser("eren", defaultPassword)
			Expect(err).To(BeNil())
			keremSamsung, err = client.GetUser("kerem", defaultPassword)
			Expect(err).To(BeNil())
			invitation, err := keremSamsung.CreateInvitation(keremDocument, "eren")
			Expect(err).To(BeNil())
			err = eren.AcceptInvitation("kerem", invitation, keremDocument)
			Expect(err).To(BeNil())
		})

	})

})
