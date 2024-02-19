package main

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
)

/*************************** Your code goes here *****************************/
// Your job is to implement `encryptPlaintext`, `decryptCiphertext`, and
// `decryptCiphertextBlock`. We've implemented `stealGrades` already, which uses
// these functions to do its job. We leave it at the top because it's the core
// logic, and we want you to look at it as a guide for how your functions will
// be used. You should not need to modify `stealGrades`.
//
// Hints:
// - `encryptPlaintext` and `decryptCiphertext` should be implemented in terms
//   of `decryptCiphertextBlock`.
// - `encryptPlaintext` and `decryptCiphertext` should not need to depend on
//   each other.
// - We recommend that you implement in the following order:
//   1. `decryptCiphertextBlock`
//   2. `decryptCiphertext`
//   3. `encryptCiphertext`
// - The `--debug` flag is your friend!

// Steals the grades of the student with ID `studentId` and print them to
// stdout.
func stealGrades(conn *conn, studentId string) {
	// The command we want to send to the server.
	cmd := fmt.Sprintf("view_student_grades %v", studentId)
	// The command, with trailer added and stored as a slice of plaintext
	// blocks.
	ptext := bytesToBlocks(addTrailer([]byte(cmd)))
	debugPrintf("Plaintext command being sent: %s\n", cmd)
	fmt.Printf("GOING TO ENCRYPT THE PLAINTEXT NOW")
	iv, ctext, err := encryptPlaintext(conn, ptext)
	fmt.Printf("JUST ENCRYPTED: ")
	if err != nil {
		log.Fatalf("could not encrypt command: %v", err)
	}

	// Send the encrypted command to the server, and receive the encrypted
	// response.
	fmt.Printf("SENDING THE ENCRYPTED COMMAND NOW")
	respIv, respCtext, err := sendCommand(conn, iv, ctext)
	if err != nil {
		log.Fatalf("could not send command ciphertext: %v", err)
	}

	// Decrypt the response.
	fmt.Printf("GOING TO TRY TO DECRYPT NOW")
	ptext, err = decryptCiphertext(conn, respIv, respCtext)
	if err != nil {
		log.Fatalf("could not send decrypt response ciphertext: %v", err)
	}

	// Strip the trailer from the decrypted plaintext response.
	fmt.Printf("GOING TO REMOVE TRAILER\n")
	grades, err := removeTrailer(concatBlocks(ptext...))
	if err != nil {
		log.Fatalf("could not remove trailer: %v", err)
	}

	fmt.Print(string(grades))
}

// Encrypts the plaintext, assuming the trailer has already been added.
//
// Returns the IV and all ciphertext blocks.

func encryptPlaintext(conn *conn, ptext []block) (block, []block, error) {
	if len(ptext) != 2 {
		return block{}, nil, errors.New("function is designed for exactly two blocks of plaintext")
	}

	// Placeholder for the intermediate states (IS) of c0 and c1
	var IS_c1, IS_c0 block

	// Step 0: Initialize c1 with an arbitrary value
	var c1 block
	_, err := rand.Read(c1.bytes[:])
	if err != nil {
		return block{}, nil, errors.New("failed to generate arbitrary c1")
	}

	// Use decryptCiphertextBlock to find the intermediate state for c1
	IS_c1, err = decryptCiphertextBlock(conn, c1)
	if err != nil {
		return block{}, nil, fmt.Errorf("failed to get intermediate state for c1: %v", err)
	}

	// Calculate c0 based on IS_c1 XOR ptext[1]
	c0 := xorBlocks(IS_c1, ptext[1])

	// Use decryptCiphertextBlock again to find the intermediate state for c0
	IS_c0, err = decryptCiphertextBlock(conn, c0)
	if err != nil {
		return block{}, nil, fmt.Errorf("failed to get intermediate state for c0: %v", err)
	}

	// Calculate IV based on IS_c0 XOR ptext[0]
	IV := xorBlocks(IS_c0, ptext[0])

	// Construct the ciphertext array with c0 and c1
	ctext := []block{c0, c1}

	return IV, ctext, nil
}

// Decrypts the given ciphertext, but does not strip the trailer.
//
// Note that this should *not* result in the server believing that a valid
// command has been sent. That's for `stealGrades` to do!
func decryptCiphertext(conn *conn, iv block, ctext []block) ([]block, error) {
	var decryptedText []block

	for i, cblock := range ctext {
		fmt.Println("GOING TO DECRYPT CIPHER BLOCK NOW: ")

		decryptedBlock, err := decryptCiphertextBlock(conn, cblock)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt block %d: %v", i, err)
		}
		fmt.Printf("DECRYPTED THE CIPHER BLOCK")

		decryptedText = append(decryptedText, decryptedBlock) // append the decrypred (Intermediate state) block to the slice
	}

	var plaintext []block
	for i, intermediateStateBlock := range decryptedText { // go though the slice and XOR each entry with the previous cipher text block or IV
		var plaintextBlock block
		if i == 0 {

			plaintextBlock = xorBlocks(intermediateStateBlock, iv) // XOR the first block's intermediate state with the IV
		} else {

			plaintextBlock = xorBlocks(intermediateStateBlock, ctext[i-1]) // XOR others with previous ciphertext blocks
		}
		plaintext = append(plaintext, plaintextBlock)
	}

	return plaintext, nil
}

// Reverse-engineers the decryption of `cblock`. Returns a plaintext block which
// encrypts to `cblock`.
//
// The returned `block` should be the decryption of `cblock` using the block
// cipher's block decryption function, and *not* considering the UFS block
// cipher mode. In other words, this is the input to encryption *after* XOR'ing,
// or equivalently, the output of decryption *before* XOR'ing (otherwise known
// as the "intermediate state").

func decryptCiphertextBlock(conn *conn, cblock block) (block, error) {
	var intermediateState block
	var tempCblock block
	var count int

	// Decrypt each byte of the block starting from the last one
	for i := 15; i >= 0; i-- {
		paddingByte := byte(16 - i) // get the padding byte based on waht index we are on // the value that the server expects to see if the guess is correct
		for guess := 0; guess < 256; guess++ {
			tempCblock.bytes[i] = byte(guess)                                         // put guess into the block  C1[i] = guess // try every single guess
			_, errResponseBlocks, _ := sendCommand(conn, tempCblock, []block{cblock}) // send the C1
			//fmt.Printf("THIS IS THE LEN OF THE SEND RESPONSE BLOCKS %d \n", len(errResponseBlocks))
			if len(errResponseBlocks) != 1 { // check for non padding errors
				//fmt.Printf("I GOT A GOOD ERROR**************************************************************************************************\n")
				count += 1
				intermediateState.bytes[i] = byte(guess) ^ paddingByte // IS[i] = C1[i] XOR ExpectedPaddingByte
				// set up all the bytes behind where we are at i to the correct padding pattern
				for j := i; j < 16; j++ {
					// set the guessed padding byte in the temp block for padding oracle verification.
					tempCblock.bytes[j] = intermediateState.bytes[j] ^ byte((16-i)+1) //C1[j] = I[j] XOR
				}
				break
			} else {
				//fmt.Println("GOT PADDING ERROR WILL TRY NEXT GUESS\n")
			}
		}
	}
	fmt.Println("THIS IS COUNT\n", count)

	// If my count gets to 16 then how did I not correctly guess everything then?

	// Verification of the entire intermediate state.
	fmt.Println("GOING TO VERIFY NOW: ")
	for i := 15; i >= 0; i-- {
		// Set the current byte and all following bytes to create a valid padding pattern for verification.
		for j := i; j < 16; j++ {
			// The bytes are set to produce a padding pattern of the form 01, 02 02, ..., 10 10 10 ... 10
			//C[i] = I[i] XOR Padding
			tempCblock.bytes[j] = intermediateState.bytes[j] ^ byte(16-i) // need to produce a padding pattern of  01, 02 02, ..., 10 10 10 ... 10  // make the server decrypt tempCblock to a block with correct padding since intermediatestate is "correct"
		}
		// Send the verification block to the server.
		_, responseBlocks, _ := sendCommand(conn, tempCblock, []block{cblock})
		fmt.Println("THIS IS THE LENGTH OF THE RESPONSE BLOCKS FOR VERIFICATION: %d INDEX AT: %d", len(responseBlocks), i)
		if len(responseBlocks) == 1 {
			fmt.Println("GOT A PADDING ERROR WHILE VERIFYING\n")
			// If the server responds with a padding error, the intermediate state is incorrect.
			return block{}, errors.New("COULD NOT VERIFY LOLZ")
		}
		// If no padding error, continue to verify the next byte.
	}
	fmt.Println("VERIFIED FULLY WITH NO PADDING ERROR\n")

	return intermediateState, nil
}

/*************************** Provided Helper Code *****************************/
// To complete this assignment you should NOT have to modify any code from here
// onwards.

// The type of both plaintext and ciphertext blocks.
type block struct {
	bytes [16]byte
}

func (b block) String() string {
	return hex.EncodeToString(b.bytes[:])
}

// Concatenates multiple blocks together.
func concatBlocks(blocks ...block) []byte {
	var ret []byte
	for _, b := range blocks {
		ret = append(ret, b.bytes[:]...)
	}
	return ret
}

// XORs two blocks together. Returns a block whose first byte is `a[0] ^ b[0]`,
// whose second byte is `a[1] ^ b[1]`, etc.
func xorBlocks(a, b block) block {
	var ret block
	for i := range a.bytes {
		ret.bytes[i] = a.bytes[i] ^ b.bytes[i]
	}
	return ret
}

// Removes trailer following the UFS standard.
func removeTrailer(b []byte) ([]byte, error) {
	// Get the last byte.
	lastByte := b[len(b)-1]

	// Make sure the byte is in [0x1, 0x10].
	if lastByte > 0x10 || lastByte == 0x0 {
		return nil, errors.New("Trailer is incorrect")

	}

	// Check to make sure that the entire trailer is correct.
	for i := len(b) - int(lastByte); i != len(b); i++ {
		if b[i] != lastByte {
			return nil, errors.New("Trailer is incorrect")

		}
	}

	return b[:len(b)-int(lastByte)], nil
}

// Adds trailing bytes as needed to ensure that the returned value is a multiple
// of the block length and conforms to the UFS trailer format.
func addTrailer(b []byte) []byte {
	rem := 16 - (len(b) % 16)
	if rem == 0 {
		rem = 16
	}

	// Do a deep copy so that `b` is unaffected. If `b` were affected by this
	// function, that could lead to surprising behavior.
	var ret []byte
	ret = append(ret, b...)

	for i := 0; i < rem; i++ {
		ret = append(ret, byte(rem))
	}

	if len(ret)%16 != 0 {
		panic("internal error: generated return byte slice which is not a multiple of the block size")
	}

	return ret
}

// Splits `b` into a slice of blocks. `b` must be a multiple of the block
// length.
func bytesToBlocks(b []byte) []block {
	if len(b)%16 != 0 {
		panic("bytesToBlocks: called with non-multiple of the block size")
	}

	var ret []block
	for i := 0; i < len(b)/16; i++ {
		var block block
		copy(block.bytes[:], b[i*16:])
		ret = append(ret, block)
	}
	return ret
}

/*************************** Other Provided Code ******************************/

var debug bool

const USAGE string = `Usage: %v [--debug] <server-addr> <student-id>

Steals the given student's grades.

Example:
	$ %v --debug :1234 12345
`

func parseArgs() (dbg bool, bindAddr, studentId string) {
	switch {
	case len(os.Args) == 3:
		return false, os.Args[1], os.Args[2]
	case len(os.Args) == 4 && os.Args[1] == "--debug":
		return true, os.Args[2], os.Args[3]
	default:
		bin := os.Args[0]
		log.Fatalf(USAGE, bin, bin)
		panic("unreachable") // otherwise Go thinks we need a `return` in this branch
	}
}

type conn struct {
	w io.Writer
	r *bufio.Reader
}

// Sends a ciphertext and returns the server's response ciphertext.
func sendCommand(conn *conn, iv block, ctext []block) (block, []block, error) {
	blocks := append([]block{iv}, ctext...)
	ciphertext := concatBlocks(blocks...)
	c := hex.EncodeToString(ciphertext)
	// We add an extra space between "sending" and "%v" so that the output lines
	// up with the output below, where the verb is "received".
	debugPrintf("sendCommand: sending  %v\n", c)

	_, err := conn.w.Write([]byte(c + "\n"))
	if err != nil {
		return block{}, nil, fmt.Errorf("could not send command: %v", err)
	}

	s, err := conn.r.ReadString('\n')
	if err != nil {
		return block{}, nil, fmt.Errorf("could not read response: %v", err)
	}
	// Truncate trailing newline.
	s = s[:len(s)-1]

	debugPrintf("sendCommand: received %v\n", s)

	type errorResponse struct {
		Message string `json:"message"`
	}

	// First, attempt to read the error response.
	var errResp errorResponse
	jsonErr := json.Unmarshal([]byte(s), &errResp)
	if jsonErr == nil {
		return block{}, nil, errors.New(errResp.Message)
	}

	// Second, if parsing as JSON fails, then we assume that a hex-encoded
	// ciphertext was sent.
	resp, hexErr := hex.DecodeString(s)
	if hexErr != nil {
		return block{}, nil, fmt.Errorf("could decode response neither as JSON (error: %v) nor as hex (error: %v)", jsonErr, hexErr)
	}

	if len(resp)%16 != 0 {
		return block{}, nil, fmt.Errorf("server ciphertext not a multiple of the block length")
	}

	blocks = bytesToBlocks(resp)
	if len(blocks) < 2 {
		return block{}, nil, fmt.Errorf("server ciphertext less than two blocks (one IV and one ciphertext block)")
	}

	return blocks[0], blocks[1:], nil
}

func main() {
	dbg, bindAddr, studentId := parseArgs()
	debug = dbg

	c, err := net.Dial("tcp", bindAddr)

	if err != nil {
		log.Fatalf("Could not connect to %v: %v\n", bindAddr, err)
	}

	r := bufio.NewReader(c)
	stealGrades(&conn{w: c, r: r}, studentId)
}

func debugPrintf(format string, a ...any) (n int, err error) {
	if debug {
		return fmt.Printf("[DEBUG] "+format, a...)
	}
	return 0, nil
}
