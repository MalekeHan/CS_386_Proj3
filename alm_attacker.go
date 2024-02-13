package main

import (
	"bufio"
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
	iv, ctext, err := encryptPlaintext(conn, ptext)
	if err != nil {
		log.Fatalf("could not encrypt command: %v", err)
	}

	// Send the encrypted command to the server, and receive the encrypted
	// response.
	respIv, respCtext, err := sendCommand(conn, iv, ctext)
	if err != nil {
		log.Fatalf("could not send command ciphertext: %v", err)
	}

	// Decrypt the response.
	ptext, err = decryptCiphertext(conn, respIv, respCtext)
	if err != nil {
		log.Fatalf("could not send decrypt response ciphertext: %v", err)
	}

	// Strip the trailer from the decrypted plaintext response.
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
	return block{}, nil, errors.New("unimplemented")
}

// Decrypts the given ciphertext, but does not strip the trailer.
//
// Note that this should *not* result in the server believing that a valid
// command has been sent. That's for `stealGrades` to do!
func decryptCiphertext(conn *conn, iv block, ctext []block) ([]block, error) {
	return nil, errors.New("unimplemented")
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

	// var intermediateState block
	// var plaintext block

	// We need to get the previous cipherblock here: C1 OR the IV
	//getPrev idk

	//We need to save that C1 cause we need to XOR it later so make a copy here that we will manipulate
	// cpy of C1 here

	//We know the block is 16 long
	// iterate through starting at 15 and go though all 256 possible guesses to deduce the Itermediate state

	// send each manipulated block to the server

	//if padding error, try next guess

	//else

	/*
		update the manipulated block to keep that guess since we know it is correct

		//recover the plaintext by XORing the Intermediate state with the origingal previous cipherblock(C1/IV)

	*/

	return block{}, errors.New("unimplemented")
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
