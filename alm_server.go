package main

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	mrand "math/rand"
	"net"
	"os"
	"strconv"
	"strings"
)

var debug bool

const USAGE string = `Usage:
    %v [--debug] <key-hex> <listen-addr>
	%v --solution <key-hex> <student-id>

Simulates a grades server. If given the --solution flag, outputs the given student's grades instead.

Examples:
	$ %v --debug aabbccddeeff001122334455 :1234
	$ %v --solution aabbccddeeff001122334455 12345
`

func usage() {
	bin := os.Args[0]
	fmt.Fprintf(os.Stderr, USAGE, bin, bin, bin, bin)
	os.Exit(1)
}

func main() {
	var keyHex, listenAddr string
	var studentId uint16
	solution := false

	switch {
	case len(os.Args) == 4 && os.Args[1] == "--solution":
		solution = true
		keyHex = os.Args[2]
		id, err := strconv.ParseUint(os.Args[3], 10, 16)
		if err != nil {
			fmt.Fprintln(os.Stderr, "student ID must be in the range [0, 65535]")
			os.Exit(1)
		}
		studentId = uint16(id)
	case len(os.Args) == 3:
		keyHex = os.Args[1]
		listenAddr = os.Args[2]
	case len(os.Args) == 4 && os.Args[1] == "--debug":
		debug = true
		keyHex = os.Args[2]
		listenAddr = os.Args[3]
	default:
		usage()
	}

	key, err := hex.DecodeString(keyHex)
	if err != nil {
		fmt.Fprintf(os.Stderr, "could not decode key as hex: %v\n", err)
		os.Exit(1)
	}

	// Use an HMAC as a KDF to generate an AES key and a seed.
	hmc := hmac.New(sha256.New, key)
	key = hmc.Sum([]byte("key"))
	seed := int64(binary.BigEndian.Uint64(hmc.Sum([]byte("seed"))))

	var k [16]byte
	copy(k[:], key)
	server, err := newServerState(k, seed)
	if err != nil {
		fmt.Fprintf(os.Stderr, "could not create server state: %v\n", err)
		os.Exit(1)
	}

	if solution {
		fmt.Print(getGrades(server, studentId))
		return
	}

	l, err := net.Listen("tcp", listenAddr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "could not listen: %v\n", err)
		os.Exit(1)
	}

	for {
		conn, err := l.Accept()
		if err != nil {
			fmt.Fprintf(os.Stderr, "error accepting: %v\n", err)
			continue
		}

		debugPrintf("New connection from %v\n", conn.RemoteAddr())

		go func() {
			err := handleRequest(newConn(conn, server))
			dbgSuffix := ""
			if err != nil {
				dbgSuffix = fmt.Sprintf(" with err %v", err)
			}
			debugPrintf("Connection closed from %v%v\n", conn.RemoteAddr(), dbgSuffix)
		}()
	}
}

type serverState struct {
	block cipher.Block
	seed  int64
}

func newServerState(key [16]byte, seed int64) (*serverState, error) {
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, fmt.Errorf("could not create AES cipher: %v", err)
	}

	return &serverState{
		block: block,
		seed:  seed,
	}, nil
}

type conn struct {
	c      net.Conn
	s      *bufio.Scanner
	server *serverState
}

func newConn(c net.Conn, server *serverState) *conn {
	return &conn{
		c:      c,
		s:      bufio.NewScanner(c),
		server: server,
	}
}

// Reads and decrypts a command from the connection.
//
// If EOF is encountered, `read` returns that as an error.
//
// If the received ciphertext could not be decrypted, an error will be sent to
// the client, and `read` will return `nil` for both return values.
func (c *conn) read() ([]byte, error) {
	// 21 is the longest possible remote address in IPv4:
	//   123.123.123.123:12345
	debugPrefix := fmt.Sprintf("[%21v]", c.c.RemoteAddr())

	if !c.s.Scan() {
		return nil, io.EOF
	}

	line := c.s.Text()

	bytes, err := hex.DecodeString(line)
	if err != nil {
		sendErrorResponse(c.c, fmt.Sprintf("could not parse ciphertext: %v", err))
		return nil, nil
	}

	switch {
	case len(bytes)%16 != 0:
		sendErrorResponse(c.c, "input length must be a multiple of the 16 bytes")
		return nil, nil
	case len(bytes) < 32:
		sendErrorResponse(c.c, "input must include IV and at least one ciphertext block")
		return nil, nil
	}

	iv := bytes[:16]
	ctext := bytes[16:]

	debugPrintf("%v iv:         %v\n", debugPrefix, hex.EncodeToString(iv))
	debugPrintf("%v ciphertext: %v\n", debugPrefix, hex.EncodeToString(ctext))

	ptext := make([]byte, len(ctext))
	mode := NewUFSDecrypter(c.server.block, iv)
	mode.CryptBlocks(ptext, ctext)

	debugPrintf("%v plaintext (with trailer): %v\n", debugPrefix, hex.EncodeToString(ptext))

	ptext, err = removeTrailer(ptext)
	if err != nil {
		debugPrintf("%v bad trailer\n", debugPrefix)
		c.write([]byte("bad trailer\n"))
		return nil, nil
	}

	// Add an extra space b/w "w/o" and "trailer" so the line is the same length
	// as the preceding one.
	debugPrintf("%v plaintext (w/o  trailer): %v\n", debugPrefix, hex.EncodeToString(ptext))

	return ptext, nil
}

func (c *conn) write(b []byte) error {
	ptext := addTrailer(b)
	var iv [16]byte
	rand.Read(iv[:])
	mode := NewUFSEncrypter(c.server.block, iv[:])

	ctext := make([]byte, len(ptext))
	mode.CryptBlocks(ctext, ptext)

	s := hex.EncodeToString(append(iv[:], ctext...))
	_, err := fmt.Fprintf(c.c, "%v\n", s)
	return err
}

func handleRequest(conn *conn) error {
	for {
		cmd, err := conn.read()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			panic("internal error: c.read() should never return an error other than io.EOF")
		}

		if cmd == nil {
			continue
		}

		args := strings.Fields(string(cmd))

		if len(args) == 0 {
			err := conn.write([]byte("no command given"))
			if err != nil {
				return fmt.Errorf("failed to write response: %v", err)
			}
			continue
		}

		cmdName := args[0]
		args = args[1:]

		// Man, `view_student_grades` is such a long command. The shortest
		// possible command, `view_student_grades 1\n`, is 21 characters long,
		// which requires two plaintext blocks to encode. I bet hackers can't
		// break our encryption, but if they were to try to, they'd have to
		// figure out how to encrypt multi-block plaintexts! That should keep
		// them at bay!
		switch {
		case cmdName == "view_student_grades" && len(args) == 1:
			id, err := strconv.ParseUint(args[0], 10, 16)
			if err != nil {
				err := conn.write([]byte("ID must be in the range [0, 65535]"))
				if err != nil {
					return fmt.Errorf("failed to write response: %v", err)
				}
				break
			}
			grades := getGrades(conn.server, uint16(id))
			err = conn.write([]byte(grades))
			if err != nil {
				return fmt.Errorf("failed to write response: %v", err)
			}
		case cmdName == "help":
			buf := bytes.NewBuffer(nil)
			fmt.Fprintf(buf, "Available commands:\n")
			fmt.Fprintf(buf, "    view_student_grades <id>\n")
			fmt.Fprintf(buf, "    help\n")
			err := conn.write(buf.Bytes())
			if err != nil {
				return fmt.Errorf("failed to write response: %v", err)
			}
		default:
			err := conn.write([]byte("invalid or unrecognized command; try typing \"help\""))
			if err != nil {
				return fmt.Errorf("failed to write response: %v", err)
			}
		}
	}
}

func sendErrorResponse(w io.Writer, msg string) error {
	type errorResponse struct {
		Message string `json:"message"`
	}

	enc := json.NewEncoder(w)
	return enc.Encode(errorResponse{Message: msg})
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
		fmt.Println(b, ret, rem)
		panic("internal error: generated return byte slice which is not a multiple of the block size")
	}

	return ret
}

var courseNames = []string{
	"Nuclear Chemistry (with lab)",
	"Advanced Topics In Structural Chemistry (with lab)",
	"Introduction To Evolutionary Entomology",
	"Advanced Topics In Medieval Irish History",
	"English 2",
	"Arabic 3",
	"Algorithms",
	"Abstract Statistics",
	"Foreign Policy And American Political Thought",
	"Environmental Econometrics",
	"An Isolationist Approach To Comparative Foreign Policy Studies",
	"Grand Strategy And Comparative Human Rights Studies",
	"Special Topics In Middle Eastern Political Thought",
	"Introduction To Family Behavior",
	"Post-cold War Era French Art History",
	"Cold War Era Folk Early Modern Australian Culinary Traditions",
	"Advanced Topics In Advanced Topics Studies",
	"Applied Abstract Theory",
	"Operating Systems",
	"War And Peace",
	"Quantitative Microeconomic Theory",
	"Introduction To Computer Science",
	"Advanced Topics In Economics And Comparative Human Rights Studies (with lab)",
	"Intermediate Finance",
	"Surrealist Film",
	"Late Medieval Marine Biology (with lab)",
	"Cognitive Behavioral Psychology",
	"Calculus 2",
	"Proof-based Comparative Literature",
	"Introduction To Computer-generated Course Names",
}

func getGrades(server *serverState, id uint16) string {
	// Seed the PRNG in a way that depends both on the CLI key and the given ID.
	r := mrand.New(mrand.NewSource(server.seed))
	id64 := uint64(id)
	newSeed := r.Int63() ^ int64((id64<<48)|(id64<<32)|(id64<<16)|id64)
	r.Seed(newSeed)

	var num int
	rval := r.Float64()
	switch {
	case rval < 0.1:
		num = 3
	case rval < 0.2:
		num = 5
	default:
		num = 4
	}

	var grades string
	courseIndexes := r.Perm(len(courseNames))[:num]
	for _, i := range courseIndexes {
		name := courseNames[i]
		var grade string
		rval = r.Float64()
		switch {
		case rval < 0.5:
			grade = "A"
		case rval < 0.8:
			grade = "B"
		case rval < 0.95:
			grade = "C"
		default:
			grade = "N"
		}

		grades += fmt.Sprintf("Course: %v\nGrade: %v\n", name, grade)
	}

	return fmt.Sprintf("Grades for %v:\n%v", id, grades)
}

func debugPrintf(format string, a ...any) (n int, err error) {
	if debug {
		return fmt.Printf("[DEBUG] "+format, a...)
	}
	return 0, nil
}

type ufsCrypter struct {
	b         cipher.Block
	blockSize int
	iv        []byte
	tmp       []byte
}

func newUFS(b cipher.Block, iv []byte) *ufsCrypter {
	return &ufsCrypter{
		b:         b,
		blockSize: b.BlockSize(),
		iv:        bytes.Clone(iv),
		tmp:       make([]byte, b.BlockSize()),
	}
}

func NewUFSEncrypter(b cipher.Block, iv []byte) cipher.BlockMode {
	if len(iv) != b.BlockSize() {
		panic("NewUFSEncrypter: IV length must equal block size")
	}
	return (*ufsEncrypter)(newUFS(b, iv))
}

func NewUFSDecrypter(b cipher.Block, iv []byte) cipher.BlockMode {
	if len(iv) != b.BlockSize() {
		panic("NewUFSDecrypter: IV length must equal block size")
	}
	return (*ufsDecrypter)(newUFS(b, iv))
}

type ufsEncrypter ufsCrypter

func (x *ufsEncrypter) BlockSize() int { return x.blockSize }
func (x *ufsEncrypter) CryptBlocks(dst, src []byte) {
	if len(src)%x.blockSize != 0 {
		panic("input not full blocks")
	}
	if len(dst) < len(src) {
		panic("output smaller than input")
	}

	iv := x.iv

	for len(src) > 0 {
		subtle.XORBytes(dst[:x.blockSize], src[:x.blockSize], iv)
		x.b.Encrypt(dst[:x.blockSize], dst[:x.blockSize])

		iv = dst[:x.blockSize]
		src = src[x.blockSize:]
		dst = dst[x.blockSize:]
	}

	copy(x.iv, iv)
}

type ufsDecrypter ufsCrypter

func (x *ufsDecrypter) BlockSize() int { return x.blockSize }
func (x *ufsDecrypter) CryptBlocks(dst, src []byte) {
	if len(src)%x.blockSize != 0 {
		panic("input not full blocks")
	}
	if len(dst) < len(src) {
		panic("output smaller than input")
	}
	if len(src) == 0 {
		return
	}

	end := len(src)
	start := end - x.blockSize
	prev := start - x.blockSize

	copy(x.tmp, src[start:end])

	for start > 0 {
		x.b.Decrypt(dst[start:end], src[start:end])
		subtle.XORBytes(dst[start:end], dst[start:end], src[prev:start])

		end = start
		start = prev
		prev -= x.blockSize
	}

	x.b.Decrypt(dst[start:end], src[start:end])
	subtle.XORBytes(dst[start:end], dst[start:end], x.iv)

	x.iv, x.tmp = x.tmp, x.iv
}
