// Copyright 2013 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// TLS reference tests run a connection against a reference implementation
// (OpenSSL) of TLS and record the bytes of the resulting connection. The Go
// code, during a test, is configured with deterministic randomness and so the
// reference test can be reproduced exactly in the future.
//
// In order to save everyone who wishes to run the tests from needing the
// reference implementation installed, the reference connections are saved in
// files in the testdata directory. Thus running the tests involves nothing
// external, but creating and updating them requires the reference
// implementation.
//
// Tests can be updated by running them with the -update flag. This will cause
// the test files for failing tests to be regenerated. Since the reference
// implementation will always generate fresh random numbers, large parts of the
// reference connection will always change.

var (
	update       = flag.Bool("update", false, "update golden files on failure")
	keyFile      = flag.String("keylog", "", "destination file for KeyLogWriter")
	bogoMode     = flag.Bool("bogo-mode", false, "Enabled bogo shim mode, ignore everything else")
	bogoFilter   = flag.String("bogo-filter", "", "BoGo test filter")
	bogoLocalDir = flag.String("bogo-local-dir", "", "Local BoGo to use, instead of fetching from source")
)

func runTestAndUpdateIfNeeded(t *testing.T, name string, run func(t *testing.T, update bool), wait bool) {
	// FIPS mode is non-deterministic and so isn't suited for testing against static test transcripts.
	skipFIPS(t)

	success := t.Run(name, func(t *testing.T) {
		if !*update && !wait {
			t.Parallel()
		}
		run(t, false)
	})

	if !success && *update {
		t.Run(name+"#update", func(t *testing.T) {
			run(t, true)
		})
	}
}

// checkOpenSSLVersion ensures that the version of OpenSSL looks reasonable
// before updating the test data.
func checkOpenSSLVersion() error {
	if !*update {
		return nil
	}

	openssl := exec.Command("openssl", "version")
	output, err := openssl.CombinedOutput()
	if err != nil {
		return err
	}

	version := string(output)
	if strings.HasPrefix(version, "OpenSSL 1.1.1") {
		return nil
	}

	println("***********************************************")
	println("")
	println("You need to build OpenSSL 1.1.1 from source in order")
	println("to update the test data.")
	println("")
	println("Configure it with:")
	println("./Configure enable-weak-ssl-ciphers no-shared")
	println("and then add the apps/ directory at the front of your PATH.")
	println("***********************************************")

	return errors.New("version of OpenSSL does not appear to be suitable for updating test data")
}

// recordingConn is a net.Conn that records the traffic that passes through it.
// WriteTo can be used to produce output that can be later be loaded with
// ParseTestData.
type recordingConn struct {
	net.Conn
	sync.Mutex
	flows   [][]byte
	reading bool
}

func (r *recordingConn) Read(b []byte) (n int, err error) {
	if n, err = r.Conn.Read(b); n == 0 {
		return
	}
	b = b[:n]

	r.Lock()
	defer r.Unlock()

	if l := len(r.flows); l == 0 || !r.reading {
		buf := make([]byte, len(b))
		copy(buf, b)
		r.flows = append(r.flows, buf)
	} else {
		r.flows[l-1] = append(r.flows[l-1], b[:n]...)
	}
	r.reading = true
	return
}

func (r *recordingConn) Write(b []byte) (n int, err error) {
	if n, err = r.Conn.Write(b); n == 0 {
		return
	}
	b = b[:n]

	r.Lock()
	defer r.Unlock()

	if l := len(r.flows); l == 0 || r.reading {
		buf := make([]byte, len(b))
		copy(buf, b)
		r.flows = append(r.flows, buf)
	} else {
		r.flows[l-1] = append(r.flows[l-1], b[:n]...)
	}
	r.reading = false
	return
}

// WriteTo writes Go source code to w that contains the recorded traffic.
func (r *recordingConn) WriteTo(w io.Writer) (int64, error) {
	// TLS always starts with a client to server flow.
	clientToServer := true
	var written int64
	for i, flow := range r.flows {
		source, dest := "client", "server"
		if !clientToServer {
			source, dest = dest, source
		}
		n, err := fmt.Fprintf(w, ">>> Flow %d (%s to %s)\n", i+1, source, dest)
		written += int64(n)
		if err != nil {
			return written, err
		}
		dumper := hex.Dumper(w)
		n, err = dumper.Write(flow)
		written += int64(n)
		if err != nil {
			return written, err
		}
		err = dumper.Close()
		if err != nil {
			return written, err
		}
		clientToServer = !clientToServer
	}
	return written, nil
}

func parseTestData(r io.Reader) (flows [][]byte, err error) {
	var currentFlow []byte

	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := scanner.Text()
		// If the line starts with ">>> " then it marks the beginning
		// of a new flow.
		if strings.HasPrefix(line, ">>> ") {
			if len(currentFlow) > 0 || len(flows) > 0 {
				flows = append(flows, currentFlow)
				currentFlow = nil
			}
			continue
		}

		// Otherwise the line is a line of hex dump that looks like:
		// 00000170  fc f5 06 bf (...)  |.....X{&?......!|
		// (Some bytes have been omitted from the middle section.)
		_, after, ok := strings.Cut(line, " ")
		if !ok {
			return nil, errors.New("invalid test data")
		}
		line = after

		before, _, ok := strings.Cut(line, "|")
		if !ok {
			return nil, errors.New("invalid test data")
		}
		line = before

		hexBytes := strings.Fields(line)
		for _, hexByte := range hexBytes {
			val, err := strconv.ParseUint(hexByte, 16, 8)
			if err != nil {
				return nil, errors.New("invalid hex byte in test data: " + err.Error())
			}
			currentFlow = append(currentFlow, byte(val))
		}
	}

	if len(currentFlow) > 0 {
		flows = append(flows, currentFlow)
	}

	return flows, nil
}

// replayingConn is a net.Conn that replays flows recorded by recordingConn.
type replayingConn struct {
	t testing.TB
	sync.Mutex
	flows   [][]byte
	reading bool
}

var _ net.Conn = (*replayingConn)(nil)

func (r *replayingConn) Read(b []byte) (n int, err error) {
	r.Lock()
	defer r.Unlock()

	if !r.reading {
		r.t.Errorf("expected write, got read")
		return 0, fmt.Errorf("recording expected write, got read")
	}

	n = copy(b, r.flows[0])
	r.flows[0] = r.flows[0][n:]
	if len(r.flows[0]) == 0 {
		r.flows = r.flows[1:]
		if len(r.flows) == 0 {
			return n, io.EOF
		} else {
			r.reading = false
		}
	}
	return n, nil
}

func (r *replayingConn) Write(b []byte) (n int, err error) {
	r.Lock()
	defer r.Unlock()

	if r.reading {
		r.t.Errorf("expected read, got write")
		return 0, fmt.Errorf("recording expected read, got write")
	}

	if !bytes.HasPrefix(r.flows[0], b) {
		r.t.Errorf("write mismatch: expected %x, got %x", r.flows[0], b)
		return 0, fmt.Errorf("write mismatch")
	}
	r.flows[0] = r.flows[0][len(b):]
	if len(r.flows[0]) == 0 {
		r.flows = r.flows[1:]
		r.reading = true
	}
	return len(b), nil
}

func (r *replayingConn) Close() error {
	r.Lock()
	defer r.Unlock()

	if len(r.flows) > 0 {
		r.t.Errorf("closed with unfinished flows")
		return fmt.Errorf("unexpected close")
	}
	return nil
}

func (r *replayingConn) LocalAddr() net.Addr                { return nil }
func (r *replayingConn) RemoteAddr() net.Addr               { return nil }
func (r *replayingConn) SetDeadline(t time.Time) error      { return nil }
func (r *replayingConn) SetReadDeadline(t time.Time) error  { return nil }
func (r *replayingConn) SetWriteDeadline(t time.Time) error { return nil }

// tempFile creates a temp file containing contents and returns its path.
func tempFile(contents string) string {
	file, err := os.CreateTemp("", "go-tls-test")
	if err != nil {
		panic("failed to create temp file: " + err.Error())
	}
	path := file.Name()
	file.WriteString(contents)
	file.Close()
	return path
}

// localListener is set up by TestMain and used by localPipe to create Conn
// pairs like net.Pipe, but connected by an actual buffered TCP connection.
var localListener struct {
	mu   sync.Mutex
	addr net.Addr
	ch   chan net.Conn
}

const localFlakes = 0 // change to 1 or 2 to exercise localServer/localPipe handling of mismatches

func localServer(l net.Listener) {
	for n := 0; ; n++ {
		c, err := l.Accept()
		if err != nil {
			return
		}
		if localFlakes == 1 && n%2 == 0 {
			c.Close()
			continue
		}
		localListener.ch <- c
	}
}

var isConnRefused = func(err error) bool { return false }

func localPipe(t testing.TB) (net.Conn, net.Conn) {
	localListener.mu.Lock()
	defer localListener.mu.Unlock()

	addr := localListener.addr

	var err error
Dialing:
	// We expect a rare mismatch, but probably not 5 in a row.
	for i := 0; i < 5; i++ {
		tooSlow := time.NewTimer(1 * time.Second)
		defer tooSlow.Stop()
		var c1 net.Conn
		c1, err = net.Dial(addr.Network(), addr.String())
		if err != nil {
			if runtime.GOOS == "dragonfly" && (isConnRefused(err) || os.IsTimeout(err)) {
				// golang.org/issue/29583: Dragonfly sometimes returns a spurious
				// ECONNREFUSED or ETIMEDOUT.
				<-tooSlow.C
				continue
			}
			t.Fatalf("localPipe: %v", err)
		}
		if localFlakes == 2 && i == 0 {
			c1.Close()
			continue
		}
		for {
			select {
			case <-tooSlow.C:
				t.Logf("localPipe: timeout waiting for %v", c1.LocalAddr())
				c1.Close()
				continue Dialing

			case c2 := <-localListener.ch:
				if c2.RemoteAddr().String() == c1.LocalAddr().String() {
					t.Cleanup(func() { c1.Close() })
					t.Cleanup(func() { c2.Close() })
					return c1, c2
				}
				t.Logf("localPipe: unexpected connection: %v != %v", c2.RemoteAddr(), c1.LocalAddr())
				c2.Close()
			}
		}
	}

	t.Fatalf("localPipe: failed to connect: %v", err)
	panic("unreachable")
}

// zeroSource is an io.Reader that returns an unlimited number of zero bytes.
type zeroSource struct{}

func (zeroSource) Read(b []byte) (n int, err error) {
	clear(b)
	return len(b), nil
}

func allCipherSuites() []uint16 {
	ids := make([]uint16, len(cipherSuites))
	for i, suite := range cipherSuites {
		ids[i] = suite.id
	}

	return ids
}

var testConfig *Config

func TestMain(m *testing.M) {
	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "Usage of %s:\n", os.Args)
		flag.PrintDefaults()
		if *bogoMode {
			os.Exit(89)
		}
	}

	flag.Parse()

	if *bogoMode {
		bogoShim()
		os.Exit(0)
	}

	os.Exit(runMain(m))
}

func runMain(m *testing.M) int {
	// Cipher suites preferences change based on the architecture. Force them to
	// the version without AES acceleration for test consistency.
	hasAESGCMHardwareSupport = false

	// Set up localPipe.
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		l, err = net.Listen("tcp6", "[::1]:0")
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to open local listener: %v", err)
		os.Exit(1)
	}
	localListener.ch = make(chan net.Conn)
	localListener.addr = l.Addr()
	defer l.Close()
	go localServer(l)

	if err := checkOpenSSLVersion(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v", err)
		os.Exit(1)
	}

	testConfig = &Config{
		Time:               func() time.Time { return time.Unix(0, 0) },
		Rand:               zeroSource{},
		Certificates:       make([]Certificate, 2),
		InsecureSkipVerify: true,
		CipherSuites:       allCipherSuites(),
		CurvePreferences:   []CurveID{X25519, CurveP256, CurveP384, CurveP521},
		MinVersion:         VersionTLS10,
		MaxVersion:         VersionTLS13,
	}
	testConfig.Certificates[0].Certificate = [][]byte{testRSACertificate}
	testConfig.Certificates[0].PrivateKey = testRSAPrivateKey
	testConfig.Certificates[1].Certificate = [][]byte{testSNICertificate}
	testConfig.Certificates[1].PrivateKey = testRSAPrivateKey
	testConfig.BuildNameToCertificate()
	if *keyFile != "" {
		f, err := os.OpenFile(*keyFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			panic("failed to open -keylog file: " + err.Error())
		}
		testConfig.KeyLogWriter = f
		defer f.Close()
	}

	return m.Run()
}

func testHandshake(t *testing.T, clientConfig, serverConfig *Config) (serverState, clientState ConnectionState, err error) {
	const sentinel = "SENTINEL\n"
	c, s := localPipe(t)
	errChan := make(chan error, 1)
	go func() {
		cli := Client(c, clientConfig)
		err := cli.Handshake()
		if err != nil {
			errChan <- fmt.Errorf("client: %v", err)
			c.Close()
			return
		}
		defer func() { errChan <- nil }()
		clientState = cli.ConnectionState()
		buf, err := io.ReadAll(cli)
		if err != nil {
			t.Errorf("failed to call cli.Read: %v", err)
		}
		if got := string(buf); got != sentinel {
			t.Errorf("read %q from TLS connection, but expected %q", got, sentinel)
		}
		// We discard the error because after ReadAll returns the server must
		// have already closed the connection. Sending data (the closeNotify
		// alert) can cause a reset, that will make Close return an error.
		cli.Close()
	}()
	server := Server(s, serverConfig)
	err = server.Handshake()
	if err == nil {
		serverState = server.ConnectionState()
		if _, err := io.WriteString(server, sentinel); err != nil {
			t.Errorf("failed to call server.Write: %v", err)
		}
		if err := server.Close(); err != nil {
			t.Errorf("failed to call server.Close: %v", err)
		}
	} else {
		err = fmt.Errorf("server: %v", err)
		s.Close()
	}
	err = errors.Join(err, <-errChan)
	return
}

func fromHex(s string) []byte {
	b, _ := hex.DecodeString(s)
	return b
}

// testTime is 2016-10-20T17:32:09.000Z, which is within the validity period of
// [testRSACertificate], [testRSACertificateIssuer], [testRSA2048Certificate],
// [testRSA2048CertificateIssuer], and [testECDSACertificate].
var testTime = func() time.Time { return time.Unix(1476984729, 0) }

var testRSACertificate = fromHex("3082024b308201b4a003020102020900e8f09d3fe25beaa6300d06092a864886f70d01010b0500301f310b3009060355040a1302476f3110300e06035504031307476f20526f6f74301e170d3136303130313030303030305a170d3235303130313030303030305a301a310b3009060355040a1302476f310b300906035504031302476f30819f300d06092a864886f70d010101050003818d0030818902818100db467d932e12270648bc062821ab7ec4b6a25dfe1e5245887a3647a5080d92425bc281c0be97799840fb4f6d14fd2b138bc2a52e67d8d4099ed62238b74a0b74732bc234f1d193e596d9747bf3589f6c613cc0b041d4d92b2b2423775b1c3bbd755dce2054cfa163871d1e24c4f31d1a508baab61443ed97a77562f414c852d70203010001a38193308190300e0603551d0f0101ff0404030205a0301d0603551d250416301406082b0601050507030106082b06010505070302300c0603551d130101ff0402300030190603551d0e041204109f91161f43433e49a6de6db680d79f60301b0603551d230414301280104813494d137e1631bba301d5acab6e7b30190603551d1104123010820e6578616d706c652e676f6c616e67300d06092a864886f70d01010b0500038181009d30cc402b5b50a061cbbae55358e1ed8328a9581aa938a495a1ac315a1a84663d43d32dd90bf297dfd320643892243a00bccf9c7db74020015faad3166109a276fd13c3cce10c5ceeb18782f16c04ed73bbb343778d0c1cf10fa1d8408361c94c722b9daedb4606064df4c1b33ec0d1bd42d4dbfe3d1360845c21d33be9fae7")

var testRSACertificateIssuer = fromHex("3082021930820182a003020102020900ca5e4e811a965964300d06092a864886f70d01010b0500301f310b3009060355040a1302476f3110300e06035504031307476f20526f6f74301e170d3136303130313030303030305a170d3235303130313030303030305a301f310b3009060355040a1302476f3110300e06035504031307476f20526f6f7430819f300d06092a864886f70d010101050003818d0030818902818100d667b378bb22f34143b6cd2008236abefaf2852adf3ab05e01329e2c14834f5105df3f3073f99dab5442d45ee5f8f57b0111c8cb682fbb719a86944eebfffef3406206d898b8c1b1887797c9c5006547bb8f00e694b7a063f10839f269f2c34fff7a1f4b21fbcd6bfdfb13ac792d1d11f277b5c5b48600992203059f2a8f8cc50203010001a35d305b300e0603551d0f0101ff040403020204301d0603551d250416301406082b0601050507030106082b06010505070302300f0603551d130101ff040530030101ff30190603551d0e041204104813494d137e1631bba301d5acab6e7b300d06092a864886f70d01010b050003818100c1154b4bab5266221f293766ae4138899bd4c5e36b13cee670ceeaa4cbdf4f6679017e2fe649765af545749fe4249418a56bd38a04b81e261f5ce86b8d5c65413156a50d12449554748c59a30c515bc36a59d38bddf51173e899820b282e40aa78c806526fd184fb6b4cf186ec728edffa585440d2b3225325f7ab580e87dd76")

var testRSA2048Certificate = fromHex("30820316308201fea003020102020900e8f09d3fe25beaa6300d06092a864886f70d01010b0500301f310b3009060355040a1302476f3110300e06035504031307476f20526f6f74301e170d3136303130313030303030305a170d3338303130313030303030305a301a310b3009060355040a1302476f310b300906035504031302476f30820122300d06092a864886f70d01010105000382010f003082010a0282010100e0ac47db9ba1b7f98a996c62dc1d248d4ee570544136fe4e911e22fccc0fe2b20982f3c4cdd8f4065c5068c873ca0a768b80dc915edc66541a5f26cdea44e56e411221e2f9927bf4e009fee76dbe0e118dcc13392efd6f42d8eb2fd5bc8f63ac77800c84d3be90c20c321273254b9137ef61f825dad1ec2c5e75aa4be6d3104899bd5ac400da7ab942b4227a3870ae5bb97870aa09a1082fb8e78b944cd7fd1b0c6fb1cce03b5430b12ef9ce2d95e01821766e998df0cc99202a57cf030577bd2dc0ec85a49f203511bb6f0e9f43398ead0958f8d7534c61e81daf4501faaa68d9cbc725b58401900fa48a3e2333b15c88cf0c5cc8f33fb9464f9d5f5768b8f10203010001a35a3058300e0603551d0f0101ff0404030205a0301d0603551d250416301406082b0601050507030106082b06010505070302300c0603551d130101ff0402300030190603551d1104123010820e6578616d706c652e676f6c616e67300d06092a864886f70d01010b050003820101009e83f835e2da08204ee6f8bdca793cf83c7aec175349c1642dfbe9f4d0dcfb1aedb4d0122e16c2ad92e63dd31cce10ca5dd04be48cded0fdc8fea49e891d9d93e778a67d54b619ac167ce7bb0f6000ca00c5677d09df3eb10080134ba32bfe4132d33954dc479cb266288d53d3f43af9c78c0ca59d396498bdc56d4966dc6b7e49081f7f2ae1d704bb9f9effed93c57d3b738da02edff3999e3f1a5dce2b093951947d233d9c6b6a12b4b1611826aa02544980089eebbcf22a1a96bd35a3ddf638578989334a93d5081fab442b4383ba6213b7cdd74110582244a2abd937828b311d8dd69178756db7874293b9810c5c2e833f91d49d283a62caaf359141997f")

var testRSA2048CertificateIssuer = fromHex("308203223082020aa003020102020900ca5e4e811a965964300d06092a864886f70d01010b0500301f310b3009060355040a1302476f3110300e06035504031307476f20526f6f74301e170d3136303130313030303030305a170d3235303130313030303030305a301f310b3009060355040a1302476f3110300e06035504031307476f20526f6f7430820122300d06092a864886f70d01010105000382010f003082010a0282010100b308c1720c7054abe66e1be6f8a11246808215a810e8936e47601f7ec1afeb02ad69a5000959d4e08ebc4455ef90b39616f380b8ff2e76f29942d7e009cf010824fe56f69140ac39b761595255ec2aa35155ca2eea884f57b25f8a52f41f56f65b0197cb6c637f9adfa97d8ac27565449f64e67f8b918646ffd630601b0badd8d38aea421fe413ee94f10ea5874c2fd6d8c1b9febaa5ca0ce759993a232c9c48e52230bbf58777b0c30e07e9e0914133730d844b9887b950d5a17c779ac69de2d9c65d26f1ea46c7dd7ac636af6d77df7c9218f78c7b5f08b025867f343ac66cd43a657ac44bfd7e9d07e95a22ff9a0babf72dcffc66eba0a1d90731f67e3bbd0203010001a361305f300e0603551d0f0101ff040403020204301d0603551d250416301406082b0601050507030106082b06010505070302300f0603551d130101ff040530030101ff301d0603551d0e0416041460145a6ce2e8a15b1b68db9a4752ce8684d6ba2d300d06092a864886f70d01010b050003820101001d342fe0b50a25d57a8b13bc14d0abb1eea7431ee752aa423e1306654183e44e9d48bbf592cd32ce77310fdc4e8bbcd724fc43d2723f454bfe605ff90d38d8c6fe60b36c6f4d2d7e4e79bceeb2484f0565274b0d0c4a8562370677624a4c133e332a9e63d4b47544c14e4908ee8685dd0760ae6f4ab089ede2b0cdc595ecefbee7d8be80d57b2d4e4510b6ceda54d1a5980540214191d81cc89a983da43d4043f8efe97a2e231c5153bded520acce87ec8c64a3408f0eb4c742c4a877e8b5b7b7f72497734a41a95994a7a103262ea6d598d03fd5cb0579ed4702424da8893334c58215bc655d49656aedcd02d18676f45d6b9469ae04b89abe9b358391cce99")

var testRSA2048PrivateKey, _ = x509.ParsePKCS1PrivateKey(fromHex("308204a40201000282010100e0ac47db9ba1b7f98a996c62dc1d248d4ee570544136fe4e911e22fccc0fe2b20982f3c4cdd8f4065c5068c873ca0a768b80dc915edc66541a5f26cdea44e56e411221e2f9927bf4e009fee76dbe0e118dcc13392efd6f42d8eb2fd5bc8f63ac77800c84d3be90c20c321273254b9137ef61f825dad1ec2c5e75aa4be6d3104899bd5ac400da7ab942b4227a3870ae5bb97870aa09a1082fb8e78b944cd7fd1b0c6fb1cce03b5430b12ef9ce2d95e01821766e998df0cc99202a57cf030577bd2dc0ec85a49f203511bb6f0e9f43398ead0958f8d7534c61e81daf4501faaa68d9cbc725b58401900fa48a3e2333b15c88cf0c5cc8f33fb9464f9d5f5768b8f10203010001028201007aac96efca229b199e1bf79a63256677e1c455792bc2a348b2e409a68ea57dda486740430d4290bb885c3f5a741eb567d4f41f7b2098a726f4df4f88cf899edc7c9b31f584dffedece15a7212642c7dbbdd8d806392a183e1fc30af36169c9bab9e528f0bdcd27ad4c8b6a97849da6452c6809de61848db80c3ba3289e785042cdfd46fbfee5f78adcba2927fcd8cbe9dcaa97190457eaa45d77adbe0db820aff0c8511d837ab5b307bad5f85afd2cc70d9659ec58045d97ced1eb7950670ac559449c0305fddefda1bac88d36629a177f65abad182c6470830b39e7f6dbdef4df813ccaef01d5a42d37213b2b9647e2ff56a63e6b6a4b6e8a1567bbfd77042102818100eb66f205e8507c78f7167dbef3ddf02fde6a67bd15152609e9296576e28c79678177145ae98e0a2fee58fdb3d626fb6beae3e0ae0b76bc47d16fcdeb16f0caca8a0902779979382609705ae84514de480c2fb2ddda3049347cc1bde9f1a359747079ef3dce020a3c186c90e63bc20b5489a40d768b1c1c35c679edc5662e18c702818100f454ffff95b126b55cb13b68a3841600fc0bc69ff4064f7ceb122495fa972fdb05ca2fa1c6e2e84432f81c96875ab12226e8ce92ba808c4f6325f27ce058791f05db96e623687d3cfc198e748a07521a8c7ee9e7e8faf95b0985be82b867a49f7d5d50fac3881d2c39dedfdbca3ebe847b859c9864cf7a543e4688f5a60118870281806cee737ac65950704daeebbb8c701c709a54d4f28baa00b33f6137a1bf0e5033d4963d2620c3e8f4eb2fe51eee2f95d3079c31e1784e96ac093fdaa33a376d3032961ebd27990fa192669abab715041385082196461c6813d0d37ac5a25afbcf452937cb7ae438c63c6b28d651bae6b1550c446aa1cefd42e9388d0df6cdc80b02818100cac172c33504923bb494fad8e5c0a9c5dd63244bfe63f238969632b82700a95cd71c2694d887d9f92656d0da75ae640a1441e392cda3f94bb3da7cb4f6335527d2639c809467946e34423cfe26c0d6786398ba20922d1b1a59f79bd5bc937d8040b75c890c13fb298548977a3c05ff71cf535c54f66b5a77684a7e4363a3cb2702818100a4d782f35d5a07f9c1f8f9c378564b220387d1e481cc856b631de7637d8bb77c851db070122050ac230dc6e45edf4523471c717c1cb86a36b2fd3358fae349d51be54d71d7dbeaa6af668323e2b51933f0b8488aa12723e0f32207068b4aa64ed54bcef4acbbbe35b92802faba7ed45ae52bef8313d9ef4393ccc5cf868ddbf8"))

// testRSAPSSCertificate has signatureAlgorithm rsassaPss, but subjectPublicKeyInfo
// algorithm rsaEncryption, for use with the rsa_pss_rsae_* SignatureSchemes.
// See also TestRSAPSSKeyError. testRSAPSSCertificate is self-signed.
var testRSAPSSCertificate = fromHex("308202583082018da003020102021100f29926eb87ea8a0db9fcc247347c11b0304106092a864886f70d01010a3034a00f300d06096086480165030402010500a11c301a06092a864886f70d010108300d06096086480165030402010500a20302012030123110300e060355040a130741636d6520436f301e170d3137313132333136313631305a170d3138313132333136313631305a30123110300e060355040a130741636d6520436f30819f300d06092a864886f70d010101050003818d0030818902818100db467d932e12270648bc062821ab7ec4b6a25dfe1e5245887a3647a5080d92425bc281c0be97799840fb4f6d14fd2b138bc2a52e67d8d4099ed62238b74a0b74732bc234f1d193e596d9747bf3589f6c613cc0b041d4d92b2b2423775b1c3bbd755dce2054cfa163871d1e24c4f31d1a508baab61443ed97a77562f414c852d70203010001a3463044300e0603551d0f0101ff0404030205a030130603551d25040c300a06082b06010505070301300c0603551d130101ff04023000300f0603551d110408300687047f000001304106092a864886f70d01010a3034a00f300d06096086480165030402010500a11c301a06092a864886f70d010108300d06096086480165030402010500a20302012003818100cdac4ef2ce5f8d79881042707f7cbf1b5a8a00ef19154b40151771006cd41626e5496d56da0c1a139fd84695593cb67f87765e18aa03ea067522dd78d2a589b8c92364e12838ce346c6e067b51f1a7e6f4b37ffab13f1411896679d18e880e0ba09e302ac067efca460288e9538122692297ad8093d4f7dd701424d7700a46a1")

var testECDSACertificate = fromHex("3082020030820162020900b8bf2d47a0d2ebf4300906072a8648ce3d04013045310b3009060355040613024155311330110603550408130a536f6d652d53746174653121301f060355040a1318496e7465726e6574205769646769747320507479204c7464301e170d3132313132323135303633325a170d3232313132303135303633325a3045310b3009060355040613024155311330110603550408130a536f6d652d53746174653121301f060355040a1318496e7465726e6574205769646769747320507479204c746430819b301006072a8648ce3d020106052b81040023038186000400c4a1edbe98f90b4873367ec316561122f23d53c33b4d213dcd6b75e6f6b0dc9adf26c1bcb287f072327cb3642f1c90bcea6823107efee325c0483a69e0286dd33700ef0462dd0da09c706283d881d36431aa9e9731bd96b068c09b23de76643f1a5c7fe9120e5858b65f70dd9bd8ead5d7f5d5ccb9b69f30665b669a20e227e5bffe3b300906072a8648ce3d040103818c0030818802420188a24febe245c5487d1bacf5ed989dae4770c05e1bb62fbdf1b64db76140d311a2ceee0b7e927eff769dc33b7ea53fcefa10e259ec472d7cacda4e970e15a06fd00242014dfcbe67139c2d050ebd3fa38c25c13313830d9406bbd4377af6ec7ac9862eddd711697f857c56defb31782be4c7780daecbbe9e4e3624317b6a0f399512078f2a")

var testEd25519Certificate = fromHex("3082012e3081e1a00302010202100f431c425793941de987e4f1ad15005d300506032b657030123110300e060355040a130741636d6520436f301e170d3139303531363231333830315a170d3230303531353231333830315a30123110300e060355040a130741636d6520436f302a300506032b65700321003fe2152ee6e3ef3f4e854a7577a3649eede0bf842ccc92268ffa6f3483aaec8fa34d304b300e0603551d0f0101ff0404030205a030130603551d25040c300a06082b06010505070301300c0603551d130101ff0402300030160603551d11040f300d820b6578616d706c652e636f6d300506032b65700341006344ed9cc4be5324539fd2108d9fe82108909539e50dc155ff2c16b71dfcab7d4dd4e09313d0a942e0b66bfe5d6748d79f50bc6ccd4b03837cf20858cdaccf0c")

var testEDMLDSACertificate = fromHex("30821630308208cba003020102021100fc58cfe3bf8bdc57b2c7760ac081f9db300b060960864801650304031130123110300e060355040a130741636d6520436f301e170d3131303130313135303430355a170d3132303130313135303430355a30123110300e060355040a130741636d6520436f308207ea300a06082a864883a8310103038207da00ad2c095759e30cd933b420608e39f635836233d2b9bd982a77b591c771d973d7b978010a4ab2cff087527f632cddefaeb9b5c3cc206fc24baa196be93de92f7034d2eab99e1d1d854a64721d3dcec90ff8e951b1b86e67b3a14057ff2d8cc64eeaed0d965d12c356d79421034e928c0f3c361163160a69aae55276b78af104e397cdb49326570d2c799e00ebd3a3f1294c618d270c8c703a5fb713f0db55e0416dc88705ea4f823899ba2903238fc6dc2d413d1e4b742629045ec18b3781bbf57cfd17250865e99eb3a186280391d0fa9b2986af7857f4f52e222d67c2756aca11664ced1760790b3d08564ff89f65a5022e46bc6c238d50e9fa98720e1f6a8b27dbbb3cc529438146e5872b22529cbfd1c41f7c8438f11b5ff8a693349080f4a0c83aa5569a6e75ce2ad529fe2718374160e329c708917d8bf428ced148d244725a3b3a040e90711cca7598a9365b0ae6d19535d5dacdccb06d7e63c4d845def61bb3d15ea80d44b19c33ce1df0fa81f73006b714354906f0be883c622ba7a553629ef8b9c4bf54f96fc9e64e46af10f2f03c23ed99a4ceed213e21b19f27b124d44d4e9d738d2576a823030670dd77a45876a9be845ee7d0b74f5839637287363ee4c9aaea30840708220adc8e4ea03bee2bdbdd9bad5bdf5e478335897a968699525145bc87c5bdc36a8252b3f6f6b115a5b0870ee7bc8d5bbf33df5ab0458e3a918d6d9f0b4f0422bbfa750e380164b00cd4d6c5f8819e9c71dd9a976f1ace91bf259355ea15b1ba5f1d352c6e5ba4e279bb9b09ac13e10643e0077f9e4e581dbba4406e7d7ec9781939bd30d677a9eaea15995124a865336e3587bd75c715fe471a0d69acfe0e3018dbc61c6adeb0ecd846003cc5205c5405f76aeffd9dbc25457c25ea0ef1c06b99438eaa8b156da61253d5ca2413a86f33d1baa05e54a856d743631fc2248f6055e93d5074d6cc1c58ec41f6a57b1a3bcfbb7a4dc594438d6fa82156946b2e11a8c4be68cd98d95d3f029403c5d4c42ae13c4edec5239323d30a63857fd01010c34a3f776bb22c53f12e622bb215ab431f7e1f957edacc172a749e3921c2e39431caec0654ba416b6a1740f7ca56ae4198f25c0ae5fd748d19a5132f884c45a6c1772dde2121170fc102150a8f0b29763994a981a5ceaf4cf7e1d46ff4f68007511c8f35f64f29919edcf559b469c5c372191b8b741b27fae7818c85047a7d3e7cc14c6d45cf49bbab1b1c1730b7b9edde50e7997cdd4c3ebc884dddb09b349c61451ac6d1705a81f74df2328c64025eea710c7bec24c71783f58bb2e61cd29ea44948ff37399d8d472f39657ad742f3e9a8dd3264192ad2a691984c07902b414b3591c5f0ef21fb2737bbda992e9b0e956de072e255e137912df710b55fd16614ceb5c494fe3918617fcc19683179816a037538a11b3950a23f3593ade2f2e53f732deddbeb42cfeecfcb653d9cdd001a5fc7b700e3a053be905a633137961e0e3add6f69878d536bdabe9252a14482401b6657fddd5c019cbd0c997c9e8b1b2e8e6d43c5bd8537283f1662c4ef7610ba27f5839da9288d39636a6302bc644760ee6a4fafa7dfe7b6a6c5629b83fad911e3a9fd8e354768f16dc69962570b4ef7453580afa8dffffd643028efc253642fe0102c6d800f2066e1b88a77f470cca9545554e1223417dad459c7453fe56cfb3a3d8cebbbdb31e6937d1628fbe34b46469f89b51932a647bc40c626e39429a50d6e204501daadf2dc5b79e268524152b39fae05f0c0e31a2f0e074b0589320d77f580d8b61f4daf8bacc996c908410f4b3b12856da5bbc2d33afbce1a1348942992df19f579bf9ecd059740200d6518688e5adeb4697c93e67c8cf4756797d38adf9cdbec01e30baa3f36d6305cc5802cbe4bad8a40f77f5498d5d93494cbf82bf06f4cca327643748b77858bb05560659d065f8b6fb5f634948d0dbfc77b2dc8852021686eef7896492d1d125cd7f66e9c59ed579fb9780049b0c8bb9d86a928f11b09576b5b3b5b7c0bece7a6abcf88d4079569cf7cc895a58a114384af79308e793bbcb4675dbf7077a0d13b7721273e56086b01a76b4c7d567205c5db0ecc62e40aa8b9725086a8759aac3023943ee454177450aa590e5586cdbac1ed2540fd69e2553865884080a773d84bdd40528757801eaac942cf81daf2c128377f814c7b19893644884d9ec8c431f390fe427fb77c3d147c4a9a41e05419dbfcc3d258da8c6cd7e55f6aff1ba2653746cddc3a0cabb3bf6f18f261678953c6c0441565d209f23a2205dccabd39e44b7904a2d178e4702c2cf0deaea09d9d7b95be8d3d5e95d487ff0df9ab9a4ba2cf4d17eda51a3f7eec035ce5b056e1a66582bb5ed56e53e8316bec72d67bfc445f0a9f1d395a57b7ef82d22ca30a0cb41211e84fcaa2e579f47151d29231b87820af0d4b7221a57858c3f0fcd863145c40480a2ac0f848fdeeff75549077dc4646637b3e23152fefa9d09df5e579fb3ede7fbc058bf8c893f9fd562118e6a07c0581db3e4a29b91e13929083273195e96403ddd7e89c298880f18706dbacf2bac22910deb4b514c8617571db06d4b321788e6f32f81789fa1fc76724f312ca6d92e4b47e2d0217570ca7e3b27a718133cd1caa351400f4f3a946bb2a35689a14db74d625cf6c469aa4905576aef793dfdc0293d875fd6312ce7dbd16106b8f6c127f907e091e613b37edeb95d192f0401c0f1df6a2095ffd0039270980cbbc61241492ac06b96b72fced2e828fce9d0e1ce008bd905940bf4cf0dc4508b70fd04b1024908c2df2029a3308d5de6d85f900a36e306c300e0603551d0f0101ff04040302028430130603551d25040c300a06082b06010505070301300f0603551d130101ff040530030101ff301d0603551d0e0416041437cbeddb4b46d6a17bc4cd06f53938782be9e4c030150603551d11040e300c820a676f6f676c652e636f6d300b060960864801650304031103820d500080d8c865a27aaf0bdc876ad0153a39041ca33692e2a97f45ebf53057c07c3cfd8194212fc080f1e8db0126be07db8eb207d9704f0247fa49b6207dcf8469f1d9714803e71a3d28ea0d8b337747f8ab258e67e33a4abe9700023fc9f42941a4f65c06e69505168d58428784b6c981aeb83234101f7eda8f1be7be1442dd5ccdfa61f17cc8028d0dc17110fa6a6e421b0c8fc74dde0e86cb14f769076bc3f4419187222134fa1b0e79dfb38bb94d0048b3e4ce22f517056618ecb4192aad20e77842163ed4b75448110ef60ee56b2e18f53b670a4e21a21488f4dd567eaef2e1b8faf25673761bb6cb7ea00073b3cd8baadddfe69c08cb18d29271435efeda24cde01fdd666c98cb573fa5ddd7eacd129823c669c8e0947bcf13daa42dd400943b43232ffd896832c68bc0832881cd4a21f450b26e742d1329ff3d5dbc7ae0a56561ded2908600c528437030861923970819b4b19ef894caf64b5e21afe2ef2b4376058ab2db2eada34e0ee0d4673cb70cf974192beeb4ffbd9426ba8ac0f10f9485eb850b82a648169c9a784f0dc00aafc56acd013b519ff985473432a9b3aa7e6c09dd093aa6940306a0b7f8e1d48494e2ba13ef0746a3fdcdc24792b2bfe03565d7315afdb2a2f423198911f33833f83e97e1a46ebb804fc1f27e294b38cabcd058a9a6ff5edd129ce09e7d544a22967703248a83ac7bb701542509b762fd2ee6fd30f8d41c5b4bbb74285c47f0fcae07df96ba38a50cc34e6a6a7d9140de227e03bb6428446caa82ca63647d9568aee4bba4f0d6c1cf5a030fd32c5762e9fd91b949d282a4293fd2cf8065f730d926a04ec6c8d2c038ae9c7a0047f34cbe05cdb5e40fffaa9b284ba2c975e2c73e89b8a97813012414b6ccd9fc89001f266e160668f78f56bbd1818dd5a90e040ca29dfe50c0e558ba8681cfc143ccc8457d4e23aac8285217bb24797cf99e18e6fd8ef46fd199158553ce8350ce9fcdda6eb2024e360b11540dd939d1d0a3ff89c3030b119af6ac24f09e1f7ab45991943a02ab68b7a6e6164e4831f071a67dc2d019d7d32f37f3edb32c1ebfe6db6a0bb39cad3b8da50e5933f14e450aee0441f97c3881271f0b12c7e83f2f2a0875823c32f2fc667098a6cb2414c1529898d6d5ef5c60ad76daa3519367ee16a6eb0956cac77860f570b2eaf405b2307b18866408e0663a08b62f9e43ea6763aa87f9d6b34b6f3e5bb794e6e0ba4f3778bc421017dfc2c666ee04349fb41c681c5fc25ce903aa538d151708c79a4b07f8621b87057cd1b368142149467b22dfa93744f7320504e731a641e25a714bfff3303a9c8a5ab11d8cbfb012d81f50f6bd160cc73a9067d8bf8276be6abf0255351b84f53345fbcbe31bd4c6eb364128d535ebf3b0770001c7e8dad2e1e15f98d9251f12a54f2b9ee9de24602c3a3a02917ddce171541dbe5f62cd0b906b587eb5fba759009d9053ee6a46972924eaf6ab84a8254d0a9d42a05e04dfcddb4bc88def495a2a3f4491bace1fdeb6624383786f42057aaaade2b3711272ffc5039c7438f6774d9b326b0f26709256f1df7b4417d94f75b38e037e9234113ad8393a84df31163ecd7a2eb6a8bddbb93f09e5d5de7e6a3f6175d4c18f520075c0896f964355811bb9e7a3b5c610af5f22eb2f7ad5ce4ece130333ce724aeaa0d58e73945a4b185be2ebcfcbb6f36736d76ef55cfe3d83ce84033beb78d8228e2ae0932bf0dc503e30523aa5d52d6af8efb162a30fcfe4f572b3341884dd6c74127f38ec9ec9e3f8cb8b60360c6b58616c33660655ef98418e5aedaae97e37f5e42ff0ef6549310f5b35c48e42ffc331d0f27216f9d4eedb9ce4f444e43752def10bcb2068e96630ff3a15f1d02679f34b51db149b9eccf159133c65ebcb2d47f8540784e4077b650c24e9aac5800e844cb273b806ad48e3fd86bf3507f7811ad93f0122b315c52b38d42c15c769a69c3089773be2a5208377deb42b193ca209322d3fd0432e870852b016ab9237b2bd0a04ecf6af06ccc73d6d073aa28f914a6bcef49f3bb543f73330a61d65d36159a85fd3217062c0e7787c597e375fc434b26986cae2299af3b50a5c3ab86101c47ef18905012bcd0719ba58b67443836c6122a8a43083953bcc199857c41c5fa2765c1ebde292dfb79c8c45ef1af48ddb5aa642d5f5982b2238d6ca0630b7dd2252d8b5785c327dbec281df0258a63b7c3071e4b3cff55eba72b5361071d068a79c64c7bcb4b796a2d224541888ea8d3db5155f454b7af302171df76bdb176a369d695d4abeaef2f47c2029614717ad13120b108aa9b50cb06f12934bb07ce36afafd4f973a78f393dd25f6d3e17fcb4b91f0b7f159de9d3bacd6873ad45ffafea1d6926eacb7cbd73890d43518cf06c0a99160034ef485834659daa45374e34cd6e7a953e34d64b1273f1c09f65612a965b97332c9d3a80d30734f64ca1b937b82687a32ec289e6493a23c4fe2af5dd05b038d1a4f0012c0edc5b6641bb6b428db6430d93a70d2b91515c5aef5e1ae0c7deecbcdffa90da4d310dd0d0b02badc10f37ba119e1b91c7de8b69f8dd001d5ac6eabc1a6c0b57ac86963cc4f18be02fa1e6d029c5203e5ee6ccb47cdf4f63a9ee5fb7db718c11901af1d1c1671934171f806fa285086edc34c93957ca1ef1e3dc9ea06bb1d1b368f8d10ef62836d1e80a35ff6f84fb5082c6a3fe3850df3dd573629186a0cb352a8ea996c38f27fd2c3850e61dcdec6081db8aa38ddd22801164088fc3a26a25f0b65bacd6842968aa1791d9f945e8fdc75b2a75e1ef4391a54946ac9cc6bee60c476399b42aeb941ace378fbf3d0ee79e1754818fede812e680a1ed22282cd3494e690f4314aa54ef26874cfe9388cb9a31f4d6e94a66aa229e473f75b96f36fac50406739a4221caa54f367ba38d5e7aa4bdcb805af9b209449d601d172d0059cdf5bfd82f337e7f0cd22bf43c6dcbfda902448a9aa38ea7d07a24d2e5755511ef93915f2fa5fc29049d996c9278f917f3430d6f16e9f9ab325db83646491472a841e10d43234800cf7193b192add25b7c5cd3a03a3cd7a1d47b5f42e70b342c8c0552bfc803524af9e199f9758bf177be8e643ae5a1f3d65c4b9b0a73c8cfb2ee8debdf97e285e9bebed7e01115305b16444cbefe902c91a7771427ee21476db25ce5aec2d3330beb46d03efd188a4e2a7ed653c1117c33fc3ae5eb8018dda6826bcbf0823a2ddc637926720d5e7984c92a65485f21b8bfec0f7b0554799678cc83bfe841f764232d53efe4057ff487dbb757fe15513c005dacf94bd23312056abdec45194343092424835c04b3db4ca7d129f6720b0d30f7583fac9f5bbb8df56c521b29a105246b6571ac5ad2f8ec2e2716703996e637ba9b8bd74231a6206dcbad1a904989be9a28ab57a9c7038f18315fc49ab7f8691112525cdbde3b850763fcc2f56afff6c36207b84b9ef86ee2d38e6c595d0ec585caef636944c132dee30737561180cdfdfdac060526ce8841d774dce0dd4f9b2013df89ab92775a526dfefff931b526b2d34d6ab3a764cc27a0fc046a1432b2245f856f1b09c30ac400d9cc7a66bc10c54ad8b43f0446ff86b5793f090568d5a92d27ed28df97d7f12539c004c1ed011e5aac095f2d99f7e25211be12e30ecb0cee07ce2fbca09dd1395efe0cfa075aa36f547311689b91386e3fbd4dd1ae2d3336562fa73a9808e9cd3b16edbff0e9d4b610911321846a2e627dc7dee1453075e8a4e4f3bfb39ff089d5aa98f7be0615ac6d52d295e2c942d70db30a7ea73c867639e6094885c96b295c82ca7b9ff08704e30b80337acc2ec6e9b3abc3ae0a43cf889c0ebce066ca787d12e7ebcb66b845ad81133c8deafa5118ab29a3bb2b7c1cc7d7d888ed97d33dcbbadfa1f67ed71bd9d642a64fb8ed83495cca56e19f31979bbef249593e48d1dfe87c13cca9d57053464c706117fd139cf98f5ef3e7b0e103ecbf6aad4ae623f25ae0280e2321bd1c36cb4a49ec0c404ea1c7546aad46953dd31f53233d67f7f6dc10481efdbfd8ea76809e340998fe9d26365d02bf2cbd07ec95bbcf82b9a665a1fcea2c6d5885afbe18f7bb4573cf2b101b7b6eacf9a683ad54d797e8e9cd5b0cfb0ebf42e72a7168dc82ced7b204b09b11991c13f9b6cce7fa6e3d679f4564c5180271978f5a3bd68d5dbe9a82e57bc9b3d15a22da679236299f00ac035f99fe100fc81d9ecea65c635cbdddc017e0a2762246e67790261612d9eacc7f67e6a678b2567919053cff2185c08d19e875a960ceb014f820c9656a8d5cd8d1e30f63d36120bc6261cc6a89866703372f6bd30dc6e9429e779a9f890bc599b162b5a350df0188d00beb3fc7c4466b2dafb82e7d6198953bc8348f308d0349755ea46377f3151a4d054f8892ccd86f45620297a5b0d645b08ab763fc00467c3efb4a41bc55d32f778acab651c95f69eba85c92fb8a9fcd656edd728b62d077d56e09e26a9baf5f1ebeae80a4f59c0943b9d382ae250db20619c557ca600c4383e255355e68788e295afd1b77a5f2933373b5e9a9ca4c9074fb9ec09141a465c90d5edff495180a7c7d0093c3f4ba3e96381c3e90000000000000000000000000000000000090d161c2226bd10ae02b6e23220c3f608e7056b9caeaba85afa59998b1a6f07395fecbe7f9a38d3b5e04556eeacc7489b9fb6a492283570446c1b95732f80b734ec448ddb43b12d5122a7e32e74e644dffb8dd1a46d34c955128f7c8b025b7c1c2b93629687f06370671e44b8db0a9eae911cd721f33500")

var testSNICertificate = fromHex("0441883421114c81480804c430820237308201a0a003020102020900e8f09d3fe25beaa6300d06092a864886f70d01010b0500301f310b3009060355040a1302476f3110300e06035504031307476f20526f6f74301e170d3136303130313030303030305a170d3235303130313030303030305a3023310b3009060355040a1302476f311430120603550403130b736e69746573742e636f6d30819f300d06092a864886f70d010101050003818d0030818902818100db467d932e12270648bc062821ab7ec4b6a25dfe1e5245887a3647a5080d92425bc281c0be97799840fb4f6d14fd2b138bc2a52e67d8d4099ed62238b74a0b74732bc234f1d193e596d9747bf3589f6c613cc0b041d4d92b2b2423775b1c3bbd755dce2054cfa163871d1e24c4f31d1a508baab61443ed97a77562f414c852d70203010001a3773075300e0603551d0f0101ff0404030205a0301d0603551d250416301406082b0601050507030106082b06010505070302300c0603551d130101ff0402300030190603551d0e041204109f91161f43433e49a6de6db680d79f60301b0603551d230414301280104813494d137e1631bba301d5acab6e7b300d06092a864886f70d01010b0500038181007beeecff0230dbb2e7a334af65430b7116e09f327c3bbf918107fc9c66cb497493207ae9b4dbb045cb63d605ec1b5dd485bb69124d68fa298dc776699b47632fd6d73cab57042acb26f083c4087459bc5a3bb3ca4d878d7fe31016b7bc9a627438666566e3389bfaeebe6becc9a0093ceed18d0f9ac79d56f3a73f18188988ed")

var testP256Certificate = fromHex("308201693082010ea00302010202105012dc24e1124ade4f3e153326ff27bf300a06082a8648ce3d04030230123110300e060355040a130741636d6520436f301e170d3137303533313232343934375a170d3138303533313232343934375a30123110300e060355040a130741636d6520436f3059301306072a8648ce3d020106082a8648ce3d03010703420004c02c61c9b16283bbcc14956d886d79b358aa614596975f78cece787146abf74c2d5dc578c0992b4f3c631373479ebf3892efe53d21c4f4f1cc9a11c3536b7f75a3463044300e0603551d0f0101ff0404030205a030130603551d25040c300a06082b06010505070301300c0603551d130101ff04023000300f0603551d1104083006820474657374300a06082a8648ce3d0403020349003046022100963712d6226c7b2bef41512d47e1434131aaca3ba585d666c924df71ac0448b3022100f4d05c725064741aef125f243cdbccaa2a5d485927831f221c43023bd5ae471a")

var testRSAPrivateKey, _ = x509.ParsePKCS1PrivateKey(fromHex("3082025b02010002818100db467d932e12270648bc062821ab7ec4b6a25dfe1e5245887a3647a5080d92425bc281c0be97799840fb4f6d14fd2b138bc2a52e67d8d4099ed62238b74a0b74732bc234f1d193e596d9747bf3589f6c613cc0b041d4d92b2b2423775b1c3bbd755dce2054cfa163871d1e24c4f31d1a508baab61443ed97a77562f414c852d702030100010281800b07fbcf48b50f1388db34b016298b8217f2092a7c9a04f77db6775a3d1279b62ee9951f7e371e9de33f015aea80660760b3951dc589a9f925ed7de13e8f520e1ccbc7498ce78e7fab6d59582c2386cc07ed688212a576ff37833bd5943483b5554d15a0b9b4010ed9bf09f207e7e9805f649240ed6c1256ed75ab7cd56d9671024100fded810da442775f5923debae4ac758390a032a16598d62f059bb2e781a9c2f41bfa015c209f966513fe3bf5a58717cbdb385100de914f88d649b7d15309fa49024100dd10978c623463a1802c52f012cfa72ff5d901f25a2292446552c2568b1840e49a312e127217c2186615aae4fb6602a4f6ebf3f3d160f3b3ad04c592f65ae41f02400c69062ca781841a09de41ed7a6d9f54adc5d693a2c6847949d9e1358555c9ac6a8d9e71653ac77beb2d3abaf7bb1183aa14278956575dbebf525d0482fd72d90240560fe1900ba36dae3022115fd952f2399fb28e2975a1c3e3d0b679660bdcb356cc189d611cfdd6d87cd5aea45aa30a2082e8b51e94c2f3dd5d5c6036a8a615ed0240143993d80ece56f877cb80048335701eb0e608cc0c1ca8c2227b52edf8f1ac99c562f2541b5ce81f0515af1c5b4770dba53383964b4b725ff46fdec3d08907df"))

var testECDSAPrivateKey, _ = x509.ParseECPrivateKey(fromHex("3081dc0201010442019883e909ad0ac9ea3d33f9eae661f1785206970f8ca9a91672f1eedca7a8ef12bd6561bb246dda5df4b4d5e7e3a92649bc5d83a0bf92972e00e62067d0c7bd99d7a00706052b81040023a18189038186000400c4a1edbe98f90b4873367ec316561122f23d53c33b4d213dcd6b75e6f6b0dc9adf26c1bcb287f072327cb3642f1c90bcea6823107efee325c0483a69e0286dd33700ef0462dd0da09c706283d881d36431aa9e9731bd96b068c09b23de76643f1a5c7fe9120e5858b65f70dd9bd8ead5d7f5d5ccb9b69f30665b669a20e227e5bffe3b"))

var testP256PrivateKey, _ = x509.ParseECPrivateKey(fromHex("30770201010420012f3b52bc54c36ba3577ad45034e2e8efe1e6999851284cb848725cfe029991a00a06082a8648ce3d030107a14403420004c02c61c9b16283bbcc14956d886d79b358aa614596975f78cece787146abf74c2d5dc578c0992b4f3c631373479ebf3892efe53d21c4f4f1cc9a11c3536b7f75"))

var testEd25519PrivateKey = ed25519.PrivateKey(fromHex("3a884965e76b3f55e5faf9615458a92354894234de3ec9f684d46d55cebf3dc63fe2152ee6e3ef3f4e854a7577a3649eede0bf842ccc92268ffa6f3483aaec8f"))

var testEDMLDSAPrivateKey, _ = x509.ParsePKCS8PrivateKey(fromHex("30820fec020100300a06082a864883a831010304820fd9ad2c095759e30cd933b420608e39f635836233d2b9bd982a77b591c771d973d7c0b473484385a9dfb6abe4e63dbbfafcc00fff4eb5551326ac2c17faddbee58da4cb237fad395d7ff52577d09e5999e423f9e9d7b5454b133a66bbe27f760e9933881133678124084041550040664036382330516585453457584218562034148526220215551340734164813630376413264333613200350387713721277474743808373527017808230508348883448870368751433178553254702845378884227212010510775863863561121041433737881088328617457176037158233611245556432820515764316431086334165538406012543412822004008317732457520302676278733502304832842461072070721775334712236537531232711260134257577017362571586384383243716074655337228763470452287250045570867123785130381006366487871357788027762574673751860576527143032830455373035362516314334184177716033400387172138122477182482833808431550652743658580822813777465564570885274622123023480680736683602748450652723012822552630705337375850274385433334107635243252566750684082613556835606611543222173356607201126812850027561657461358810160262551426101613531271174371377211668431610227077501726702718287465705348765725063663002628856385681753634478884310340071587467845083867376621746704641213816533512830863116708115602184683240505386323647035177264552280683311582214180818085431842413675147700825447210238605153430321278453055024060016057466515125345075427021430334687746718262533083578087262426620818468085757273500261408188566834403225333475511758873135101260602213646344371675566760464660418445470237617277033312547846256110285300521283274403623004672464841772362423146365038784548383045072115338408687051163660776837227630205757316085187384436277085165804155746425836472172766614736065435167562684540865377563347277415084658225428836011262688616113740600287463842553108436345016456047644746451268500555888571758841123080112022774476488378238284887351317765478517046315245682115171531421147611562738771700022731564503137311036822572707202083500683005643604071234308418607186676202638601165222817007082650635527604338363146505888116704130288668203474121854227775082868612328438376488303585054062351437561838446580283880786711131825744562407626542033050144175888466047278703481628561588466860004317254264147743662420187321161481844648230377310047455654767528260851365658424228060440552031388724080303460042712451687021870057828420433560524177575500524814557675542318116675083125585374067337828373688468045512485053351270247138264147870118046106576608572230111018720552850864806831558143871246354018247444651731625655787235544603781578686524528828165885135202654086107674356605088532847614820570057760637781033467415876001283877034746330556518566685858832468188781812462835673150551433080351580835530433486433826277003533751505887134518743608532301373144053013424354171540254175400771430146860685381534725050374363340473853838003462054483531604442417118736556540128077287333280822225033047556535267342243207705267488151317658700177012165312607526866847108173467337211067472032580867317410168285711810366332780401356741360045035303176626325521115443817007618054236147868579379a06e59798455780a939002375e16296ff48c918b12c1e4821a9d258ead26e86ebf2cdf9280ca1cc92a3f898cf0732c544ce7bd01172b7c35f616d51de4d4bab13c4c5784c454b03c79c9000587c7e250855c960f54f78d510ff320224b5b25ae30b2606539b7f589b9212c20dd26648b0fce7527b541522aedda3cafaae9206b7e7426f2ab82672789b7c1a22cf8174c2ed062b72af5e7215d2ff74bb53cfafb3c395125c253eff98b50ab1143c757b3f596d1f05a68e96bae7b25ecf72ef974cb77170ad0af6ceda652b8b87553115503744207067d6e766921f2334bf965206924ac2ffcc2a1f8b4f55e94f26ef4a4b39cf97326336ac1cc660413061095d1dd43f1995efd8964c4af965f1bc90fda551eab8a53f529ea49c08d25a3ca8b300a22fc87d18047c0cee5b77a12a4b59ac94483e988ef4ad482ae065c9243412f793e9b4439e3c34a7fc82409991c3b7fd1cd5a1bcc960fcb8682241eb0192123b1edaa1c319bae2c672fdfba356816e5dfdf1ca67486ba94a163133c2681a308ab85ed9e67d73b0930775d97baa88edd752d8ddc083de87ce348d10386dbb87726cbad392b7a7a64ddfeffc4d487e0d4faba71de33a8f51ba09e061f7bcaa37e384b13a80227e8f8c94d63b86b9008bf523c4fd9b7d9d11e3805694ad228f7e1ae33d31082c11894494f47ac02cc4953ddc10df14ddb3ff9402b1bebcedca1dccbd450af117686b7e9a4ee6e6ff9dae0ffb539fe2b25a7d3b8e8a91ceca00f35d667aaec4838fb1a93e3d99e8c160c8a141bda08165a3b3a4a4413e23181e7b5ea2d07c9613bf463c3a763397d09a0dead8199032f24a16e39d13cdd70e9fe23517d0f9eff5f1474daa6103f46283edd0d68d9ac08e813d464a2677ee2f137196e472db57b3177844f0046e32ed02990f40da51debaac44f24b92494c9a1d19ae9f7b436898f9cf6682c41c6c8a657e8fe3feb21f30c07060200228c9c114b78516ce9633b3148aced0b3d18bf1bc4156df4bdb81e0b894b72df6379b7ac3540fbfed2075c869a827b2e1fd9f0be9394c5f93b8d61eb89bad8495959a720473f9b873534c2d49d82201cb9d5729c43f85a04667071a900f01ac0a81624fb48927046ba8de91e5d487172bec6fa7b57dd41e2bfdd7ada1d5b9d9086b0a3b59852a86e96ac3eaa483835eb7fad75593eb7ba7d91eb226900ff0ea17b3ed4da69d366ce2ae95a90afc93420db6f6fcf4047ecee5273a28d27c9da61e91603c3f770cf08b5fc3e0b11eae4915469d5950507ddf7ac27275ec02e800f73c962b3ff90e66b6415342efd05e01345d1d7be836973bb9fbd77009effa2bf3107345d5f2bcabde26f718c040bf80fcbe6129eab928181877343296424891c2dd026cbeb6d76d67ed7b0447675cf2de6333d4536017f47f0bf3f3ec63fa7ac7a7fa206a9030f2915109ae4e60d37f89a233b2843c74226070134ee95bd209c8cb4162287edbb40ac91abec56b02381f68366e6167a2b644ec72f8fd4e09260303b4394b885dca7169fbff4f21f940332869373f88917ed6b1cf83379c6567ee537401b98c43355a08955c25dad0e60f56a959f3c7f2e174e77cc88ab40c0fc6117576d884ad8c8f50bd794f81c7eaf4592250003b95d4842fe23111394a28e4acbe3fdc09988b5870c48617aebceec9a6a3ba4e75cff0ae7b8ec14e3f71a1f539a1e390af750dc75070ed4802454c35f41b5fe4384c418affdbb3650d7b8a04d5c7680496c4a0b963c192d36c1f6e15c75d477e7d64ba2beaab713d64982d6a0b938d3f24d21a9a73e5a75da4869c4b0690180ea046bab189974e0d152352c165afece857210672fdd0a5965d58d97ad3da8029a636e3984541328c0ff6caaf02324818336ef2bb5cdd7170e2a21c4a8e2950d6bf39b16f54335128cf2f791e6e1acc08e5032462a7f8fbf5e7932c3bfcbe7e2786abb93f2abc16577465aa804dea6aaac7ab7d25c0550fa39eeb252ea19f8b59b9ed985d0f9fc8c1d84d5132b52beaf40d46f060c23d2ad99ad7ec066bcb2aff43b30de9094a924d7161deaacf0564ff78cb4ef722b7399b11d90f88ee26d4de694d2d90e2de4979e7f71293bc3a36f2a6fd9998d9748ecac09d1978cd6c4e4a652302006de8f3f9e7fc39becc72112bf7c678c68c74f9a384bb3fbd25c1e076359d28b26b0d77d3236d0341ecc85997ed03dcc2f247391affde4daf399501928ffe910d50b7260a5376c4e1261de3bfdda3d828d183c70c8a43e5a6e51e681e6783fcf593e3547780cf283c52aa58312465528fcd73972e859e1a16abb660d079905dd1f111dbf2c922a6a3426153b0174bfc7fa89bf1788e7300b97a7b31e67c03a6ae99f9c76c6a2d8d9446c99410ce9a171762ca28e8c7b72d5dbd8927e29ea1afd883f5654cd3733b8edd04040f016fb825ea5f747ee586bc2a21ea706fc17a7493cef42e9d3a0c75d80d75954acc95da112488f1c95be3ea5bea2228f877994ea440b9d7adc8933b4a105285bbf8334d6043a630e7431f423d889e7238d7e6b26060a85ac173d90b47b144f5eed192f6e423d6acdf7c28c8e54f5aa7cd97534061f0cb9764ddb73d9c2e0aa90c3acfc8079d3128f6d2e1ff6d9e35515d69d9e0030cf71e4d743f76a8c3c29be08d25f6c51a2ac16ed7ceb2873b0a304385f0fc27a6ebc60a141f311a21be620c4cf98fdf3ec97a50bceb6b9df7f5decedd73c0fe9a81405a798b3cea1dabd03238582237b3526f12add4595bd97e852eb49e7491342129e16ea06e247dd5486d6fc332d06464f4951edb5cd39a1a765c896c5415bd57f8e6e662aa2bf587104bee1b0f829db419c9a79b07e1c0a7e9ffbe5354937cd43527e5e1fc94a36ae75bf4f8a5c3a9131c9210432c48137b9da2c08d4e4c816249bbc0befc3a3aeaadbed846a0f5600f596e76e76a31dfd829e06ae228d65168c0b484d9620a158d695c87614afd4e1d3e4d8aa095e702753ed6a7665d68e74c1fb1d09f4ccc25d218764d388d376d1bf233a61c486e5ef591cdbb8b0636a105a7589fcb978794154e16a07341bacfa8fead934a82236060ae270e747f850308052421c497b39f083f47bae2cb4a6c205737377f471354d306d3be56f534ae9e9b8e056e269c14f3eb1eaec3be4be5c2079279fa2c1dfb4eba42656a1bbbe8d1e214162f14a5319b86100b774d33d64ce1021bb8dc91670f8775667c590bc9f689ab46f76b2536060bbdafdada63c81e46cd254ce5e183eb93390695565e30abbe141c45b4b6225b7e613614a8c58cfb4aedc8b60b586173ea431cb5f5074af93365458ca4ef4acb0619b77e5cad9b2cec1c2f451a40c1d3545cf173fb4648a12c375a913c0f5adf4fded593d1c090642b8ddf6a7345a63610dc736ff60b8b69f0729185c1b41452697772ac0a164d053c0b9599e1f0493f6d120b9e79a7ad2096c6313a66c6cc4138eb6be6b55fb477de18fdfb81a096e3546a98b207c50744ddd92c49fe19c814d97ea7dcf17f4ce62ba221e494c2dc9175c7b3922efb4fb3d9991bda79f1c68953bec89e44686765aded1afeba5f0fa7fcbc7b2cdb1ac9ed"))

const clientCertificatePEM = `
-----BEGIN CERTIFICATE-----
MIIB7zCCAVigAwIBAgIQXBnBiWWDVW/cC8m5k5/pvDANBgkqhkiG9w0BAQsFADAS
MRAwDgYDVQQKEwdBY21lIENvMB4XDTE2MDgxNzIxNTIzMVoXDTE3MDgxNzIxNTIz
MVowEjEQMA4GA1UEChMHQWNtZSBDbzCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkC
gYEAum+qhr3Pv5/y71yUYHhv6BPy0ZZvzdkybiI3zkH5yl0prOEn2mGi7oHLEMff
NFiVhuk9GeZcJ3NgyI14AvQdpJgJoxlwaTwlYmYqqyIjxXuFOE8uCXMyp70+m63K
hAfmDzr/d8WdQYUAirab7rCkPy1MTOZCPrtRyN1IVPQMjkcCAwEAAaNGMEQwDgYD
VR0PAQH/BAQDAgWgMBMGA1UdJQQMMAoGCCsGAQUFBwMBMAwGA1UdEwEB/wQCMAAw
DwYDVR0RBAgwBocEfwAAATANBgkqhkiG9w0BAQsFAAOBgQBGq0Si+yhU+Fpn+GKU
8ZqyGJ7ysd4dfm92lam6512oFmyc9wnTN+RLKzZ8Aa1B0jLYw9KT+RBrjpW5LBeK
o0RIvFkTgxYEiKSBXCUNmAysEbEoVr4dzWFihAm/1oDGRY2CLLTYg5vbySK3KhIR
e/oCO8HJ/+rJnahJ05XX1Q7lNQ==
-----END CERTIFICATE-----`

var clientKeyPEM = testingKey(`
-----BEGIN RSA TESTING KEY-----
MIICXQIBAAKBgQC6b6qGvc+/n/LvXJRgeG/oE/LRlm/N2TJuIjfOQfnKXSms4Sfa
YaLugcsQx980WJWG6T0Z5lwnc2DIjXgC9B2kmAmjGXBpPCViZiqrIiPFe4U4Ty4J
czKnvT6brcqEB+YPOv93xZ1BhQCKtpvusKQ/LUxM5kI+u1HI3UhU9AyORwIDAQAB
AoGAEJZ03q4uuMb7b26WSQsOMeDsftdatT747LGgs3pNRkMJvTb/O7/qJjxoG+Mc
qeSj0TAZXp+PXXc3ikCECAc+R8rVMfWdmp903XgO/qYtmZGCorxAHEmR80SrfMXv
PJnznLQWc8U9nphQErR+tTESg7xWEzmFcPKwnZd1xg8ERYkCQQDTGtrFczlB2b/Z
9TjNMqUlMnTLIk/a/rPE2fLLmAYhK5sHnJdvDURaH2mF4nso0EGtENnTsh6LATnY
dkrxXGm9AkEA4hXHG2q3MnhgK1Z5hjv+Fnqd+8bcbII9WW4flFs15EKoMgS1w/PJ
zbsySaSy5IVS8XeShmT9+3lrleed4sy+UwJBAJOOAbxhfXP5r4+5R6ql66jES75w
jUCVJzJA5ORJrn8g64u2eGK28z/LFQbv9wXgCwfc72R468BdawFSLa/m2EECQGbZ
rWiFla26IVXV0xcD98VWJsTBZMlgPnSOqoMdM1kSEd4fUmlAYI/dFzV1XYSkOmVr
FhdZnklmpVDeu27P4c0CQQCuCOup0FlJSBpWY1TTfun/KMBkBatMz0VMA3d7FKIU
csPezl677Yjo8u1r/KzeI6zLg87Z8E6r6ZWNc9wBSZK6
-----END RSA TESTING KEY-----`)

const clientECDSACertificatePEM = `
-----BEGIN CERTIFICATE-----
MIIB/DCCAV4CCQCaMIRsJjXZFzAJBgcqhkjOPQQBMEUxCzAJBgNVBAYTAkFVMRMw
EQYDVQQIEwpTb21lLVN0YXRlMSEwHwYDVQQKExhJbnRlcm5ldCBXaWRnaXRzIFB0
eSBMdGQwHhcNMTIxMTE0MTMyNTUzWhcNMjIxMTEyMTMyNTUzWjBBMQswCQYDVQQG
EwJBVTEMMAoGA1UECBMDTlNXMRAwDgYDVQQHEwdQeXJtb250MRIwEAYDVQQDEwlK
b2VsIFNpbmcwgZswEAYHKoZIzj0CAQYFK4EEACMDgYYABACVjJF1FMBexFe01MNv
ja5oHt1vzobhfm6ySD6B5U7ixohLZNz1MLvT/2XMW/TdtWo+PtAd3kfDdq0Z9kUs
jLzYHQFMH3CQRnZIi4+DzEpcj0B22uCJ7B0rxE4wdihBsmKo+1vx+U56jb0JuK7q
ixgnTy5w/hOWusPTQBbNZU6sER7m8TAJBgcqhkjOPQQBA4GMADCBiAJCAOAUxGBg
C3JosDJdYUoCdFzCgbkWqD8pyDbHgf9stlvZcPE4O1BIKJTLCRpS8V3ujfK58PDa
2RU6+b0DeoeiIzXsAkIBo9SKeDUcSpoj0gq+KxAxnZxfvuiRs9oa9V2jI/Umi0Vw
jWVim34BmT0Y9hCaOGGbLlfk+syxis7iI6CH8OFnUes=
-----END CERTIFICATE-----`

var clientECDSAKeyPEM = testingKey(`
-----BEGIN EC PARAMETERS-----
BgUrgQQAIw==
-----END EC PARAMETERS-----
-----BEGIN EC TESTING KEY-----
MIHcAgEBBEIBkJN9X4IqZIguiEVKMqeBUP5xtRsEv4HJEtOpOGLELwO53SD78Ew8
k+wLWoqizS3NpQyMtrU8JFdWfj+C57UNkOugBwYFK4EEACOhgYkDgYYABACVjJF1
FMBexFe01MNvja5oHt1vzobhfm6ySD6B5U7ixohLZNz1MLvT/2XMW/TdtWo+PtAd
3kfDdq0Z9kUsjLzYHQFMH3CQRnZIi4+DzEpcj0B22uCJ7B0rxE4wdihBsmKo+1vx
+U56jb0JuK7qixgnTy5w/hOWusPTQBbNZU6sER7m8Q==
-----END EC TESTING KEY-----`)

const clientEd25519CertificatePEM = `
-----BEGIN CERTIFICATE-----
MIIBLjCB4aADAgECAhAX0YGTviqMISAQJRXoNCNPMAUGAytlcDASMRAwDgYDVQQK
EwdBY21lIENvMB4XDTE5MDUxNjIxNTQyNloXDTIwMDUxNTIxNTQyNlowEjEQMA4G
A1UEChMHQWNtZSBDbzAqMAUGAytlcAMhAAvgtWC14nkwPb7jHuBQsQTIbcd4bGkv
xRStmmNveRKRo00wSzAOBgNVHQ8BAf8EBAMCBaAwEwYDVR0lBAwwCgYIKwYBBQUH
AwIwDAYDVR0TAQH/BAIwADAWBgNVHREEDzANggtleGFtcGxlLmNvbTAFBgMrZXAD
QQD8GRcqlKUx+inILn9boF2KTjRAOdazENwZ/qAicbP1j6FYDc308YUkv+Y9FN/f
7Q7hF9gRomDQijcjKsJGqjoI
-----END CERTIFICATE-----`

var clientEd25519KeyPEM = testingKey(`
-----BEGIN TESTING KEY-----
MC4CAQAwBQYDK2VwBCIEINifzf07d9qx3d44e0FSbV4mC/xQxT644RRbpgNpin7I
-----END TESTING KEY-----`)

const clientEDMLDSACertificatePEM = `
-----BEGIN CERTIFICATE-----
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
1JTS0BHZY0nitthOfDptwG92MgA=
-----END CERTIFICATE-----`

var clientEDMLDSAKeyPEM = testingKey(`
-----BEGIN PRIVATE KEY-----
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
-----END PRIVATE KEY-----`)
