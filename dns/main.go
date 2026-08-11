// dns/main.go — minimal authoritative DNS server answering a single A record.
//
// Listens on UDP/53 and answers every A query for `manuals.playstation.net`
// with the IPv4 address supplied via the DNS_IP env var. All other queries
// get a NXDOMAIN reply. No recursion, no caching, no upstream.
//
// Sized to be embedded on scratch in a multi-stage Docker build. ~1.8 MB binary.
package main

import (
	"encoding/binary"
	"errors"
	"log"
	"net"
	"os"
	"strings"
)

const (
	defaultListenAddr = ":53"
	targetName        = "manuals.playstation.net"
	maxUDPpacket      = 512
)

// DNS header flags we care about.
const (
	flagQR     = 1 << 15 // 0=query, 1=response
	flagAA     = 1 << 10 // authoritative answer
	flagRcodeN = 3       // NXDOMAIN
	flagRcodeO = 0       // NOERROR
	qtypeA     = 1
	qclassIN   = 1
)

func main() {
	ipStr := os.Getenv("DNS_IP")
	if ipStr == "" {
		ipStr = "127.0.0.1"
	}
	ip := net.ParseIP(ipStr).To4()
	if ip == nil {
		log.Fatalf("dns: DNS_IP=%q is not a valid IPv4 address", ipStr)
	}

	// LISTEN_ADDR lets us run on a non-privileged port in dev / CI / tests.
	// Docker uses the default ":53".
	listenAddr := os.Getenv("LISTEN_ADDR")
	if listenAddr == "" {
		listenAddr = defaultListenAddr
	}

	udpAddr, err := net.ResolveUDPAddr("udp", listenAddr)
	if err != nil {
		log.Fatalf("dns: resolve udp: %v", err)
	}
	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		log.Fatalf("dns: listen udp %s: %v", listenAddr, err)
	}
	defer conn.Close()

	log.Printf("dns: serving A %s -> %s on UDP %s", targetName, ip.String(), listenAddr)

	buf := make([]byte, maxUDPpacket)
	for {
		n, src, err := conn.ReadFromUDP(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			log.Printf("dns: read: %v", err)
			continue
		}
		reply, q, err := buildReply(buf[:n], ip)
		if err != nil {
			log.Printf("dns: build reply from %s: %v", src.String(), err)
			continue
		}
		// Log every query we actually answer. Format is intentionally
		// grep-friendly: `client | qname TYPE CLASS -> result`.
		// q.qname keeps the original casing the client sent.
		result := "NXDOMAIN"
		if q.answered {
			result = "ANSWER " + ip.String()
		}
		log.Printf("query %s | %s %s %s -> %s", src, q.qname, qtypeName(q.qtype), qclassName(q.qclass), result)

		if _, err := conn.WriteToUDP(reply, src); err != nil {
			log.Printf("dns: write: %v", err)
		}
	}
}

// query holds the parsed DNS question plus whether we authoritatively answered
// it. Returned from buildReply so the caller can log it.
type query struct {
	qname    string
	qtype    uint16
	qclass   uint16
	answered bool
}

// qtypeName returns a short label for common DNS query types, falling back
// to "TYPE<n>" for anything we don't recognise. Compact for log brevity.
func qtypeName(t uint16) string {
	switch t {
	case 1:
		return "A"
	case 2:
		return "NS"
	case 5:
		return "CNAME"
	case 6:
		return "SOA"
	case 12:
		return "PTR"
	case 15:
		return "MX"
	case 16:
		return "TXT"
	case 28:
		return "AAAA"
	case 33:
		return "SRV"
	case 255:
		return "ANY"
	}
	return "TYPE" + uintStr(t)
}

// qclassName returns a short label for common DNS classes.
func qclassName(c uint16) string {
	switch c {
	case 1:
		return "IN"
	case 2:
		return "CS"
	case 3:
		return "CH"
	case 4:
		return "HS"
	case 255:
		return "ANY"
	}
	return "CLASS" + uintStr(c)
}

// uintStr avoids pulling in strconv just for log labels.
func uintStr(u uint16) string {
	if u == 0 {
		return "0"
	}
	var b [5]byte
	i := len(b)
	for u > 0 {
		i--
		b[i] = byte('0' + u%10)
		u /= 10
	}
	return string(b[i:])
}

// buildReply parses a DNS query, copies the question section verbatim, and
// appends either an A answer (matching targetName) or sets NXDOMAIN.
// Returns the wire-format reply and the parsed question for logging.
func buildReply(msg []byte, ip net.IP) ([]byte, query, error) {
	q := query{}
	if len(msg) < 12 {
		return nil, q, errors.New("query too short")
	}
	id := binary.BigEndian.Uint16(msg[0:2])
	flags := binary.BigEndian.Uint16(msg[2:4])
	// Quick sanity: must be a standard query (QR=0), ignore everything else.
	if flags&flagQR != 0 {
		return nil, q, errors.New("not a query")
	}
	qdCount := binary.BigEndian.Uint16(msg[4:6])
	if qdCount == 0 || qdCount > 4 {
		return nil, q, errors.New("no/bad question count")
	}

	// Parse the first question only. Preserve the original casing of the
	// name for logging — we still compare case-insensitively below.
	off := 12
	rawName, off, err := readName(msg, off)
	if err != nil {
		return nil, q, err
	}
	if off+4 > len(msg) {
		return nil, q, errors.New("truncated question")
	}
	qtype := binary.BigEndian.Uint16(msg[off : off+2])
	qclass := binary.BigEndian.Uint16(msg[off+2 : off+4])
	off += 4

	q.qname = rawName
	q.qtype = qtype
	q.qclass = qclass

	// Build the response header.
	out := make([]byte, 0, 256)
	out = append(out, 0, 0)   // ID placeholder
	rcode := byte(flagRcodeN) // default NXDOMAIN
	answers := 0
	if qtype == qtypeA && qclass == qclassIN && strings.EqualFold(rawName, targetName) {
		rcode = byte(flagRcodeO)
		answers = 1
		q.answered = true
	}
	respFlags := uint16(flagQR|flagAA) | uint16(rcode)
	out = binary.BigEndian.AppendUint16(out, respFlags)
	out = binary.BigEndian.AppendUint16(out, 1) // QDCOUNT
	out = binary.BigEndian.AppendUint16(out, uint16(answers))
	out = binary.BigEndian.AppendUint16(out, 0) // NSCOUNT
	out = binary.BigEndian.AppendUint16(out, 0) // ARCOUNT

	// Patch the transaction ID back in.
	binary.BigEndian.PutUint16(out[0:2], id)

	// Append the question verbatim from the query.
	out = append(out, msg[12:off]...)

	// Append the answer if we're answering authoritatively.
	if answers == 1 {
		// Name pointer to the question's first label: 0xC0 0x0C.
		out = append(out, 0xC0, 0x0C)
		out = binary.BigEndian.AppendUint16(out, qtypeA)   // TYPE
		out = binary.BigEndian.AppendUint16(out, qclassIN) // CLASS
		out = binary.BigEndian.AppendUint32(out, 60)       // TTL (60s)
		out = binary.BigEndian.AppendUint16(out, 4)        // RDLENGTH
		out = append(out, ip...)
	}

	return out, q, nil
}

// readName walks a DNS name (sequence of length-prefixed labels) starting at
// off, returning the name as a dotted string with original casing preserved
// (callers that need case-insensitive comparison can use strings.EqualFold)
// and the offset past the name's terminating zero byte. Refuses compression
// pointers (loop-safe).
func readName(buf []byte, off int) (string, int, error) {
	var labels []string
	start := off
	for off < len(buf) {
		l := int(buf[off])
		if l == 0 {
			off++
			break
		}
		// Refuse compression pointers — we don't recurse.
		if l&0xC0 != 0 {
			return "", 0, errors.New("compression pointer in question not supported")
		}
		off++
		if off+l > len(buf) {
			return "", 0, errors.New("label overflow")
		}
		labels = append(labels, string(buf[off:off+l]))
		off += l
	}
	if off > start+255 {
		return "", 0, errors.New("name too long")
	}
	// Preserve the original casing of each label so the operator can see
	// exactly what the client sent. The caller (buildReply) compares against
	// the target with strings.EqualFold, which is the DNS-spec behaviour.
	return strings.Join(labels, "."), off, nil
}
