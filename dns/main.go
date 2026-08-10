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
	listenAddr   = ":53"
	targetName   = "manuals.playstation.net"
	maxUDPpacket = 512
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
		reply, err := buildReply(buf[:n], ip)
		if err != nil {
			log.Printf("dns: build reply: %v", err)
			continue
		}
		if _, err := conn.WriteToUDP(reply, src); err != nil {
			log.Printf("dns: write: %v", err)
		}
	}
}

// buildReply parses a DNS query, copies the question section verbatim, and
// appends either an A answer (matching targetName) or sets NXDOMAIN.
func buildReply(query []byte, ip net.IP) ([]byte, error) {
	if len(query) < 12 {
		return nil, errors.New("query too short")
	}
	id := binary.BigEndian.Uint16(query[0:2])
	flags := binary.BigEndian.Uint16(query[2:4])
	// Quick sanity: must be a standard query (QR=0), ignore everything else.
	if flags&flagQR != 0 {
		return nil, errors.New("not a query")
	}
	qdCount := binary.BigEndian.Uint16(query[4:6])
	if qdCount == 0 || qdCount > 4 {
		return nil, errors.New("no/bad question count")
	}

	// Parse the first question only.
	off := 12
	qname, off, err := readName(query, off)
	if err != nil {
		return nil, err
	}
	if off+4 > len(query) {
		return nil, errors.New("truncated question")
	}
	qtype := binary.BigEndian.Uint16(query[off : off+2])
	qclass := binary.BigEndian.Uint16(query[off+2 : off+4])
	off += 4

	// Build the response header.
	out := make([]byte, 0, 256)
	out = append(out, 0, 0)   // ID placeholder
	rcode := byte(flagRcodeN) // default NXDOMAIN
	answers := 0
	if qtype == qtypeA && qclass == qclassIN && strings.EqualFold(qname, targetName) {
		rcode = byte(flagRcodeO)
		answers = 1
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
	out = append(out, query[12:off]...)

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

	return out, nil
}

// readName walks a DNS name (sequence of length-prefixed labels) starting at
// off, returning the name as a lower-cased dotted string and the offset past
// the name's terminating zero byte. Refuses compression pointers (loop-safe).
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
	return strings.ToLower(strings.Join(labels, ".")), off, nil
}
