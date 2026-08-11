// dns/main.go — minimal authoritative DNS server with three buckets:
//
//  1. PRIMARY targets (DNS_TARGETS, default: manuals.playstation.net)
//     Answer A queries with the IPv4 address supplied via DNS_IP.
//     Used to redirect the PS5 captive-port probe to the local web server.
//
//  2. NULL targets    (DNS_NULL_TARGETS, default: smetrics.aem.playstation.com
//     and telemetry-console.api.playstation.com)
//     Answer A queries with 0.0.0.0. The PS5 will silently drop the
//     connection because 0.0.0.0 is not a routable address. We do NOT use
//     NXDOMAIN here because some clients fall back to a captive portal on
//     NXDOMAIN, which would re-trigger the very loop we are trying to break.
//
//  3. Anything else — answer NXDOMAIN. No recursion, no caching, no upstream.
//
// Sized to be embedded on scratch in a multi-stage Docker build. ~2 MB binary.
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
	maxUDPpacket      = 512
)

// Defaults are baked in so an out-of-the-box deployment works without any
// env vars. Operators can override or extend at runtime via DNS_TARGETS and
// DNS_NULL_TARGETS (comma-separated, lower-cased, fully qualified, no trailing
// dot). All comparisons below use strings.EqualFold so user-supplied casing
// doesn't matter.
var (
	defaultPrimaryTargets = []string{"manuals.playstation.net"}
	defaultNullTargets    = []string{
		"smetrics.aem.playstation.com",
		"telemetry-console.api.playstation.com",
	}
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

// result is one of three possible outcomes for a parsed query. Used both for
// logging and for picking the response payload.
type result int

const (
	resNXDOMAIN result = iota
	resAnswer          // matched a primary target — answer with DNS_IP
	resNull            // matched a null target — answer with 0.0.0.0
)

func main() {
	dnsIP := parseIP(os.Getenv("DNS_IP"))
	primaryTargets := parseTargets(os.Getenv("DNS_TARGETS"), defaultPrimaryTargets)
	nullTargets := parseTargets(os.Getenv("DNS_NULL_TARGETS"), defaultNullTargets)

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

	log.Printf("dns: serving %d primary target(s) -> %s on UDP %s",
		len(primaryTargets), dnsIP.String(), listenAddr)
	for _, n := range primaryTargets {
		log.Printf("dns:   primary: %s", n)
	}
	for _, n := range nullTargets {
		log.Printf("dns:   null   : %s -> 0.0.0.0", n)
	}

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
		reply, q, ansIP, err := buildReply(buf[:n], dnsIP, primaryTargets, nullTargets)
		if err != nil {
			log.Printf("dns: build reply from %s: %v", src.String(), err)
			continue
		}
		log.Printf("query %s | %s %s %s -> %s", src, q.qname,
			qtypeName(q.qtype), qclassName(q.qclass), resultLabel(q.res, ansIP))

		if _, err := conn.WriteToUDP(reply, src); err != nil {
			log.Printf("dns: write: %v", err)
		}
	}
}

// parseIP reads an IPv4 from an env var, returning 127.0.0.1 on empty input
// and logging fatally on malformed input.
func parseIP(env string) net.IP {
	if env == "" {
		env = "127.0.0.1"
	}
	ip := net.ParseIP(env).To4()
	if ip == nil {
		log.Fatalf("dns: DNS_IP=%q is not a valid IPv4 address", env)
	}
	return ip
}

// parseTargets splits a comma-separated env var into a normalised slice,
// falling back to the supplied defaults when the env var is empty.
func parseTargets(env string, def []string) []string {
	if env == "" {
		return normaliseTargets(def)
	}
	parts := strings.Split(env, ",")
	return normaliseTargets(parts)
}

// normaliseTargets trims whitespace, strips a single trailing dot, drops
// empties, and lower-cases every entry. dns names are case-insensitive so we
// always store them in canonical form.
func normaliseTargets(in []string) []string {
	out := make([]string, 0, len(in))
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		s = strings.TrimSuffix(s, ".")
		out = append(out, strings.ToLower(s))
	}
	return out
}

// resultLabel formats a result+answer-IP pair for the log line.
func resultLabel(r result, ansIP net.IP) string {
	switch r {
	case resAnswer:
		return "ANSWER " + ansIP.String()
	case resNull:
		return "NULL " + ansIP.String()
	default:
		return "NXDOMAIN"
	}
}

// query holds the parsed DNS question plus classification metadata. Returned
// from buildReply so the caller can log it.
type query struct {
	qname  string
	qtype  uint16
	qclass uint16
	res    result
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

// buildReply parses a DNS query and produces:
//   - an A record pointing at dnsIP if the name is in primary,
//   - an A record pointing at 0.0.0.0 if the name is in null of,
//   - NXDOMAIN otherwise.
//
// Only A/IN queries get answered authoritatively; everything else stays on
// NXDOMAIN so the client doesn't keep hammering us looking for glue.
// Returns the wire-format reply, the parsed question, the IP that was put
// in the answer section (nil if no answer), and any parse error.
func buildReply(msg []byte, dnsIP net.IP, primary, nullof []string) ([]byte, query, net.IP, error) {
	q := query{}
	if len(msg) < 12 {
		return nil, q, nil, errors.New("query too short")
	}
	id := binary.BigEndian.Uint16(msg[0:2])
	flags := binary.BigEndian.Uint16(msg[2:4])
	// Quick sanity: must be a standard query (QR=0), ignore everything else.
	if flags&flagQR != 0 {
		return nil, q, nil, errors.New("not a query")
	}
	qdCount := binary.BigEndian.Uint16(msg[4:6])
	if qdCount == 0 || qdCount > 4 {
		return nil, q, nil, errors.New("no/bad question count")
	}

	// Parse the first question only. Preserve the original casing of the
	// name for logging — matching is done against normalised names below.
	off := 12
	rawName, off, err := readName(msg, off)
	if err != nil {
		return nil, q, nil, err
	}
	if off+4 > len(msg) {
		return nil, q, nil, errors.New("truncated question")
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
	answerIP := net.IP(nil)

	switch {
	case qtype == qtypeA && qclass == qclassIN && nameMatches(rawName, primary):
		// Primary target — answer with the configured DNS_IP.
		rcode = byte(flagRcodeO)
		answers = 1
		answerIP = dnsIP
		q.res = resAnswer
	case qtype == qtypeA && qclass == qclassIN && nameMatches(rawName, nullof):
		// Null target — answer with 0.0.0.0 so the client drops the
		// connection instead of falling back to NXDOMAIN/captive logic.
		rcode = byte(flagRcodeO)
		answers = 1
		answerIP = net.IPv4zero
		q.res = resNull
	default:
		// Anything else, including non-A/IN queries: stay on NXDOMAIN.
		q.res = resNXDOMAIN
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
		out = append(out, answerIP...)
	}

	return out, q, answerIP, nil
}

// nameMatches reports whether name is in set. Both are compared after
// stripping a single trailing dot and lower-casing, matching the canonical
// normalisation DNS resolvers apply.
func nameMatches(name string, set []string) bool {
	n := strings.ToLower(strings.TrimSuffix(name, "."))
	for _, s := range set {
		if s == n {
			return true
		}
	}
	return false
}

// readName walks a DNS name (sequence of length-prefixed labels) starting at
// off, returning the name as a dotted string with original casing preserved
// (callers that need case-insensitive comparison can use nameMatches above)
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
	// exactly what the client sent. Matching/normalisation happens in the
	// caller.
	return strings.Join(labels, "."), off, nil
}
