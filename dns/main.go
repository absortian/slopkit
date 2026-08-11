// dns/main.go — minimal authoritative DNS server with five buckets:
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
//  3. ALIAS targets   (DNS_ALIAS_TARGETS, default: empty)
//     Each entry is `alias=reference` where `reference` is the name of a
//     PRIMARY target. The alias resolves to the SAME IP as its reference,
//     so an operator can spoof additional captive-port probes without
//     duplicating DNS_IP. The reference must exist in DNS_TARGETS — this
//     bucket never does upstream lookups.
//
//  4. RESOLVE targets (DNS_RESOLVE_TARGETS, default: empty)
//     Each entry is `alias=external_domain`. When the alias is queried we
//     forward an A query to the upstream resolver configured in
//     DNS_UPSTREAM (default 1.1.1.1:53), cache the answer for its TTL,
//     and return it. If upstream fails / times out we FALL BACK to DNS_IP
//     so the PS5 captive-port flow still terminates at the local server
//     even when the host has no internet.
//
//  5. Anything else — answer NXDOMAIN. No recursion outside the RESOLVE
//     bucket, no caching outside the RESOLVE bucket.
//
// Sized to be embedded on scratch in a multi-stage Docker build.
package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

const (
	defaultListenAddr = ":53"
	maxUDPpacket      = 512
	// upstreamTimeout caps each forwarded query. Kept short so the PS5's
	// captive-port probe doesn't stall waiting on a dead upstream.
	upstreamTimeout = 2 * time.Second
	// upstreamDefault is the fallback resolver if DNS_UPSTREAM is unset.
	// Cloudflare's 1.1.1.1 is fast, anycast, and typically reachable from
	// home networks.
	upstreamDefault = "1.1.1.1:53"
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

// result is one of several possible outcomes for a parsed query. Used both
// for logging and for picking the response payload.
type result int

const (
	resNXDOMAIN result = iota
	resAnswer          // matched a primary target — answer with DNS_IP
	resNull            // matched a null target — answer with 0.0.0.0
	resAlias           // matched an alias target — answer with DNS_IP (mirror)
	resResolve         // matched a resolve target — answer with upstream IP
)

func main() {
	// `dns healthcheck` is invoked by the Docker healthcheck on a separate
	// invocation of this same binary — it validates that:
	//   1. DNS_IP, if set, parses as an IPv4 address.
	//   2. DNS_TARGETS and DNS_NULL_TARGETS, if set, parse as comma-separated
	//      lists of names.
	// It does NOT bind any UDP port, so it can run alongside the real DNS
	// listener without colliding. It always exits 0 on success and 1 on
	// failure; the message goes to stderr so `docker inspect` shows it under
	// `State.Health.Status`.
	if len(os.Args) > 1 && os.Args[1] == "healthcheck" {
		os.Exit(runHealthcheck())
	}

	dnsIP := parseIP(os.Getenv("DNS_IP"))
	primaryTargets := parseTargets(os.Getenv("DNS_TARGETS"), defaultPrimaryTargets)
	nullTargets := parseTargets(os.Getenv("DNS_NULL_TARGETS"), defaultNullTargets)
	aliases := parseAliases(os.Getenv("DNS_ALIAS_TARGETS"), primaryTargets)
	resolveTargets := parseResolveTargets(os.Getenv("DNS_RESOLVE_TARGETS"))
	resolver := newResolver(os.Getenv("DNS_UPSTREAM"))

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

	log.Printf("dns: serving %d primary target(s) -> %s on UDP %s (upstream %s)",
		len(primaryTargets), dnsIP.String(), listenAddr, resolver.upstream)
	for _, n := range primaryTargets {
		log.Printf("dns:   primary: %s", n)
	}
	for _, n := range nullTargets {
		log.Printf("dns:   null   : %s -> 0.0.0.0", n)
	}
	for _, a := range aliases {
		log.Printf("dns:   alias  : %s -> %s -> %s", a.alias, a.reference, dnsIP.String())
	}
	for _, r := range resolveTargets {
		log.Printf("dns:   resolve: %s -> %s (via upstream)", r.alias, r.external)
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
		reply, q, ansIP, ansSrc, err := buildReply(buf[:n], dnsIP, primaryTargets, nullTargets, aliases, resolveTargets, resolver)
		if err != nil {
			log.Printf("dns: build reply from %s: %v", src.String(), err)
			continue
		}
		log.Printf("query %s | %s %s %s -> %s", src, q.qname,
			qtypeName(q.qtype), qclassName(q.qclass), resultLabel(q.res, ansIP, ansSrc))

		if _, err := conn.WriteToUDP(reply, src); err != nil {
			log.Printf("dns: write: %v", err)
		}
	}
}

// runHealthcheck validates the runtime configuration without starting the
// server. Returns 0 on success, 1 on failure. Failure messages go to stderr so
// they are visible in `docker inspect`.
func runHealthcheck() int {
	// DNS_IP — accept empty (will fall back to 127.0.0.1) but reject junk.
	if v := os.Getenv("DNS_IP"); v != "" {
		if net.ParseIP(v).To4() == nil {
			fmt.Fprintln(os.Stderr, "healthcheck: DNS_IP is not a valid IPv4 address:", v)
			return 1
		}
	}
	// DNS_TARGETS / DNS_NULL_TARGETS — accept empty (use defaults) but reject
	// malformed entries (anything with spaces embedded or invalid label chars).
	for _, envName := range []string{"DNS_TARGETS", "DNS_NULL_TARGETS"} {
		v := os.Getenv(envName)
		if v == "" {
			continue
		}
		for _, name := range strings.Split(v, ",") {
			name = strings.TrimSpace(name)
			if name == "" {
				continue
			}
			if !looksLikeDNSName(name) {
				fmt.Fprintf(os.Stderr, "healthcheck: %s contains malformed entry %q\n", envName, name)
				return 1
			}
		}
	}
	// DNS_ALIAS_TARGETS — accept empty but reject malformed entries. Each
	// entry must be of the form `alias=reference`, both halves must look
	// like DNS names. We do NOT verify that the reference exists in
	// DNS_TARGETS here — that's done in parseAliases at startup so the
	// failure mode is a fatal log line rather than silent misconfiguration.
	if v := os.Getenv("DNS_ALIAS_TARGETS"); v != "" {
		for _, entry := range strings.Split(v, ",") {
			entry = strings.TrimSpace(entry)
			if entry == "" {
				continue
			}
			parts := strings.SplitN(entry, "=", 2)
			if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
				fmt.Fprintf(os.Stderr, "healthcheck: DNS_ALIAS_TARGETS contains malformed entry %q (want alias=reference)\n", entry)
				return 1
			}
			if !looksLikeDNSName(strings.TrimSpace(parts[0])) || !looksLikeDNSName(strings.TrimSpace(parts[1])) {
				fmt.Fprintf(os.Stderr, "healthcheck: DNS_ALIAS_TARGETS contains malformed entry %q\n", entry)
				return 1
			}
		}
	}
	// DNS_RESOLVE_TARGETS — same syntactic shape as DNS_ALIAS_TARGETS but
	// the right-hand side is an external domain, not a DNS_TARGETS entry.
	// No semantic cross-check here either — `parseResolveTargets` is lax
	// by design (any DNS-shaped name is valid as an external target).
	if v := os.Getenv("DNS_RESOLVE_TARGETS"); v != "" {
		for _, entry := range strings.Split(v, ",") {
			entry = strings.TrimSpace(entry)
			if entry == "" {
				continue
			}
			parts := strings.SplitN(entry, "=", 2)
			if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
				fmt.Fprintf(os.Stderr, "healthcheck: DNS_RESOLVE_TARGETS contains malformed entry %q (want alias=external_domain)\n", entry)
				return 1
			}
			if !looksLikeDNSName(strings.TrimSpace(parts[0])) || !looksLikeDNSName(strings.TrimSpace(parts[1])) {
				fmt.Fprintf(os.Stderr, "healthcheck: DNS_RESOLVE_TARGETS contains malformed entry %q\n", entry)
				return 1
			}
		}
	}
	// DNS_UPSTREAM — accept empty (will default to 1.1.1.1:53) but reject
	// anything that doesn't parse as `host:port`. We don't try to reach
	// it from the healthcheck — connectivity to internet is the
	// responsibility of the runtime, not the config validator.
	if v := os.Getenv("DNS_UPSTREAM"); v != "" {
		if _, _, err := net.SplitHostPort(v); err != nil {
			fmt.Fprintln(os.Stderr, "healthcheck: DNS_UPSTREAM is not valid host:port:", v)
			return 1
		}
	}
	fmt.Println("healthcheck: OK")
	return 0
}

// looksLikeDNSName returns true if name is a valid dotted DNS label sequence.
// Permissive (no trailing dot requirement) since both forms are accepted by
// normaliseTargets.
func looksLikeDNSName(name string) bool {
	if len(name) == 0 || len(name) > 253 {
		return false
	}
	for _, label := range strings.Split(name, ".") {
		if label == "" || len(label) > 63 {
			return false
		}
		for _, r := range label {
			switch {
			case r >= 'a' && r <= 'z':
			case r >= 'A' && r <= 'Z':
			case r >= '0' && r <= '9':
			case r == '-':
			default:
				return false
			}
		}
	}
	return true
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

// aliasEntry pairs an alias name with the primary target it should mirror.
// Both fields are pre-normalised (lower-cased, trailing dot stripped).
type aliasEntry struct {
	alias     string
	reference string
}

// parseAliases reads DNS_ALIAS_TARGETS (a comma-separated list of
// `alias=reference` pairs) and returns a normalised slice. Each entry's
// `reference` must exist in `primary` — we never do recursive DNS lookups,
// so an alias that points at a name we don't already answer for would just
// silently fall through to NXDOMAIN, which defeats the point. Failing fast
// at startup is safer.
func parseAliases(env string, primary []string) []aliasEntry {
	if env == "" {
		return nil
	}
	primarySet := make(map[string]struct{}, len(primary))
	for _, p := range primary {
		primarySet[p] = struct{}{}
	}
	var out []aliasEntry
	for _, raw := range strings.Split(env, ",") {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		parts := strings.SplitN(raw, "=", 2)
		if len(parts) != 2 {
			log.Fatalf("dns: DNS_ALIAS_TARGETS contains malformed entry %q (want alias=reference)", raw)
		}
		alias := normaliseTargets([]string{parts[0]})
		reference := normaliseTargets([]string{parts[1]})
		if len(alias) == 0 || len(reference) == 0 {
			log.Fatalf("dns: DNS_ALIAS_TARGETS contains malformed entry %q (want alias=reference)", raw)
		}
		if _, ok := primarySet[reference[0]]; !ok {
			log.Fatalf("dns: DNS_ALIAS_TARGETS entry %q references %q which is NOT in DNS_TARGETS — add it first", raw, reference[0])
		}
		out = append(out, aliasEntry{alias: alias[0], reference: reference[0]})
	}
	return out
}

// resolveEntry pairs an alias name with the external domain we should query
// upstream to learn its current IPv4 address. The alias is what the PS5
// sees; the external is what we ask the upstream resolver for.
type resolveEntry struct {
	alias    string
	external string
}

// parseResolveTargets reads DNS_RESOLVE_TARGETS (a comma-separated list of
// `alias=external_domain` pairs). Unlike aliases, the right-hand side is
// NOT required to be in DNS_TARGETS — it is a real public domain that will
// be resolved upstream. Validation here is only syntactic.
func parseResolveTargets(env string) []resolveEntry {
	if env == "" {
		return nil
	}
	var out []resolveEntry
	for _, raw := range strings.Split(env, ",") {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		parts := strings.SplitN(raw, "=", 2)
		if len(parts) != 2 {
			log.Fatalf("dns: DNS_RESOLVE_TARGETS contains malformed entry %q (want alias=external_domain)", raw)
		}
		alias := normaliseTargets([]string{parts[0]})
		external := normaliseTargets([]string{parts[1]})
		if len(alias) == 0 || len(external) == 0 {
			log.Fatalf("dns: DNS_RESOLVE_TARGETS contains malformed entry %q (want alias=external_domain)", raw)
		}
		out = append(out, resolveEntry{alias: alias[0], external: external[0]})
	}
	return out
}

// cacheEntry holds a resolved IP together with the moment after which the
// entry is stale. We honour the upstream's TTL (clamped) so frequent
// queries don't hammer the resolver and DNS changes propagate eventually.
type cacheEntry struct {
	ip       net.IP
	expires  time.Time
	negative bool // true when upstream returned NXDOMAIN/empty; cache briefly
}

// resolver owns the upstream connection and the cache. One per server
// instance. Cache is keyed by the external domain (the right-hand side of
// DNS_RESOLVE_TARGETS) — multiple aliases can share a cache entry if they
// point at the same external domain.
type resolver struct {
	upstream string
	mu       sync.Mutex
	cache    map[string]cacheEntry
}

func newResolver(upstream string) *resolver {
	if upstream == "" {
		upstream = upstreamDefault
	}
	return &resolver{
		upstream: upstream,
		cache:    make(map[string]cacheEntry),
	}
}

// lookup returns the IPv4 for `domain`, consulting the cache first. On a
// miss it forwards an A query to the upstream resolver, honours the
// upstream TTL (clamped to [30s, 1h]), and caches the answer. On any error
// (timeout, parse failure, SERVFAIL, NXDOMAIN) the second return value is
// nil and the caller falls back to DNS_IP. Negative answers are cached
// briefly so we don't spam a misconfigured upstream.
func (r *resolver) lookup(domain string) (net.IP, bool) {
	r.mu.Lock()
	if e, ok := r.cache[domain]; ok && time.Now().Before(e.expires) {
		r.mu.Unlock()
		if e.negative {
			return nil, false
		}
		return e.ip, true
	}
	r.mu.Unlock()

	ip, ttl, err := r.queryUpstream(domain)
	if err != nil {
		// Cache the failure for 30s so we don't pound a dead upstream.
		r.mu.Lock()
		r.cache[domain] = cacheEntry{expires: time.Now().Add(30 * time.Second), negative: true}
		r.mu.Unlock()
		return nil, false
	}
	if ip == nil {
		// Upstream returned NOERROR but no A record. Cache as negative
		// for the original TTL (clamped) — the domain exists but has no
		// A record right now.
		r.mu.Lock()
		r.cache[domain] = cacheEntry{expires: time.Now().Add(clampTTL(ttl, 30*time.Second, time.Hour)), negative: true}
		r.mu.Unlock()
		return nil, false
	}
	// Successful hit — cache the IP for the upstream TTL (clamped).
	r.mu.Lock()
	r.cache[domain] = cacheEntry{ip: ip, expires: time.Now().Add(clampTTL(ttl, 30*time.Second, time.Hour))}
	r.mu.Unlock()
	return ip, true
}

// clampTTL keeps the cache entry useful but bounded. 30s minimum avoids
// thrashing on misbehaving upstreams with TTL=0. 1h maximum ensures
// operator-visible config changes propagate within a reasonable window.
func clampTTL(ttl time.Duration, min, max time.Duration) time.Duration {
	if ttl <= 0 {
		return min
	}
	if ttl < min {
		return min
	}
	if ttl > max {
		return max
	}
	return ttl
}

// queryUpstream sends a single A query to the configured upstream and
// returns the first A record (plus its TTL) from the answer section. We
// hand-build a minimal DNS query and parse only the fields we need; full
// RFC compliance is not required for a captive-port use case.
func (r *resolver) queryUpstream(domain string) (net.IP, time.Duration, error) {
	udpAddr, err := net.ResolveUDPAddr("udp", r.upstream)
	if err != nil {
		return nil, 0, fmt.Errorf("resolve upstream %s: %w", r.upstream, err)
	}
	conn, err := net.DialUDP("udp", nil, udpAddr)
	if err != nil {
		return nil, 0, fmt.Errorf("dial upstream %s: %w", r.upstream, err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(upstreamTimeout)); err != nil {
		return nil, 0, err
	}

	// Transaction ID is fixed at 0x0001 — the upstream response echoes it
	// and we don't care about collisions in a single-flight resolver.
	qid := uint16(0x0001)
	req := buildUpstreamQuery(qid, domain)
	if _, err := conn.Write(req); err != nil {
		return nil, 0, fmt.Errorf("write upstream: %w", err)
	}
	resp := make([]byte, maxUDPpacket)
	n, err := conn.Read(resp)
	if err != nil {
		return nil, 0, fmt.Errorf("read upstream: %w", err)
	}
	return parseUpstreamResponse(resp[:n], qid)
}

// buildUpstreamQuery constructs a minimal DNS A query for `name`.
// Header: QR=0, OPCODE=0, RD=1 (recursion desired). One question, no
// answer/authority/additional. The trailing 0x00 ends the question name.
func buildUpstreamQuery(id uint16, name string) []byte {
	out := make([]byte, 0, 64)
	out = binary.BigEndian.AppendUint16(out, id)
	// flags: RD=1, everything else zero (standard query)
	out = binary.BigEndian.AppendUint16(out, 1<<8)
	out = binary.BigEndian.AppendUint16(out, 1) // QDCOUNT
	out = binary.BigEndian.AppendUint16(out, 0) // ANCOUNT
	out = binary.BigEndian.AppendUint16(out, 0) // NSCOUNT
	out = binary.BigEndian.AppendUint16(out, 0) // ARCOUNT
	for _, label := range strings.Split(name, ".") {
		if label == "" {
			continue
		}
		out = append(out, byte(len(label)))
		out = append(out, []byte(label)...)
	}
	out = append(out, 0) // root terminator
	out = binary.BigEndian.AppendUint16(out, qtypeA)
	out = binary.BigEndian.AppendUint16(out, qclassIN)
	return out
}

// parseUpstreamResponse extracts the first A record from the answer
// section of a DNS response and returns its IPv4 plus TTL. Returns an
// error if the response is malformed, has the wrong ID, has the QR bit
// unset, or sets an error rcode.
func parseUpstreamResponse(resp []byte, expectID uint16) (net.IP, time.Duration, error) {
	if len(resp) < 12 {
		return nil, 0, errors.New("upstream response too short")
	}
	id := binary.BigEndian.Uint16(resp[0:2])
	if id != expectID {
		return nil, 0, fmt.Errorf("upstream ID mismatch: got 0x%04x want 0x%04x", id, expectID)
	}
	flags := binary.BigEndian.Uint16(resp[2:4])
	if flags&flagQR == 0 {
		return nil, 0, errors.New("upstream response has QR=0")
	}
	rcode := flags & 0xF
	if rcode != flagRcodeO {
		// Map any non-NOERROR to an error so the caller falls back to
		// DNS_IP. NXDOMAIN specifically is treated as "no answer for
		// this name" so it counts as a negative cache hit.
		return nil, 0, fmt.Errorf("upstream rcode=%d", rcode)
	}
	qdCount := binary.BigEndian.Uint16(resp[4:6])
	anCount := binary.BigEndian.Uint16(resp[6:8])

	off := 12
	// Skip the question section verbatim. We don't validate it matches
	// our query — ID check above is enough.
	for i := 0; i < int(qdCount); i++ {
		_, next, err := readName(resp, off)
		if err != nil {
			return nil, 0, fmt.Errorf("upstream question name: %w", err)
		}
		off = next
		if off+4 > len(resp) {
			return nil, 0, errors.New("upstream question truncated")
		}
		off += 4 // QTYPE + QCLASS
	}
	// Walk the answer section, returning the first A record.
	for i := 0; i < int(anCount); i++ {
		_, next, err := readName(resp, off)
		if err != nil {
			return nil, 0, fmt.Errorf("upstream answer name: %w", err)
		}
		off = next
		if off+10 > len(resp) {
			return nil, 0, errors.New("upstream answer truncated")
		}
		typ := binary.BigEndian.Uint16(resp[off : off+2])
		class := binary.BigEndian.Uint16(resp[off+2 : off+4])
		ttl := binary.BigEndian.Uint32(resp[off+4 : off+8])
		rdlen := binary.BigEndian.Uint16(resp[off+8 : off+10])
		off += 10
		if off+int(rdlen) > len(resp) {
			return nil, 0, errors.New("upstream answer rdata truncated")
		}
		if typ == qtypeA && class == qclassIN && rdlen == 4 {
			return net.IP(resp[off : off+4]), time.Duration(ttl) * time.Second, nil
		}
		off += int(rdlen)
	}
	return nil, 0, nil // NOERROR but no A record — caller treats as negative
}

// resolveFor returns the cached or freshly-resolved IPv4 for the external
// domain associated with `alias`, or (nil, "", false) if the alias is not a
// RESOLVE target. The alias lookup uses the same case-insensitive /
// trailing-dot-tolerant comparison as the other buckets.
//
// IMPORTANT: when the alias DOES match but the upstream lookup fails,
// we return (nil, external, true) — the caller distinguishes "alias matched
// but upstream down" from "alias not present at all" by inspecting the
// returned `ok`. (We used to collapse both cases by shadowing `ok` with
// the lookup result; that bug silently turned every upstream failure into
// NXDOMAIN.)
func (r *resolver) resolveFor(name string, set []resolveEntry) (net.IP, string, bool) {
	n := strings.ToLower(strings.TrimSuffix(name, "."))
	for _, e := range set {
		if e.alias == n {
			ip, _ := r.lookup(e.external)
			return ip, e.external, true
		}
	}
	return nil, "", false
}

// resultLabel formats a result+answer-IP pair for the log line. The
// `src` argument is the external domain we resolved from, when applicable
// (resolve bucket only) — empty for all other buckets.
func resultLabel(r result, ansIP net.IP, src string) string {
	switch r {
	case resAnswer:
		return "ANSWER " + ansIP.String()
	case resNull:
		return "NULL " + ansIP.String()
	case resAlias:
		return "ALIAS " + ansIP.String()
	case resResolve:
		if src != "" {
			return "RESOLVE " + ansIP.String() + " (from " + src + ")"
		}
		return "RESOLVE " + ansIP.String()
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
//   - an A record pointing at dnsIP if the name matches an alias of a primary,
//   - an A record with the upstream-resolved IP if the name is in resolve,
//     falling back to dnsIP if upstream fails,
//   - an A record pointing at 0.0.0.0 if the name is in null of,
//   - NXDOMAIN otherwise.
//
// Only A/IN queries get answered authoritatively; everything else stays on
// NXDOMAIN so the client doesn't keep hammering us looking for glue.
// Returns the wire-format reply, the parsed question, the IP that was put
// in the answer section (nil if no answer), the external domain we resolved
// from (empty for all other buckets, used for logging), and any parse error.
func buildReply(msg []byte, dnsIP net.IP, primary, nullof []string, aliases []aliasEntry, resolve []resolveEntry, res *resolver) ([]byte, query, net.IP, string, error) {
	q := query{}
	if len(msg) < 12 {
		return nil, q, nil, "", errors.New("query too short")
	}
	id := binary.BigEndian.Uint16(msg[0:2])
	flags := binary.BigEndian.Uint16(msg[2:4])
	// Quick sanity: must be a standard query (QR=0), ignore everything else.
	if flags&flagQR != 0 {
		return nil, q, nil, "", errors.New("not a query")
	}
	qdCount := binary.BigEndian.Uint16(msg[4:6])
	if qdCount == 0 || qdCount > 4 {
		return nil, q, nil, "", errors.New("no/bad question count")
	}

	// Parse the first question only. Preserve the original casing of the
	// name for logging — matching is done against normalised names below.
	off := 12
	rawName, off, err := readName(msg, off)
	if err != nil {
		return nil, q, nil, "", err
	}
	if off+4 > len(msg) {
		return nil, q, nil, "", errors.New("truncated question")
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
	ansSrc := "" // external domain we resolved from (RESOLVE bucket only)

	switch {
	case qtype == qtypeA && qclass == qclassIN && nameMatches(rawName, primary):
		// Primary target — answer with the configured DNS_IP.
		rcode = byte(flagRcodeO)
		answers = 1
		answerIP = dnsIP
		q.res = resAnswer
	case qtype == qtypeA && qclass == qclassIN && aliasMatches(rawName, aliases):
		// Alias of a primary target — mirror the primary's IP so additional
		// captive-port probes reach the local web server without duplicating
		// DNS_IP. No upstream lookup, no fallback logic.
		rcode = byte(flagRcodeO)
		answers = 1
		answerIP = dnsIP
		q.res = resAlias
	case qtype == qtypeA && qclass == qclassIN && (func() bool {
		ip, ext, ok := res.resolveFor(rawName, resolve)
		if !ok {
			return false
		}
		if ip != nil {
			answerIP = ip
			ansSrc = ext
		} else {
			// Upstream failed — fall back to DNS_IP so the captive-port
			// flow still terminates at the local server. Log it as a
			// RESOLVE too so the operator can see the fallback happened.
			answerIP = dnsIP
			ansSrc = ext + " (fallback)"
		}
		rcode = byte(flagRcodeO)
		answers = 1
		q.res = resResolve
		return true
	})():
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

	return out, q, answerIP, ansSrc, nil
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

// aliasMatches reports whether name matches the `alias` field of any entry
// in the slice, using the same case-insensitive / trailing-dot-tolerant
// comparison as nameMatches.
func aliasMatches(name string, set []aliasEntry) bool {
	n := strings.ToLower(strings.TrimSuffix(name, "."))
	for _, e := range set {
		if e.alias == n {
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
