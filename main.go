package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/crypto/acme/autocert"
)

// DNSRecord represents a DNS record
type DNSRecord struct {
	Domain     string
	IP         string
	RecordType string
	IsWildcard bool
	Pattern    *regexp.Regexp
}

// NewDNSRecord creates a new DNS record
func NewDNSRecord(domain, ip, recordType string) *DNSRecord {
	// 自动兼容 $*xxx 和 $xxx 写法
	if strings.HasPrefix(domain, "$*") {
		domain = "*" + domain[2:]
	} else if strings.HasPrefix(domain, "$") {
		domain = domain[1:]
	}
	record := &DNSRecord{
		Domain:     strings.ToLower(domain),
		IP:         ip,
		RecordType: recordType,
		IsWildcard: strings.Contains(domain, "*"),
	}

	if record.IsWildcard {
		// Convert wildcard pattern to regex
		pattern := strings.ReplaceAll(domain, ".", "\\.")
		pattern = strings.ReplaceAll(pattern, "*", ".*")
		pattern = "^" + pattern + "$"
		record.Pattern = regexp.MustCompile(pattern)
	}

	return record
}

// Matches checks if a domain matches this record
func (r *DNSRecord) Matches(queryDomain string) bool {
	queryDomain = strings.ToLower(queryDomain)
	if r.IsWildcard {
		return r.Pattern.MatchString(queryDomain)
	}
	return queryDomain == r.Domain
}

// Config represents the configuration structure
type Config struct {
	General struct {
		Name         string   `json:"name"`
		Address      string   `json:"adress"` // Note: keeping original typo for compatibility
		Port         int      `json:"port"`
		PreDNS       string   `json:"predns"`
		UpstreamDNS  []string `json:"upstream_dns"`
		DohPort      int      `json:"doh_port"`
		DohHTTPS     bool     `json:"doh_https"`
		CertCacheDir string   `json:"cert_cache_dir"`
		Domain       string   `json:"domain"`
	} `json:"general"`
	Rules []struct {
		Type    string   `json:"type"`
		IP      string   `json:"ip"`
		Domains []string `json:"domains"`
	} `json:"rules"`
	Sources []struct {
		Name    string `json:"name"`
		Type    string `json:"type"`
		URL     string `json:"url"`
		Enabled bool   `json:"enabled"`
	} `json:"sources"`
}

// DNSServer represents the main DNS server
type DNSServer struct {
	config          *Config
	records         []*DNSRecord
	recordsMutex    sync.RWMutex
	upstreamServers []string
	server          *dns.Server
	running         bool
	stopChan        chan struct{}
	logger          *log.Logger
	dohPort         int
	dohHTTPS        bool
	certCacheDir    string
	domain          string
}

// NewDNSServer creates a new DNS server instance
func NewDNSServer(configFile string) (*DNSServer, error) {
	logger := log.New(os.Stdout, "[DNS] ", log.LstdFlags)

	server := &DNSServer{
		upstreamServers: []string{"223.5.5.5:53", "223.6.6.6:53"},
		stopChan:        make(chan struct{}),
		logger:          logger,
	}

	if err := server.loadConfig(configFile); err != nil {
		return nil, fmt.Errorf("failed to load config: %w", err)
	}

	server.setupUpstreamServers()
	server.loadRules()

	return server, nil
}

// loadConfig loads configuration from file
func (s *DNSServer) loadConfig(configFile string) error {
	data, err := os.ReadFile(configFile)
	if err != nil {
		return fmt.Errorf("failed to read config file: %w", err)
	}

	s.config = &Config{}
	if err := json.Unmarshal(data, s.config); err != nil {
		return fmt.Errorf("failed to parse config: %w", err)
	}

	s.logger.Printf("Config loaded successfully: %s", s.config.General.Name)
	return nil
}

// setupUpstreamServers configures upstream DNS servers
func (s *DNSServer) setupUpstreamServers() {
	servers := []string{"223.5.5.5:53", "223.6.6.6:53"}

	// Add predefined DNS server
	if s.config.General.PreDNS != "" {
		if isValidIP(s.config.General.PreDNS) {
			servers = append([]string{s.config.General.PreDNS + ":53"}, servers...)
			s.logger.Printf("Added predefined upstream DNS: %s", s.config.General.PreDNS)
		} else {
			s.logger.Printf("Invalid predefined DNS address: %s", s.config.General.PreDNS)
		}
	}

	// Add upstream DNS servers from config
	if len(s.config.General.UpstreamDNS) > 0 {
		validServers := []string{}
		for _, server := range s.config.General.UpstreamDNS {
			if isValidIP(server) {
				validServers = append(validServers, server+":53")
			} else {
				s.logger.Printf("Invalid upstream DNS address: %s", server)
			}
		}
		if len(validServers) > 0 {
			servers = validServers
			s.logger.Printf("Set upstream DNS servers: %s", strings.Join(validServers, ", "))
		}
	}

	s.upstreamServers = servers
	s.logger.Printf("Current upstream DNS servers: %s", strings.Join(s.upstreamServers, ", "))
}

// loadRules loads DNS rules from config and remote sources
func (s *DNSServer) loadRules() {
	s.recordsMutex.Lock()
	defer s.recordsMutex.Unlock()

	s.records = nil

	// Load local rules
	for _, rule := range s.config.Rules {
		if rule.Type == "ip" {
			recordType := "A"
			if strings.Contains(rule.IP, ":") {
				recordType = "AAAA"
			}

			for _, domain := range rule.Domains {
				record := NewDNSRecord(domain, rule.IP, recordType)
				s.records = append(s.records, record)
				s.logger.Printf("Loaded local rule: %s -> %s", domain, rule.IP)
			}
		}
	}

	// Load remote sources
	for _, source := range s.config.Sources {
		if source.Enabled && source.Type == "list" {
			s.loadRemoteSource(source)
		}
	}
}

// loadRemoteSource loads rules from remote source
func (s *DNSServer) loadRemoteSource(source struct {
	Name    string `json:"name"`
	Type    string `json:"type"`
	URL     string `json:"url"`
	Enabled bool   `json:"enabled"`
}) {
	s.logger.Printf("Loading remote source: %s", source.Name)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(source.URL)
	if err != nil {
		s.logger.Printf("Failed to load remote source %s: %v", source.Name, err)
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		s.logger.Printf("Failed to read remote source %s: %v", source.Name, err)
		return
	}

	count := 0

	// Try to parse as JSON first
	var jsonData interface{}
	if err := json.Unmarshal(body, &jsonData); err == nil {
		switch data := jsonData.(type) {
		case []interface{}:
			// Handle array format: [["domain1","domain2"], "cname", "ip"]
			for _, entry := range data {
				if entryArray, ok := entry.([]interface{}); ok && len(entryArray) >= 3 {
					domains := entryArray[0]
					ip, ok := entryArray[2].(string)
					if !ok || !isValidIP(ip) {
						continue
					}

					recordType := "A"
					if strings.Contains(ip, ":") {
						recordType = "AAAA"
					}

					if domainArray, ok := domains.([]interface{}); ok {
						for _, d := range domainArray {
							if domain, ok := d.(string); ok && domain != "" {
								record := NewDNSRecord(domain, ip, recordType)
								s.records = append(s.records, record)
								count++
							}
						}
					} else if domain, ok := domains.(string); ok && domain != "" {
						record := NewDNSRecord(domain, ip, recordType)
						s.records = append(s.records, record)
						count++
					}
				}
			}
		case map[string]interface{}:
			// Handle object format: {"domain": "ip"}
			for domain, ipInterface := range data {
				if ip, ok := ipInterface.(string); ok && isValidIP(ip) {
					recordType := "A"
					if strings.Contains(ip, ":") {
						recordType = "AAAA"
					}
					record := NewDNSRecord(domain, ip, recordType)
					s.records = append(s.records, record)
					count++
				}
			}
		default:
			s.logger.Printf("Unsupported remote source format: %s", source.Name)
		}
	} else {
		// Try to parse as hosts format
		lines := strings.Split(string(body), "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}

			parts := strings.Fields(line)
			if len(parts) >= 2 {
				ip := parts[0]
				domains := parts[1:]

				if isValidIP(ip) {
					recordType := "A"
					if strings.Contains(ip, ":") {
						recordType = "AAAA"
					}

					for _, domain := range domains {
						record := NewDNSRecord(domain, ip, recordType)
						s.records = append(s.records, record)
						count++
					}
				}
			}
		}
	}

	s.logger.Printf("Remote source loaded: %s, %d records", source.Name, count)
}

// isValidIP checks if an IP address is valid
func isValidIP(ip string) bool {
	return net.ParseIP(ip) != nil
}

// findRecord finds a DNS record for the given domain and type
func (s *DNSServer) findRecord(domain, recordType string) *DNSRecord {
	s.recordsMutex.RLock()
	defer s.recordsMutex.RUnlock()

	for _, record := range s.records {
		if record.RecordType == recordType && record.Matches(domain) {
			return record
		}
	}
	return nil
}

// queryUpstream queries upstream DNS servers
func (s *DNSServer) queryUpstream(domain string, qtype uint16) []dns.RR {
	client := &dns.Client{Timeout: 3 * time.Second}

	for _, upstream := range s.upstreamServers {
		msg := &dns.Msg{}
		msg.SetQuestion(dns.Fqdn(domain), qtype)

		resp, _, err := client.Exchange(msg, upstream)
		if err != nil {
			s.logger.Printf("Failed to query upstream %s: %v", upstream, err)
			continue
		}

		if resp.Rcode == dns.RcodeSuccess && len(resp.Answer) > 0 {
			return resp.Answer
		}
	}

	return nil
}

// handleDNSRequest handles DNS queries
func (s *DNSServer) handleDNSRequest(w dns.ResponseWriter, r *dns.Msg) {
	msg := &dns.Msg{}
	msg.SetReply(r)

	if len(r.Question) == 0 {
		msg.Rcode = dns.RcodeFormatError
		w.WriteMsg(msg)
		return
	}

	question := r.Question[0]
	domain := strings.TrimSuffix(question.Name, ".")
	qtype := question.Qtype

	s.logger.Printf("DNS query: %s (%s) from %s", domain, dns.TypeToString[qtype], w.RemoteAddr())

	// Determine record type
	recordType := "A"
	if qtype == dns.TypeAAAA {
		recordType = "AAAA"
	}

	// Check local records first
	if record := s.findRecord(domain, recordType); record != nil {
		s.logger.Printf("Local resolution: %s -> %s", domain, record.IP)

		var rr dns.RR
		var err error

		if recordType == "A" {
			rr, err = dns.NewRR(fmt.Sprintf("%s A %s", question.Name, record.IP))
		} else {
			rr, err = dns.NewRR(fmt.Sprintf("%s AAAA %s", question.Name, record.IP))
		}

		if err == nil {
			msg.Answer = append(msg.Answer, rr)
			w.WriteMsg(msg)
			return
		}
	}

	// Query upstream DNS servers
	answers := s.queryUpstream(domain, qtype)
	if len(answers) > 0 {
		s.logger.Printf("Upstream resolution: %s", domain)
		msg.Answer = answers
		w.WriteMsg(msg)
		return
	}

	// No answer found
	s.logger.Printf("Resolution failed: %s", domain)
	msg.Rcode = dns.RcodeNameError
	w.WriteMsg(msg)
}

// handleDoHRequest handles DNS over HTTPS (DoH) requests
func (s *DNSServer) handleDoHRequest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost && r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	var dnsQuery []byte
	var origName string
	var origType uint16 = 1
	nameParam := ""
	if r.Method == http.MethodPost {
		if ct := r.Header.Get("Content-Type"); ct != "application/dns-message" {
			w.WriteHeader(http.StatusUnsupportedMediaType)
			return
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		dnsQuery = body
	} else if r.Method == http.MethodGet {
		dnsParam := r.URL.Query().Get("dns")
		nameParam = r.URL.Query().Get("name")
		if dnsParam != "" {
			decoded, err := decodeBase64URL(dnsParam)
			if err != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			dnsQuery = decoded
		} else if nameParam != "" {
			domain := nameParam
			typeParam := strings.ToUpper(r.URL.Query().Get("type"))
			var qtype uint16 = 1 // 默认A
			if typeParam == "AAAA" {
				qtype = 28
			}
			msg := new(dns.Msg)
			msg.SetQuestion(dns.Fqdn(domain), qtype)
			wire, err := msg.Pack()
			if err != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			dnsQuery = wire
			origName = dns.Fqdn(domain)
			origType = qtype
		} else {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
	}

	msg := new(dns.Msg)
	if err := msg.Unpack(dnsQuery); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	resp := s.doDoHQuery(msg, r.RemoteAddr)

	// 检查是否要求返回 JSON
	ctParam := r.URL.Query().Get("ct")
	ctParam2 := r.URL.Query().Get("content-type")
	// 默认: 只要是 GET 且有 name 参数，且未显式要求 wire format，就返回 JSON
	wantJSON := false
	if r.Method == http.MethodGet && nameParam != "" {
		if ctParam == "" && ctParam2 == "" {
			wantJSON = true
		}
	}
	if ctParam == "application/dns-json" || ctParam2 == "application/dns-json" {
		wantJSON = true
	}
	if ctParam == "application/dns-message" || ctParam2 == "application/dns-message" {
		wantJSON = false
	}

	if wantJSON && (origName != "" || (len(resp.Question) > 0)) {
		// 组装 Cloudflare 风格 JSON
		qName := origName
		qType := origType
		if qName == "" && len(resp.Question) > 0 {
			qName = resp.Question[0].Name
			qType = resp.Question[0].Qtype
		}
		jsonResp := map[string]interface{}{
			"Status": resp.Rcode,
			"TC":     resp.Truncated,
			"RD":     resp.RecursionDesired,
			"RA":     resp.RecursionAvailable,
			"AD":     resp.AuthenticatedData,
			"CD":     resp.CheckingDisabled,
			"Question": []map[string]interface{}{
				{"name": qName, "type": qType},
			},
		}
		// Answer
		answers := []map[string]interface{}{}
		for _, rr := range resp.Answer {
			m := map[string]interface{}{
				"name": rr.Header().Name,
				"type": rr.Header().Rrtype,
				"TTL":  rr.Header().Ttl,
			}
			switch v := rr.(type) {
			case *dns.A:
				m["data"] = v.A.String()
			case *dns.AAAA:
				m["data"] = v.AAAA.String()
			case *dns.CNAME:
				m["data"] = v.Target
			default:
				m["data"] = rr.String()
			}
			answers = append(answers, m)
		}
		jsonResp["Answer"] = answers
		w.Header().Set("Content-Type", "application/dns-json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(jsonResp)
		return
	}

	packed, err := resp.Pack()
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/dns-message")
	w.WriteHeader(http.StatusOK)
	w.Write(packed)
}

// doDoHQuery processes a DNS query and returns a response (for DoH)
func (s *DNSServer) doDoHQuery(r *dns.Msg, remoteAddr string) *dns.Msg {
	msg := &dns.Msg{}
	msg.SetReply(r)

	if len(r.Question) == 0 {
		msg.Rcode = dns.RcodeFormatError
		return msg
	}

	question := r.Question[0]
	domain := strings.TrimSuffix(question.Name, ".")
	qtype := question.Qtype

	s.logger.Printf("DoH query: %s (%s) from %s", domain, dns.TypeToString[qtype], remoteAddr)

	recordType := "A"
	if qtype == dns.TypeAAAA {
		recordType = "AAAA"
	}

	if record := s.findRecord(domain, recordType); record != nil {
		s.logger.Printf("Local resolution: %s -> %s", domain, record.IP)
		var rr dns.RR
		var err error
		if recordType == "A" {
			rr, err = dns.NewRR(fmt.Sprintf("%s A %s", question.Name, record.IP))
		} else {
			rr, err = dns.NewRR(fmt.Sprintf("%s AAAA %s", question.Name, record.IP))
		}
		if err == nil {
			msg.Answer = append(msg.Answer, rr)
			return msg
		}
	}

	answers := s.queryUpstream(domain, qtype)
	if len(answers) > 0 {
		s.logger.Printf("Upstream resolution: %s", domain)
		msg.Answer = answers
		return msg
	}

	s.logger.Printf("Resolution failed: %s", domain)
	msg.Rcode = dns.RcodeNameError
	return msg
}

// decodeBase64URL decodes base64url (RFC4648) string
func decodeBase64URL(s string) ([]byte, error) {
	// Add padding if needed
	switch len(s) % 4 {
	case 2:
		s += "=="
	case 3:
		s += "="
	}
	return base64.RawURLEncoding.DecodeString(s)
}

// updateRulesPeriodically updates rules periodically
func (s *DNSServer) updateRulesPeriodically() {
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			s.logger.Printf("Starting DNS rules update...")
			oldCount := len(s.records)
			s.loadRules()
			newCount := len(s.records)
			s.logger.Printf("Rules update completed: %d -> %d", oldCount, newCount)
		case <-s.stopChan:
			return
		}
	}
}

// Start starts the DNS server
func (s *DNSServer) Start() error {
	address := fmt.Sprintf("%s:%d", s.config.General.Address, s.config.General.Port)

	dns.HandleFunc(".", s.handleDNSRequest)

	s.server = &dns.Server{
		Addr: address,
		Net:  "udp",
	}

	s.running = true
	s.logger.Printf("DNS server started successfully: %s", address)
	s.logger.Printf("Loaded %d DNS records", len(s.records))

	// Start periodic rules update
	go s.updateRulesPeriodically()

	return s.server.ListenAndServe()
}

// StartDoH starts the DoH server
func (s *DNSServer) StartDoH() error {
	cfg := s.config.General
	s.dohPort = cfg.DohPort
	s.dohHTTPS = cfg.DohHTTPS
	s.certCacheDir = cfg.CertCacheDir
	s.domain = cfg.Domain

	if s.dohPort == 0 {
		s.dohPort = 8080 // Default to 8080 if not set
	}

	http.HandleFunc("/dns-query", s.handleDoHRequest)

	if s.dohHTTPS {
		manager := &autocert.Manager{
			Cache:      autocert.DirCache(s.certCacheDir),
			Prompt:     autocert.AcceptTOS,
			HostPolicy: autocert.HostWhitelist(s.domain),
		}
		server := &http.Server{
			Addr:      fmt.Sprintf(":%d", s.dohPort),
			Handler:   nil,
			TLSConfig: manager.TLSConfig(),
		}
		s.logger.Printf("DoH HTTPS server started at https://%s/dns-query", fmt.Sprintf(":%d", s.dohPort))
		return server.ListenAndServeTLS("", "")
	} else {
		s.logger.Printf("DoH HTTP server started at http://%s/dns-query", fmt.Sprintf(":%d", s.dohPort))
		return http.ListenAndServe(fmt.Sprintf(":%d", s.dohPort), nil)
	}
}

// Stop stops the DNS server
func (s *DNSServer) Stop() error {
	s.running = false
	close(s.stopChan)

	if s.server != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return s.server.ShutdownContext(ctx)
	}

	s.logger.Printf("DNS server stopped")
	return nil
}

func main() {
	// Find config file
	configFile := "config.json"
	if len(os.Args) > 1 {
		configFile = os.Args[1]
	}

	// Check if config file exists
	if _, err := os.Stat(configFile); os.IsNotExist(err) {
		// Look for config file in executable directory
		execDir := filepath.Dir(os.Args[0])
		configFile = filepath.Join(execDir, "config.json")
	}

	// Create DNS server
	server, err := NewDNSServer(configFile)
	if err != nil {
		log.Fatalf("Failed to create DNS server: %v", err)
	}

	// Setup signal handling
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Start DoH server in a goroutine
	go func() {
		if err := server.StartDoH(); err != nil {
			log.Fatalf("DoH server error: %v", err)
		}
	}()

	// Wait for shutdown signal
	<-sigChan
	log.Println("Received shutdown signal, stopping server...")

	if err := server.Stop(); err != nil {
		log.Printf("Error stopping server: %v", err)
	}
}
