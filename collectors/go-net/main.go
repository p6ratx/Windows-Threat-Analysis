package main

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"
)

type Entity struct {
	Kind  string                 `json:"kind"`
	ID    string                 `json:"id"`
	Label string                 `json:"label,omitempty"`
	Attrs map[string]interface{} `json:"attrs,omitempty"`
}

type Edge struct {
	Src        string  `json:"src"`
	Dst        string  `json:"dst"`
	Rel        string  `json:"rel"`
	Confidence float64 `json:"confidence,omitempty"`
}

type Event struct {
	TS       string                 `json:"ts"`
	Agent    string                 `json:"agent"`
	HostID   string                 `json:"host_id"`
	Type     string                 `json:"type"`
	Severity string                 `json:"severity"`
	Entities []Entity               `json:"entities"`
	Edges    []Edge                 `json:"edges"`
	Raw      map[string]interface{} `json:"raw"`
}

func main() {
	defer func() {
		if r := recover(); r != nil {
			fmt.Fprintf(os.Stderr, "go-net panic: %v\n", r)
			os.Exit(1)
		}
	}()
	hostID := envOr("AEGIS_HOST_ID", hostname())
	if len(hostID) > 128 {
		hostID = hostID[:128]
	}
	events := collect(hostID)
	enc := json.NewEncoder(os.Stdout)
	for _, e := range events {
		if err := enc.Encode(e); err != nil {
			fmt.Fprintf(os.Stderr, "encode: %v\n", err)
			break
		}
	}
}

func collect(hostID string) []Event {
	now := time.Now().UTC().Format(time.RFC3339)
	var out []Event
	procNames := processNameByPID()
	conns := listEstablished(procNames)
	peersByPID := map[int][]string{}
	for _, c := range conns {
		peersByPID[c.PID] = append(peersByPID[c.PID], fmt.Sprintf("%s:%d", c.RemoteIP, c.RemotePort))
	}

	listeners := listListeners()
	for i := range listeners {
		if name, ok := procNames[listeners[i].PID]; ok && name != "" {
			listeners[i].Process = name
		}
	}
	for _, l := range listeners {
		sev := "info"
		if l.Bind == "0.0.0.0" || l.Bind == "::" || l.Bind == "*" {
			sev = "medium"
		}
		if l.Port == 445 || l.Port == 3389 || l.Port == 23 || l.Port == 21 {
			sev = "high"
		}
		fn := portFunction(l.Port)
		portID := fmt.Sprintf("%s:%d", hostID, l.Port)
		procID := fmt.Sprintf("pid:%d", l.PID)
		peers := peersByPID[l.PID]
		if len(peers) > 12 {
			peers = peers[:12]
		}
		ents := []Entity{
			{Kind: "host", ID: hostID, Label: hostID},
			{Kind: "port", ID: portID, Label: fmt.Sprintf("%s %d", strings.ToUpper(l.Proto), l.Port), Attrs: map[string]interface{}{
				"port": l.Port, "proto": l.Proto, "bind": l.Bind,
				"function": fn, "peer_count": len(peersByPID[l.PID]),
			}},
		}
		edges := []Edge{{Src: hostID, Dst: portID, Rel: "exposes", Confidence: 0.9}}
		if l.PID > 0 {
			ents = append(ents, Entity{Kind: "process", ID: procID, Label: l.Process, Attrs: map[string]interface{}{
				"pid": l.PID, "function": fn,
			}})
			edges = append(edges, Edge{Src: procID, Dst: portID, Rel: "listens", Confidence: 0.85})
		}
		out = append(out, Event{
			TS: now, Agent: "go-net", HostID: hostID, Type: "net.port.listen", Severity: sev,
			Entities: ents, Edges: edges,
			Raw: map[string]interface{}{
				"listener":          l,
				"function":          fn,
				"how":               portHow(l.Port, l.Bind),
				"established_peers": peers,
				"activity":          "accepts_inbound_or_holds_listener",
			},
		})
		if sev == "high" {
			out = append(out, Event{
				TS: now, Agent: "go-net", HostID: hostID, Type: "net.misconfig", Severity: "high",
				Entities: ents, Edges: edges,
				Raw: map[string]interface{}{
					"heuristic": "sensitive_port_exposed",
					"port":      l.Port,
					"function":  fn,
					"how":       portHow(l.Port, l.Bind),
					"why_risk":  "Sensitive admin/file protocol bound broadly",
				},
			})
		}
	}

	out = append(out, peerAndC2Events(hostID, now, conns)...)

	if anom := connectionAnomaly(hostID, now); anom != nil {
		out = append(out, *anom)
	}
	return out
}

func portFunction(port int) string {
	switch port {
	case 445:
		return "smb"
	case 3389:
		return "rdp"
	case 135:
		return "rpc"
	case 139:
		return "netbios"
	case 5985, 5986, 47001:
		return "winrm"
	case 53:
		return "dns"
	case 80:
		return "http"
	case 443:
		return "https"
	case 21:
		return "ftp"
	case 22:
		return "ssh"
	case 23:
		return "telnet"
	default:
		return "network"
	}
}

func portHow(port int, bind string) string {
	return fmt.Sprintf("Process holds %s listener on %s — function=%s", fmt.Sprintf("%d", port), bind, portFunction(port))
}

type conn struct {
	Proto      string
	LocalIP    string
	LocalPort  int
	RemoteIP   string
	RemotePort int
	PID        int
	Process    string
	Public     bool
	Private    bool
	Loopback   bool
}

func processNameByPID() map[int]string {
	out := map[int]string{}
	if runtime.GOOS != "windows" {
		return out
	}
	cmd := exec.Command("tasklist", "/fo", "csv", "/nh")
	b, err := cmd.Output()
	if err != nil {
		return out
	}
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		// "name.exe","1234","Session Name","Session#","Mem Usage"
		parts := strings.Split(line, "\",\"")
		if len(parts) < 2 {
			continue
		}
		name := strings.Trim(parts[0], "\"")
		pidStr := strings.Trim(parts[1], "\"")
		pid, err := strconv.Atoi(pidStr)
		if err != nil || pid <= 0 {
			continue
		}
		out[pid] = name
	}
	return out
}

func listEstablished(procNames map[int]string) []conn {
	if runtime.GOOS != "windows" {
		return nil
	}
	cmd := exec.Command("netstat", "-ano")
	b, err := cmd.Output()
	if err != nil {
		return nil
	}
	var out []conn
	seen := map[string]struct{}{}
	for _, line := range strings.Split(string(b), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}
		proto := strings.ToLower(fields[0])
		if proto != "tcp" && proto != "tcpv6" {
			continue
		}
		if !strings.EqualFold(fields[3], "ESTABLISHED") {
			continue
		}
		localHost, localPortStr, err1 := splitHostPort(fields[1])
		remoteHost, remotePortStr, err2 := splitHostPort(fields[2])
		if err1 != nil || err2 != nil {
			continue
		}
		localPort, _ := strconv.Atoi(localPortStr)
		remotePort, _ := strconv.Atoi(remotePortStr)
		pid, _ := strconv.Atoi(fields[len(fields)-1])
		if pid <= 0 || remotePort <= 0 {
			continue
		}
		remoteIP := normalizeBind(remoteHost)
		localIP := normalizeBind(localHost)
		key := fmt.Sprintf("%d|%s|%d|%s|%d", pid, localIP, localPort, remoteIP, remotePort)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		proc := procNames[pid]
		if proc == "" {
			proc = fmt.Sprintf("pid-%d", pid)
		}
		c := conn{
			Proto: strings.TrimSuffix(proto, "v6"), LocalIP: localIP, LocalPort: localPort,
			RemoteIP: remoteIP, RemotePort: remotePort, PID: pid, Process: proc,
			Loopback: isLoopbackIP(remoteIP), Private: isPrivateIP(remoteIP), Public: isPublicIP(remoteIP),
		}
		out = append(out, c)
	}
	return out
}

func isLoopbackIP(ip string) bool {
	ip = strings.Trim(ip, "[]")
	return ip == "127.0.0.1" || ip == "::1" || strings.HasPrefix(ip, "127.")
}

func isPrivateIP(ip string) bool {
	ip = strings.Trim(ip, "[]")
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	if parsed.IsLoopback() || parsed.IsLinkLocalUnicast() || parsed.IsLinkLocalMulticast() {
		return true
	}
	priv := []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7", "fe80::/10"}
	for _, cidr := range priv {
		_, n, err := net.ParseCIDR(cidr)
		if err == nil && n.Contains(parsed) {
			return true
		}
	}
	return false
}

func isPublicIP(ip string) bool {
	ip = strings.Trim(ip, "[]")
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	if parsed.IsLoopback() || parsed.IsUnspecified() || parsed.IsMulticast() {
		return false
	}
	return !isPrivateIP(ip) && !isLoopbackIP(ip)
}

func softwareClass(process string) (string, float64) {
	p := strings.ToLower(process)
	known := []struct {
		class string
		conf  float64
		match []string
	}{
		{"browser", 0.92, []string{"msedge.exe", "chrome.exe", "firefox.exe", "brave.exe", "opera.exe", "iexplore.exe", "msedgewebview2.exe"}},
		{"windows_ui", 0.9, []string{
			"searchapp.exe", "searchhost.exe", "searchindexer.exe", "startmenuexperiencehost.exe",
			"shellexperiencehost.exe", "applicationframehost.exe", "systemsettings.exe",
			"textinputhost.exe", "lockapp.exe", "widgets.exe", "widgetservice.exe",
			"phoneexperiencehost.exe", "gamebar.exe", "gamebarftserver.exe", "explorer.exe",
		}},
		{"microsoft_system", 0.9, []string{
			"svchost.exe", "system", "lsass.exe", "services.exe", "wininit.exe", "csrss.exe", "smss.exe",
			"spoolsv.exe", "runtimebroker.exe", "sihost.exe", "taskhostw.exe", "dwm.exe", "winlogon.exe",
			"fontdrvhost.exe", "conhost.exe", "dllhost.exe", "wmiprvse.exe", "taskmgr.exe",
			"powershell.exe", "pwsh.exe", "cmd.exe",
		}},
		{"microsoft_update", 0.88, []string{"usoclient.exe", "wuauclt.exe", "moagent.exe", "tiworker.exe", "trustedinstaller.exe"}},
		{"dev_tool", 0.85, []string{
			"cursor.exe", "code.exe", "devenv.exe", "node.exe", "python.exe", "python3", "python3.",
			"go.exe", "git.exe", "docker.exe", "com.docker.backend.exe", "lm studio.exe",
		}},
		{"office_collab", 0.84, []string{"outlook.exe", "teams.exe", "ms-teams.exe", "winword.exe", "excel.exe", "powerpnt.exe", "onedrive.exe"}},
		{"security_agent", 0.86, []string{"msmpeng.exe", "securityhealthservice.exe", "sense.exe", "mssense.exe"}},
		{"remote_access", 0.8, []string{"mstsc.exe", "anydesk.exe", "teamviewer.exe", "vnc", "ssh.exe"}},
		{"hypervisor", 0.84, []string{"vmware-authd.exe", "vmware-hostd.exe", "vmware-vmx.exe", "vmnat.exe", "vmmem"}},
	}
	for _, k := range known {
		for _, m := range k.match {
			if p == m || strings.Contains(p, m) {
				return k.class, k.conf
			}
		}
	}
	if strings.HasSuffix(p, ".exe") {
		return "unknown_process", 0.35
	}
	return "unclassified", 0.2
}

func remotePortRole(port int) string {
	switch port {
	case 80:
		return "http"
	case 443:
		return "https"
	case 53:
		return "dns"
	case 22:
		return "ssh"
	case 21:
		return "ftp"
	case 25, 465, 587:
		return "smtp"
	case 110, 993, 995:
		return "mail"
	case 3389:
		return "rdp"
	case 445, 139:
		return "smb"
	case 135:
		return "rpc"
	case 853:
		return "dot"
	case 8080, 8443, 8000, 8888:
		return "alt_http"
	case 4444, 4445, 1337, 31337, 5555, 6666, 12345, 1234, 9001, 9050:
		return "suspicious_c2_port"
	default:
		return "other"
	}
}

func scoreC2(c conn, swClass string) (float64, []string, string) {
	reasons := []string{}
	score := 0.0
	role := remotePortRole(c.RemotePort)
	doing := fmt.Sprintf("%s established TCP to %s:%d (%s)", c.Process, c.RemoteIP, c.RemotePort, role)

	if c.Loopback {
		return 0, nil, doing
	}
	if c.Private {
		if role == "suspicious_c2_port" || role == "ssh" || role == "rdp" {
			score += 0.35
			reasons = append(reasons, "private_peer_admin_or_tool_port")
		}
		return score, reasons, doing
	}
	if !c.Public {
		return 0, nil, doing
	}

	switch swClass {
	case "browser", "microsoft_update", "office_collab", "security_agent", "dev_tool", "windows_ui", "hypervisor":
		// expected outbound / local tooling — do not elevate to C2 on normal ports
		if role == "https" || role == "http" || role == "dns" || role == "dot" {
			return 0, nil, doing
		}
	case "microsoft_system":
		if role != "https" && role != "http" && role != "dns" && role != "dot" {
			score += 0.45
			reasons = append(reasons, "system_process_unusual_public_port")
		} else {
			return 0, nil, doing
		}
	case "unknown_process", "unclassified":
		score += 0.55
		reasons = append(reasons, "unknown_process_public_egress")
	default:
		score += 0.2
		reasons = append(reasons, "non_allowlisted_process_public_egress")
	}

	if role == "suspicious_c2_port" {
		score += 0.5
		reasons = append(reasons, "known_abuse_port")
	}
	if role == "other" && c.RemotePort < 1024 && c.RemotePort != 80 && c.RemotePort != 443 {
		score += 0.25
		reasons = append(reasons, "unusual_privileged_remote_port")
	}
	if role == "other" && c.RemotePort >= 1024 {
		score += 0.2
		reasons = append(reasons, "high_port_public_egress")
	}
	if role == "ssh" || role == "rdp" || role == "smb" {
		score += 0.35
		reasons = append(reasons, "admin_protocol_to_public_ip")
	}
	if score > 1 {
		score = 1
	}
	return score, reasons, doing
}

func peerAndC2Events(hostID, now string, conns []conn) []Event {
	if len(conns) == 0 {
		return nil
	}
	var out []Event
	byIP := map[string]int{}
	byProc := map[string]int{}
	publicCount := 0
	privateCount := 0
	var destinations []map[string]interface{}
	var c2Hits []conn
	var c2Meta []map[string]interface{}

	for _, c := range conns {
		byIP[c.RemoteIP]++
		byProc[c.Process]++
		if c.Public {
			publicCount++
		} else if c.Private {
			privateCount++
		}
		sw, conf := softwareClass(c.Process)
		c2, reasons, doing := scoreC2(c, sw)
		peerID := fmt.Sprintf("peer:%s:%d", c.RemoteIP, c.RemotePort)
		procID := fmt.Sprintf("pid:%d", c.PID)
		destinations = append(destinations, map[string]interface{}{
			"remote_ip": c.RemoteIP, "remote_port": c.RemotePort, "pid": c.PID,
			"process": c.Process, "local": fmt.Sprintf("%s:%d", c.LocalIP, c.LocalPort),
			"public": c.Public, "private": c.Private, "software_class": sw,
			"attribution_confidence": conf, "c2_score": c2, "c2_reasons": reasons,
			"doing": doing, "port_role": remotePortRole(c.RemotePort),
		})
		if c2 >= 0.45 {
			c2Hits = append(c2Hits, c)
			c2Meta = append(c2Meta, map[string]interface{}{
				"remote_ip": c.RemoteIP, "remote_port": c.RemotePort, "process": c.Process,
				"pid": c.PID, "score": c2, "reasons": reasons, "doing": doing, "software_class": sw,
			})
			sev := "medium"
			if c2 >= 0.75 {
				sev = "high"
			}
			ents := []Entity{
				{Kind: "host", ID: hostID, Label: hostID},
				{Kind: "process", ID: procID, Label: c.Process, Attrs: map[string]interface{}{
					"pid": c.PID, "software_class": sw, "attribution_confidence": conf,
				}},
				{Kind: "peer", ID: peerID, Label: fmt.Sprintf("%s:%d", c.RemoteIP, c.RemotePort), Attrs: map[string]interface{}{
					"remote_ip": c.RemoteIP, "remote_port": c.RemotePort, "public": c.Public,
					"c2_score": c2, "port_role": remotePortRole(c.RemotePort),
				}},
				{Kind: "finding", ID: fmt.Sprintf("c2:%s:%d:%d", c.RemoteIP, c.RemotePort, c.PID),
					Label: fmt.Sprintf("C2 candidate %s → %s:%d", c.Process, c.RemoteIP, c.RemotePort),
					Attrs: map[string]interface{}{"c2_score": c2, "reasons": reasons}},
			}
			out = append(out, Event{
				TS: now, Agent: "go-net", HostID: hostID, Type: "net.c2.candidate", Severity: sev,
				Entities: ents,
				Edges: []Edge{
					{Src: procID, Dst: peerID, Rel: "connects_to", Confidence: 0.9},
					{Src: hostID, Dst: peerID, Rel: "egress_to", Confidence: 0.85},
				},
				Raw: map[string]interface{}{
					"connection": c, "c2_score": c2, "reasons": reasons, "doing": doing,
					"software_class": sw, "attribution": sw, "remote_ip": c.RemoteIP,
					"remote_port": c.RemotePort, "activity": "outbound_c2_heuristic",
				},
			})
		}
	}

	// Cap destinations in summary to keep event size sane
	if len(destinations) > 80 {
		destinations = destinations[:80]
	}
	topIPs := topKeys(byIP, 15)
	topProcs := topKeys(byProc, 15)

	out = append([]Event{{
		TS: now, Agent: "go-net", HostID: hostID, Type: "net.peers.summary", Severity: "info",
		Entities: []Entity{
			{Kind: "host", ID: hostID, Label: hostID},
			{Kind: "finding", ID: "peers-summary", Label: "Remote peer inventory", Attrs: map[string]interface{}{
				"established": len(conns), "public_peers": publicCount, "private_peers": privateCount,
				"unique_remote_ips": len(byIP),
			}},
		},
		Edges: []Edge{{Src: hostID, Dst: "peers-summary", Rel: "observed_as", Confidence: 0.95}},
		Raw: map[string]interface{}{
			"established_count": len(conns),
			"public_count":      publicCount,
			"private_count":     privateCount,
			"unique_remote_ips": len(byIP),
			"top_remote_ips":    topIPs,
			"top_processes":     topProcs,
			"destinations":      destinations,
			"c2_candidates":     c2Meta,
			"activity":          "enumerate_remote_peers_and_egress",
			"how":               "netstat ESTABLISHED + process attribution + C2 heuristics",
		},
	}}, out...)

	_ = c2Hits
	return out
}

func topKeys(m map[string]int, n int) []map[string]interface{} {
	type kv struct {
		k string
		v int
	}
	var items []kv
	for k, v := range m {
		items = append(items, kv{k, v})
	}
	for i := 0; i < len(items); i++ {
		for j := i + 1; j < len(items); j++ {
			if items[j].v > items[i].v {
				items[i], items[j] = items[j], items[i]
			}
		}
	}
	if len(items) > n {
		items = items[:n]
	}
	out := make([]map[string]interface{}, 0, len(items))
	for _, it := range items {
		out = append(out, map[string]interface{}{"key": it.k, "count": it.v})
	}
	return out
}

type listener struct {
	Proto   string
	Bind    string
	Port    int
	PID     int
	Process string
}

func listListeners() []listener {
	if runtime.GOOS == "windows" {
		return listListenersWindows()
	}
	return listListenersUnix()
}

func allowSynthetic() bool {
	return os.Getenv("AEGIS_ALLOW_SYNTHETIC") == "1"
}

func listListenersWindows() []listener {
	cmd := exec.Command("netstat", "-ano")
	b, err := cmd.Output()
	if err != nil {
		return demoListeners()
	}
	var out []listener
	lines := strings.Split(string(b), "\n")
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		proto := strings.ToLower(fields[0])
		if proto != "tcp" && proto != "tcpv6" && proto != "udp" && proto != "udpv6" {
			continue
		}
		stateIdx := 3
		pidIdx := len(fields) - 1
		if strings.HasPrefix(proto, "tcp") {
			if len(fields) < 5 || !strings.EqualFold(fields[3], "LISTENING") {
				continue
			}
			stateIdx = 3
			_ = stateIdx
		}
		local := fields[1]
		host, portStr, err := splitHostPort(local)
		if err != nil {
			continue
		}
		port, _ := strconv.Atoi(portStr)
		pid, _ := strconv.Atoi(fields[pidIdx])
		out = append(out, listener{Proto: strings.TrimSuffix(proto, "v6"), Bind: normalizeBind(host), Port: port, PID: pid, Process: fmt.Sprintf("pid-%d", pid)})
	}
	if len(out) == 0 {
		return demoListeners()
	}
	return out
}

func listListenersUnix() []listener {
	cmd := exec.Command("ss", "-lptu")
	b, err := cmd.Output()
	if err != nil {
		return demoListeners()
	}
	var out []listener
	for _, line := range strings.Split(string(b), "\n") {
		if !strings.Contains(line, "LISTEN") && !strings.Contains(line, "UNCONN") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}
		proto := strings.ToLower(fields[0])
		local := fields[4]
		host, portStr, err := splitHostPort(local)
		if err != nil {
			continue
		}
		port, _ := strconv.Atoi(portStr)
		out = append(out, listener{Proto: proto, Bind: normalizeBind(host), Port: port, PID: 0, Process: "unknown"})
	}
	if len(out) == 0 {
		return demoListeners()
	}
	return out
}

// demoListeners only when AEGIS_ALLOW_SYNTHETIC=1 — never inject fake SMB/RDP in production.
func demoListeners() []listener {
	if !allowSynthetic() {
		return nil
	}
	return []listener{
		{Proto: "tcp", Bind: "0.0.0.0", Port: 445, PID: 4, Process: "System"},
		{Proto: "tcp", Bind: "0.0.0.0", Port: 3389, PID: 1000, Process: "svchost.exe"},
		{Proto: "tcp", Bind: "127.0.0.1", Port: 8787, PID: 2000, Process: "node"},
	}
}

func connectionAnomaly(hostID, now string) *Event {
	// Lightweight heuristic: many distinct remote peers via netstat ESTABLISHED count
	cmd := exec.Command("netstat", "-ano")
	if runtime.GOOS != "windows" {
		cmd = exec.Command("ss", "-tan")
	}
	b, err := cmd.Output()
	if err != nil {
		return nil
	}
	peers := map[string]struct{}{}
	for _, line := range strings.Split(string(b), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		joined := strings.ToUpper(strings.Join(fields, " "))
		if !strings.Contains(joined, "ESTAB") {
			continue
		}
		remote := fields[2]
		if runtime.GOOS != "windows" && len(fields) > 4 {
			remote = fields[4]
		}
		peers[remote] = struct{}{}
	}
	if len(peers) < 40 {
		return nil
	}
	findingID := "conn-fanout"
	return &Event{
		TS: now, Agent: "go-net", HostID: hostID, Type: "net.conn.anomaly", Severity: "medium",
		Entities: []Entity{
			{Kind: "host", ID: hostID, Label: hostID},
			{Kind: "finding", ID: findingID, Label: "High connection fan-out", Attrs: map[string]interface{}{"peers": len(peers)}},
		},
		Edges: []Edge{{Src: hostID, Dst: findingID, Rel: "observed_as", Confidence: 0.6}},
		Raw:   map[string]interface{}{"peer_count": len(peers)},
	}
}

func splitHostPort(addr string) (string, string, error) {
	addr = strings.TrimSpace(addr)
	if strings.Count(addr, ":") > 1 {
		// [ipv6]:port or ipv6:port
		if strings.HasPrefix(addr, "[") {
			return net.SplitHostPort(addr)
		}
		idx := strings.LastIndex(addr, ":")
		return addr[:idx], addr[idx+1:], nil
	}
	return net.SplitHostPort(addr)
}

func normalizeBind(h string) string {
	h = strings.Trim(h, "[]")
	if h == "0.0.0.0" || h == "::" || h == "*" || h == "" {
		return "0.0.0.0"
	}
	return h
}

func hostname() string {
	h, err := os.Hostname()
	if err != nil {
		return "local-host"
	}
	return h
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
