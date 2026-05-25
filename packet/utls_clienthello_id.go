package packet

import (
	"fmt"
	"sort"
	"strings"

	utls "github.com/refraction-networking/utls"
)

var DefaultClientHelloID = utls.HelloFirefox_Auto

var presetClientHelloIDs = []utls.ClientHelloID{
	utls.HelloGolang, utls.HelloCustom,
	utls.HelloRandomized, utls.HelloRandomizedALPN, utls.HelloRandomizedNoALPN,
	utls.HelloFirefox_55, utls.HelloFirefox_56, utls.HelloFirefox_63, utls.HelloFirefox_65,
	utls.HelloFirefox_99, utls.HelloFirefox_102, utls.HelloFirefox_105, utls.HelloFirefox_120,
	utls.HelloChrome_58, utls.HelloChrome_62, utls.HelloChrome_70, utls.HelloChrome_72,
	utls.HelloChrome_83, utls.HelloChrome_87, utls.HelloChrome_96,
	utls.HelloChrome_100, utls.HelloChrome_102, utls.HelloChrome_106_Shuffle,
	utls.HelloChrome_100_PSK, utls.HelloChrome_112_PSK_Shuf, utls.HelloChrome_114_Padding_PSK_Shuf,
	utls.HelloChrome_115_PQ, utls.HelloChrome_115_PQ_PSK,
	utls.HelloChrome_120, utls.HelloChrome_120_PQ, utls.HelloChrome_131, utls.HelloChrome_133,
	utls.HelloIOS_11_1, utls.HelloIOS_12_1, utls.HelloIOS_13, utls.HelloIOS_14,
	utls.HelloAndroid_11_OkHttp,
	utls.HelloEdge_85, utls.HelloEdge_106,
	utls.HelloSafari_16_0,
	utls.Hello360_7_5, utls.Hello360_11_0,
	utls.HelloQQ_11_1,
}

var browserAutoAliases = map[string]utls.ClientHelloID{
	"chrome":     utls.HelloChrome_Auto,
	"firefox":    utls.HelloFirefox_Auto,
	"safari":     utls.HelloSafari_Auto,
	"edge":       utls.HelloEdge_Auto,
	"ios":        utls.HelloIOS_Auto,
	"qq":         utls.HelloQQ_Auto,
	"360browser": utls.Hello360_Auto,
}

var clientHelloIDByName map[string]utls.ClientHelloID

func init() {
	clientHelloIDByName = make(map[string]utls.ClientHelloID, len(presetClientHelloIDs)*4+32)
	for _, id := range presetClientHelloIDs {
		registerPresetKeys(id)
	}
	for name, id := range browserAutoAliases {
		clientHelloIDByName[name] = id
	}
}

func canonicalUTLSKey(id utls.ClientHelloID) string {
	if id.Version == "0" {
		c := strings.ToLower(id.Client)
		c = strings.ReplaceAll(c, ".", "_")
		return strings.ReplaceAll(c, "-", "_")
	}
	s := strings.ToLower(id.Str())
	s = strings.ReplaceAll(s, ".", "_")
	return strings.ReplaceAll(s, "-", "_")
}

func registerPresetKeys(id utls.ClientHelloID) {
	k := canonicalUTLSKey(id)
	clientHelloIDByName[k] = id

	s := strings.ToLower(id.Str())
	clientHelloIDByName[s] = id
	clientHelloIDByName[strings.ReplaceAll(s, "-", "_")] = id
	clientHelloIDByName[strings.ReplaceAll(s, "-", "")] = id
	parts := strings.SplitN(s, "-", 2)
	if len(parts) == 2 {
		clientHelloIDByName[parts[0]+"_"+parts[1]] = id
	}
}

func UTLSHelpGroupedCSV() string {
	groups := make(map[string]map[string]struct{})
	add := func(client, name string) {
		if groups[client] == nil {
			groups[client] = make(map[string]struct{})
		}
		groups[client][name] = struct{}{}
	}

	seen := make(map[string]struct{})
	for _, id := range presetClientHelloIDs {
		s := id.Str()
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		add(id.Client, canonicalUTLSKey(id))
	}
	for short, id := range browserAutoAliases {
		add(id.Client, short)
	}

	clients := make([]string, 0, len(groups))
	for c := range groups {
		clients = append(clients, c)
	}
	sort.Strings(clients)

	var b strings.Builder
	fmt.Fprintf(&b, "%s (legacy fixed ClientHello template)\n\n", LegacyUTLSName)
	for _, c := range clients {
		names := make([]string, 0, len(groups[c]))
		for n := range groups[c] {
			names = append(names, n)
		}
		sort.Strings(names)
		fmt.Fprintf(&b, "%s\n", strings.Join(names, ", "))
	}
	return b.String()
}

func DefaultUTLSSummary() string {
	return "firefox"
}

// LegacyUTLSName is the -utls value that selects the fixed legacy ClientHello template.
const LegacyUTLSName = "none"

// IsLegacyUTLS reports whether s selects the legacy ClientHello (-utls none).
func IsLegacyUTLS(s string) bool {
	return strings.EqualFold(strings.TrimSpace(s), LegacyUTLSName)
}

func ParseClientHelloID(s string) (utls.ClientHelloID, error) {
	s = strings.TrimSpace(s)
	if IsLegacyUTLS(s) {
		return utls.ClientHelloID{}, fmt.Errorf("%q selects the legacy ClientHello template (not a uTLS preset)", s)
	}
	if s == "" {
		return DefaultClientHelloID, nil
	}
	keys := []string{
		strings.ToLower(s),
		strings.ToLower(strings.ReplaceAll(s, "-", "_")),
	}
	for _, k := range keys {
		if id, ok := clientHelloIDByName[k]; ok {
			return id, nil
		}
	}
	return utls.ClientHelloID{}, fmt.Errorf("unknown uTLS ClientHello ID %q (see -h for valid names)", s)
}
