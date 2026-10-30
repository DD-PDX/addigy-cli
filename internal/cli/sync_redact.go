// Hand-authored for the DD-PDX fork. Not generated.
//
// Text-level secret redaction for synced rows. Ported from the
// Automa_Addigy_Tracking exporter's tools/secret_scan.py (Redactor) so the
// local mirror scrubs the same things the git snapshot does: credentials
// embedded in smart-software install scripts, custom-fact bodies,
// maintenance scripts and embedded plists. RE2 has no lookaheads or
// backreferences, so those parts of the Python patterns are checks in code.

package cli

import (
	"regexp"
	"strings"
)

// secretValueRule matches a credential inside free text. When the pattern
// has a capture group, only group 1 is replaced and the surrounding text
// (flag name, header name) is kept.
type secretValueRule struct {
	name string
	re   *regexp.Regexp
}

var secretValueRules = []secretValueRule{
	{"slack-webhook", regexp.MustCompile(`https://hooks\.slack(?:-gov)?\.com/(?:services|workflows|triggers)/[A-Za-z0-9/_-]{8,}`)},
	{"teams-webhook", regexp.MustCompile(`(?i)https://[a-z0-9.-]*(?:webhook\.office\.com|outlook\.office\.com/webhook|logic\.azure\.com)[^\s"'<>]*(?:sig|code)=[A-Za-z0-9%_-]{8,}`)},
	{"discord-webhook", regexp.MustCompile(`https://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_-]{20,}`)},
	{"generic-webhook-token", regexp.MustCompile(`(?i)https://[^\s"'<>]*/(?:hooks?|webhooks?)/[A-Za-z0-9_-]{24,}`)},
	{"url-credential-param", regexp.MustCompile(`(?i)[?&](?:api[_-]?key|apikey|token|access_token|secret|sig|signature|code|key|password|auth)=([A-Za-z0-9%._~+/-]{12,})`)},
	{"url-userinfo", regexp.MustCompile(`(?i)\b[a-z][a-z0-9+.-]*://[^\s/:@"'<>]+:([^\s/@"'<>$]{3,})@[^\s"'<>]+`)},
	{"jwt", regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}`)},
	{"jwt-base64", regexp.MustCompile(`\bZXlK[A-Za-z0-9+/]{40,}`)},
	{"pkcs12-blob", regexp.MustCompile(`\bMII[A-Za-z0-9+/]{2,3}AgEDMII[A-Za-z0-9+/]{20,}`)},
	{"private-key", regexp.MustCompile(`-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----[\s\S]*?(?:-----END (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----|$)`)},
	{"aws-access-key", regexp.MustCompile(`\b(?:AKIA|ASIA)[0-9A-Z]{16}\b`)},
	{"github-token", regexp.MustCompile(`\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}\b|\bgithub_pat_[A-Za-z0-9_]{60,}\b`)},
	{"slack-token", regexp.MustCompile(`\bxox[abposr]-[A-Za-z0-9-]{10,}`)},
	{"google-api-key", regexp.MustCompile(`\bAIza[0-9A-Za-z_-]{35}\b`)},
	{"stripe-key", regexp.MustCompile(`\b(?:sk|rk)_live_[0-9A-Za-z]{16,}\b`)},
	{"openai-anthropic-key", regexp.MustCompile(`\bsk-(?:ant-|proj-)?[A-Za-z0-9_-]{32,}\b`)},
	{"authorization-header", regexp.MustCompile(`(?i)\b(?:authorization|x-api-key|api-key|x-auth-token)\s*[:=]\s*(?:bearer\s+|basic\s+)?['"]?([A-Za-z0-9._~+/=-]{16,})`)},
	{"bearer-token", regexp.MustCompile(`(?i)\bbearer\s+([A-Za-z0-9._~+/=-]{20,})`)},
	{"curl-basic-auth", regexp.MustCompile(`(?i)\bcurl\b[^\n]*\s(?:-u|--user)\s+['"]?[^\s:'"$][^\s:'"]*:([^\s'"]{3,})`)},
	{"cli-secret-flag", regexp.MustCompile(`(?i)--(?:[a-z-]*-)?(?:api-key|apikey|token|password|passwd|secret|psk|license|site-key|registration-key)[= ]['"]?([A-Za-z0-9._~+/=@!#%^&*-]{6,})`)},
	{"dscl-passwd", regexp.MustCompile(`(?i)\b(?:dscl\b[^\n]*-passwd|sysadminctl\b[^\n]*-(?:adminP|password))\s+['"]?([^\s'"]{4,})`)},
}

var (
	// NAME = value assignments in scripts and custom fact bodies. The Python
	// original also requires a matching closing quote; without
	// backreferences this one accepts an unmatched quote, which only widens it.
	assignmentRE = regexp.MustCompile(`\b([A-Za-z_][A-Za-z0-9_]*)\s*(?::=|=|:)\s*['"]?([^'"\s;,)}\]<>]{6,})`)
	// <key>Name</key> <string>value</string> in plist / mobileconfig text.
	plistPairRE = regexp.MustCompile(`(?is)<key>\s*([^<]{1,80}?)\s*</key>\s*<(?:string|data)>(.*?)</(?:string|data)>`)
	// "key": "value" pairs in JSON text embedded in a string.
	jsonPairRE = regexp.MustCompile(`"([^"\\]{1,80})"\s*:\s*"((?:[^"\\]|\\.)*)"`)

	sensitiveKeyRE     = regexp.MustCompile(`(?i)(^|[_\W])(password|passwd|passphrase|passcode|secret|client_?secret|shared_?secret|token|bootstrap_?token|access_?token|refresh_?token|auth_?token|api_?token|api_?key|apikey|x_?api_?key|license_?key|serial_?key|registration_?(key|code)|activation_?(key|code)|private_?key|psk|pre_?shared_?key|enrollment_?(key|token|secret)|site_?key|tenant_?key|install_?token|bearer|webhook(_?url)?|hook_?url|recovery_?key|personal_?recovery_?key|prk|bypass_?code|unlock_?token|escrow_?key)($|[_\W])`)
	weakSensitiveKeyRE = regexp.MustCompile(`(?i)(^|[_\W])(authorization|auth|pin|challenge|licen[cs]e|credentials?|key_?data|pkcs12|p12)($|[_\W])`)
	safeKeyRE          = regexp.MustCompile(`(?i)^(.*_(allowed|enabled|required|disabled|exists|pending|present|compliant|escrowed|set_date|last_set_date|type|types|id|ids|uuid|name|label|title|length|age|history|reuse|count|policy|description|prompt|hint|format|status|enforced|grace_period|mode|version|url_scheme)|(allow|require|disable|enable|force|prompt|show|hide|use|is|has|can|should|ask_for|change|dont_allow|message)_.*|payload_?(type|identifier|uuid|display_?name|description|version|organization|scope)|.*password_?(policy|history|age|length|complexity|reset_ui|sync|change.*)|auth(entication)?_?(method|type|mode|protocol|server.*|domain|realm|name)|token_?(type|lifetime|expir.*)|minimum.*|maximum.*|max.*|min.*)$`)
	tokenLikeRE        = regexp.MustCompile(`(?i)^(?:basic\s+|bearer\s+)?([A-Za-z0-9+/=._~-]{16,})$`)
	placeholderRE      = regexp.MustCompile(`(?i)^(|REDACTED.*|\[REDACTED.*|SHA256:[0-9a-f]{12,}.*|\$\{?[A-Za-z_][A-Za-z0-9_]*\}?|%[A-Za-z_][A-Za-z0-9_]*%|\{\{[^}]*\}\}|<[^<>]{1,60}>|\*+|x{3,}|\.{3,}|-+|null|none|nil|true|false|yes|no|0|1|n/?a|(your|enter|insert|example|changeme|placeholder)[ _-].*)$`)
	numericLikeRE      = regexp.MustCompile(`^[0-9.:+ TZ-]{1,32}$`)
	uuidRE             = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	camelBoundaryRE    = regexp.MustCompile(`([a-z0-9])([A-Z])`)
	nonAlnumRE         = regexp.MustCompile(`[^a-z0-9]+`)
	hasDigitRE         = regexp.MustCompile(`[0-9]`)
	hasLetterRE        = regexp.MustCompile(`[A-Za-z]`)
)

// normalizeSecretKey turns "apiToken" / "API-Token" into "api_token".
func normalizeSecretKey(name string) string {
	snake := camelBoundaryRE.ReplaceAllString(strings.TrimSpace(name), "${1}_${2}")
	return strings.Trim(nonAlnumRE.ReplaceAllString(strings.ToLower(snake), "_"), "_")
}

// keyIsSensitive mirrors secret_scan.key_is_sensitive.
func keyIsSensitive(name, value string) bool {
	key := normalizeSecretKey(name)
	if key == "" || safeKeyRE.MatchString(key) {
		return false
	}
	if sensitiveKeyRE.MatchString(key) {
		return true
	}
	return weakSensitiveKeyRE.MatchString(key) && looksTokenLike(value)
}

func looksTokenLike(value string) bool {
	m := tokenLikeRE.FindStringSubmatch(strings.TrimSpace(value))
	return m != nil && hasDigitRE.MatchString(m[1]) && hasLetterRE.MatchString(m[1])
}

// valueIsPlaceholder mirrors secret_scan.value_is_placeholder.
func valueIsPlaceholder(value string) bool {
	v := strings.Trim(strings.TrimSpace(value), `'"`)
	return placeholderRE.MatchString(v) || numericLikeRE.MatchString(v) || uuidRE.MatchString(v)
}

func redactedLabel(rule string) string {
	return "REDACTED:" + rule
}

// redactSecretText replaces credentials found in free text (script bodies,
// embedded plists) and reports whether anything changed.
func redactSecretText(text string) (string, bool) {
	if text == "" {
		return text, false
	}
	orig := text
	for _, rule := range secretValueRules {
		text = replaceSubmatchOrAll(rule.re, text, func(v string) bool {
			if strings.Contains(v, "REDACTED") {
				return false
			}
			// The Python rules refuse values that are references or flags.
			return !(rule.name == "cli-secret-flag" || rule.name == "dscl-passwd") || !strings.HasPrefix(v, "-")
		}, redactedLabel(rule.name))
	}
	pair := func(re *regexp.Regexp, skipRefs bool) {
		text = re.ReplaceAllStringFunc(text, func(m string) string {
			idx := re.FindStringSubmatchIndex(m)
			if idx == nil || idx[4] < 0 {
				return m
			}
			name, value := m[idx[2]:idx[3]], m[idx[4]:idx[5]]
			if !keyIsSensitive(name, value) || valueIsPlaceholder(value) || strings.Contains(value, "REDACTED") {
				return m
			}
			if skipRefs && (strings.HasPrefix(value, "$") || strings.HasPrefix(value, "`") || strings.HasPrefix(value, "(")) {
				return m
			}
			return m[:idx[4]] + redactedLabel(normalizeSecretKey(name)) + m[idx[5]:]
		})
	}
	pair(plistPairRE, false)
	pair(jsonPairRE, false)
	pair(assignmentRE, true)
	return text, text != orig
}

// replaceSubmatchOrAll replaces group 1 of each match (or the whole match
// when the pattern has no group) with repl, when keep(value) allows it.
func replaceSubmatchOrAll(re *regexp.Regexp, text string, keep func(string) bool, repl string) string {
	return re.ReplaceAllStringFunc(text, func(m string) string {
		idx := re.FindStringSubmatchIndex(m)
		if idx == nil {
			return m
		}
		start, end := idx[0], idx[1]
		if len(idx) >= 4 && idx[2] >= 0 {
			start, end = idx[2], idx[3]
		}
		if !keep(m[start:end]) {
			return m
		}
		return m[:start] + repl + m[end:]
	})
}

// syncTextRedactionExempt lists resources that are Addigy's public catalogs
// rather than org configuration: no org secrets, and rewriting their text
// would only corrupt rule definitions the compliance command reads.
var syncTextRedactionExempt = map[string]bool{
	"oa-benchmarks-pre-built":        true,
	"oa-compliance-rules-pre-built":  true,
	"mdm-configurations-definitions": true,
}

// redactSecretsDeep applies the scanner's key rule and text rules to every
// string in a decoded row, in place.
func redactSecretsDeep(v any, key string) (any, bool) {
	switch t := v.(type) {
	case map[string]any:
		changed := false
		for k, child := range t {
			if nv, c := redactSecretsDeep(child, k); c {
				t[k] = nv
				changed = true
			}
		}
		return t, changed
	case []any:
		changed := false
		for i, child := range t {
			if nv, c := redactSecretsDeep(child, key); c {
				t[i] = nv
				changed = true
			}
		}
		return t, changed
	case string:
		if key != "" && keyIsSensitive(key, t) && !valueIsPlaceholder(t) {
			return redactedLabel(normalizeSecretKey(key)), true
		}
		return redactSecretText(t)
	}
	return v, false
}
