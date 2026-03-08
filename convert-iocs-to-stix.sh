#!/usr/bin/env bash
# ══════════════════════════════════════════════════════════════════════════════
#  IOC → STIX 2.1 Converter  |  Microsoft Sentinel
#  v2.0  |  Auto-detect · Deduplicate · TLP aware
#
#  Author  : Alex Milla
#  Requires: bash 4+, python3 (stdlib only), curl
# ══════════════════════════════════════════════════════════════════════════════

set -euo pipefail

# ─────────────────────────────────────────────────────────────────────────────
#  PATHS & CONSTANTS
# ─────────────────────────────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VERSION="2.0"
CONFIG_FILE="${SCRIPT_DIR}/stix_converter_config.json"
LOG_FILE=""

# TLP marking-definition IDs (STIX 2.1 / OASIS)
declare -A TLP=(
    [white]="marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9"
    [green]="marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da"
    [amber]="marking-definition--f88d31f6-486f-44da-b317-01333bde0b82"
    [red]="marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed"
)

# Output filenames per type
declare -A TYPE_FILENAMES=(
    [ipv4-addr]="stix_ipv4.json"
    [ipv6-addr]="stix_ipv6.json"
    [domain-name]="stix_domains.json"
    [url]="stix_urls.json"
    [file]="stix_hashes.json"
    [email-addr]="stix_emails.json"
    [user-account]="stix_users.json"
    [windows-registry-key]="stix_registry.json"
)

SUPPORTED_TYPES=("ipv4-addr" "ipv6-addr" "domain-name" "url" "file" "email-addr" "user-account" "windows-registry-key")

# ─────────────────────────────────────────────────────────────────────────────
#  COLORS
# ─────────────────────────────────────────────────────────────────────────────
C_RESET="\033[0m"
C_CYAN="\033[36m"
C_DCYAN="\033[96m"
C_GREEN="\033[32m"
C_YELLOW="\033[33m"
C_RED="\033[31m"
C_WHITE="\033[97m"
C_GRAY="\033[90m"
C_DYELLOW="\033[33m"

# ─────────────────────────────────────────────────────────────────────────────
#  LOGGING
# ─────────────────────────────────────────────────────────────────────────────
log() {
    local color="${1:-$C_WHITE}"
    local msg="${2:-}"
    local nonl="${3:-}"
    if [[ "$nonl" == "nonl" ]]; then
        printf "${color}%s${C_RESET}" "$msg"
    else
        printf "${color}%s${C_RESET}\n" "$msg"
    fi
    if [[ -n "$LOG_FILE" ]]; then
        local ts
        ts=$(date -u "+%Y-%m-%d %H:%M:%S")
        printf "[%s] %s\n" "$ts" "$msg" >> "$LOG_FILE" 2>/dev/null || true
    fi
}

sep()  { log "$C_GRAY" "─────────────────────────────────────────"; }
sep2() { log "$C_GRAY" "═════════════════════════════════════════"; }

# ─────────────────────────────────────────────────────────────────────────────
#  DEPENDENCY CHECK
# ─────────────────────────────────────────────────────────────────────────────
check_deps() {
    local missing=()
    command -v python3 &>/dev/null || missing+=("python3")
    command -v curl    &>/dev/null || missing+=("curl (optional, needed for API upload)")
    if [[ ${#missing[@]} -gt 0 ]]; then
        log "$C_RED" "[ERROR] Missing dependencies: ${missing[*]}"
        log "$C_YELLOW" "        Install with: sudo apt install python3 curl"
        exit 1
    fi
}

# ─────────────────────────────────────────────────────────────────────────────
#  CONFIGURATION  (JSON via python3)
# ─────────────────────────────────────────────────────────────────────────────

# Config variables (global)
CFG_OUTPUT_FOLDER="$SCRIPT_DIR"
CFG_THREAT_ACTOR=""
CFG_SOURCE=""
CFG_TAGS=""
CFG_CONFIDENCE="75"
CFG_TLP="white"
CFG_INDICATOR_TYPES="malicious-activity"
CFG_VALID_DAYS="365"
CFG_LOG_FILE=""
CFG_API_ENABLED="false"
CFG_API_WORKSPACE_ID=""
CFG_API_ENDPOINT="https://sentinelus.azure-api.net/workspaces/{workspaceId}/threatintelligenceindicators:upload?api-version=2022-07-01"
CFG_API_BATCH_SIZE="100"

load_config() {
    [[ ! -f "$CONFIG_FILE" ]] && return
    local val
    _cfg_get() { python3 -c "
import json,sys
try:
    d=json.load(open('$CONFIG_FILE'))
    print(d.get('$1',''))
except: print('')
" 2>/dev/null; }
    _cfg_get_nested() { python3 -c "
import json,sys
try:
    d=json.load(open('$CONFIG_FILE'))
    print(d.get('API',{}).get('$1',''))
except: print('')
" 2>/dev/null; }
    _cfg_get_tags() { python3 -c "
import json,sys
try:
    d=json.load(open('$CONFIG_FILE'))
    tags=d.get('Tags',[])
    print(','.join(tags) if tags else '')
except: print('')
" 2>/dev/null; }

    val=$(_cfg_get OutputFolder);   [[ -n "$val" ]] && CFG_OUTPUT_FOLDER="$val"
    val=$(_cfg_get ThreatActor);    [[ -n "$val" ]] && CFG_THREAT_ACTOR="$val"
    val=$(_cfg_get Source);         [[ -n "$val" ]] && CFG_SOURCE="$val"
    val=$(_cfg_get_tags);           [[ -n "$val" ]] && CFG_TAGS="$val"
    val=$(_cfg_get Confidence);     [[ -n "$val" ]] && CFG_CONFIDENCE="$val"
    val=$(_cfg_get TLPLevel);       [[ -n "$val" ]] && CFG_TLP="$val"
    val=$(_cfg_get IndicatorTypes); [[ -n "$val" ]] && CFG_INDICATOR_TYPES="$val"
    val=$(_cfg_get ValidDays);      [[ -n "$val" ]] && CFG_VALID_DAYS="$val"
    val=$(_cfg_get LogFile);        [[ -n "$val" ]] && CFG_LOG_FILE="$val" && LOG_FILE="$val"
    val=$(_cfg_get_nested Enabled);     [[ -n "$val" ]] && CFG_API_ENABLED="$val"
    val=$(_cfg_get_nested WorkspaceId); [[ -n "$val" ]] && CFG_API_WORKSPACE_ID="$val"
    val=$(_cfg_get_nested Endpoint);    [[ -n "$val" ]] && CFG_API_ENDPOINT="$val"
    val=$(_cfg_get_nested BatchSize);   [[ -n "$val" ]] && CFG_API_BATCH_SIZE="$val"
}

save_config() {
    python3 - <<PYEOF
import json

tags = [t.strip() for t in "${CFG_TAGS}".split(',') if t.strip()]
api_enabled = "${CFG_API_ENABLED}".lower() in ('true','1','yes')

cfg = {
    "OutputFolder":   "${CFG_OUTPUT_FOLDER}",
    "ThreatActor":    "${CFG_THREAT_ACTOR}",
    "Source":         "${CFG_SOURCE}",
    "Tags":           tags,
    "Confidence":     int("${CFG_CONFIDENCE}"),
    "TLPLevel":       "${CFG_TLP}",
    "IndicatorTypes": "${CFG_INDICATOR_TYPES}",
    "ValidDays":      int("${CFG_VALID_DAYS}"),
    "LogFile":        "${CFG_LOG_FILE}",
    "API": {
        "Enabled":     api_enabled,
        "WorkspaceId": "${CFG_API_WORKSPACE_ID}",
        "Endpoint":    "${CFG_API_ENDPOINT}",
        "BatchSize":   int("${CFG_API_BATCH_SIZE}")
    }
}
with open("${CONFIG_FILE}", "w") as f:
    json.dump(cfg, f, indent=2)
print("  [OK] Config saved → ${CONFIG_FILE}")
PYEOF
}

# ─────────────────────────────────────────────────────────────────────────────
#  INPUT HELPERS
# ─────────────────────────────────────────────────────────────────────────────
ask() {
    # ask "Prompt" "default" → prints to stderr, returns via stdout
    local prompt="$1"
    local default="${2:-}"
    local answer
    if [[ -n "$default" ]]; then
        printf "${C_WHITE}  %s [${C_CYAN}%s${C_WHITE}]: ${C_RESET}" "$prompt" "$default" >&2
    else
        printf "${C_WHITE}  %s: ${C_RESET}" "$prompt" >&2
    fi
    read -r answer
    if [[ -z "$answer" && -n "$default" ]]; then
        echo "$default"
    else
        echo "$answer"
    fi
}

ask_bool() {
    local prompt="$1"
    local default="${2:-n}"
    local def_disp
    def_disp=$(echo "$default" | tr '[:lower:]' '[:upper:]')
    local answer
    printf "${C_YELLOW}  %s (y/n) [%s]: ${C_RESET}" "$prompt" "$def_disp" >&2
    read -r answer
    answer="${answer:-$default}"
    [[ "$answer" =~ ^[Yy] ]]
}

wait_key() {
    echo ""
    log "$C_GRAY" "  Press Enter to continue..."
    read -r
}

# ─────────────────────────────────────────────────────────────────────────────
#  UI
# ─────────────────────────────────────────────────────────────────────────────
show_banner() {
    clear
    log "$C_CYAN"  "══════════════════════════════════════════════════════"
    log "$C_CYAN"  "   IOC → STIX 2.1 Converter  |  Microsoft Sentinel   "
    log "$C_DCYAN" "   v${VERSION}  |  Auto-detect · Deduplicate · TLP aware  "
    log "$C_CYAN"  "══════════════════════════════════════════════════════"
    echo ""
}

show_menu() {
    printf "  ${C_WHITE}1.${C_RESET} ${C_GREEN}Convert file(s)${C_RESET}\n"
    printf "  ${C_WHITE}2.${C_RESET} ${C_CYAN}Upload to Sentinel API${C_RESET}\n"
    printf "  ${C_WHITE}3.${C_RESET} ${C_YELLOW}Configuration${C_RESET}\n"
    printf "  ${C_WHITE}4.${C_RESET} ${C_GRAY}Type detection test (single value)${C_RESET}\n"
    printf "  ${C_WHITE}0.${C_RESET} ${C_RED}Exit${C_RESET}\n"
    echo ""
    sep
}

show_config() {
    echo ""
    log "$C_YELLOW" "  Current configuration:"
    sep
    printf "  ${C_GRAY}%-22s${C_RESET}: ${C_WHITE}%s${C_RESET}\n" "Output folder"   "${CFG_OUTPUT_FOLDER:-  (not set)}"
    printf "  ${C_GRAY}%-22s${C_RESET}: ${C_WHITE}%s${C_RESET}\n" "Threat actor"    "${CFG_THREAT_ACTOR:-(not set)}"
    printf "  ${C_GRAY}%-22s${C_RESET}: ${C_WHITE}%s${C_RESET}\n" "Source name"     "${CFG_SOURCE:-(not set)}"
    printf "  ${C_GRAY}%-22s${C_RESET}: ${C_WHITE}%s${C_RESET}\n" "Tags"            "${CFG_TAGS:-(none)}"
    printf "  ${C_GRAY}%-22s${C_RESET}: ${C_WHITE}%s${C_RESET}\n" "Confidence"      "$CFG_CONFIDENCE"
    printf "  ${C_GRAY}%-22s${C_RESET}: ${C_WHITE}%s${C_RESET}\n" "TLP level"       "$CFG_TLP"
    printf "  ${C_GRAY}%-22s${C_RESET}: ${C_WHITE}%s${C_RESET}\n" "Indicator type"  "$CFG_INDICATOR_TYPES"
    printf "  ${C_GRAY}%-22s${C_RESET}: ${C_WHITE}%s${C_RESET}\n" "Valid days"      "$CFG_VALID_DAYS"
    printf "  ${C_GRAY}%-22s${C_RESET}: ${C_WHITE}%s${C_RESET}\n" "Log file"        "${CFG_LOG_FILE:-(disabled)}"
    if [[ "$CFG_API_ENABLED" == "true" ]]; then
        printf "  ${C_GRAY}%-22s${C_RESET}: ${C_GREEN}%s${C_RESET}\n" "API enabled"     "YES"
        printf "  ${C_GRAY}%-22s${C_RESET}: ${C_WHITE}%s${C_RESET}\n" "API WorkspaceId" "${CFG_API_WORKSPACE_ID:-(not set)}"
        printf "  ${C_GRAY}%-22s${C_RESET}: ${C_WHITE}%s${C_RESET}\n" "API batch size"  "$CFG_API_BATCH_SIZE"
    else
        printf "  ${C_GRAY}%-22s${C_RESET}: ${C_GRAY}%s${C_RESET}\n" "API enabled"     "no"
    fi
    sep
}

# ─────────────────────────────────────────────────────────────────────────────
#  AUTO-DETECT IOC TYPE  (pure bash + regex)
# ─────────────────────────────────────────────────────────────────────────────
get_ioc_type() {
    local v="$1"
    [[ -z "$v" ]] && echo "" && return

    # Windows registry key
    if [[ "$v" =~ ^HK(EY_|LM|CU|CR|U|CC) ]]; then echo "windows-registry-key"; return; fi

    # Email  (before domain — both have @)
    if [[ "$v" =~ ^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$ ]]; then echo "email-addr"; return; fi

    # URL  (before domain — domains don't have ://)
    if [[ "$v" =~ ^(https?|ftp|ftps):// ]]; then echo "url"; return; fi

    # IPv4  with optional CIDR
    if [[ "$v" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}(/[0-9]{1,2})?$ ]]; then
        local ip="${v%%/*}"
        local valid=1
        local IFS='.'
        local o1 o2 o3 o4
        read -r o1 o2 o3 o4 <<< "$ip"
        for o in "$o1" "$o2" "$o3" "$o4"; do
            [[ "$o" =~ ^[0-9]+$ ]] && [[ "$o" -gt 255 ]] && valid=0 && break
        done
        [[ "$valid" -eq 1 ]] && echo "ipv4-addr" && return
    fi

    # IPv6
    if [[ "$v" =~ ^[0-9a-fA-F]{0,4}(:[0-9a-fA-F]{0,4}){2,7}(/[0-9]{1,3})?$ ]]; then echo "ipv6-addr"; return; fi

    # Hashes — hex only, by length
    if [[ "$v" =~ ^[0-9a-fA-F]+$ ]]; then
        case ${#v} in
            32|40|64|128) echo "file"; return ;;
        esac
    fi

    # Domain-name
    if [[ "$v" =~ ^([a-zA-Z0-9_-]+\.)+[a-zA-Z]{2,}$ && ! "$v" =~ [[:space:]] ]]; then
        echo "domain-name"; return
    fi

    echo ""   # Unknown
}

get_hash_algo() {
    case ${#1} in
        32)  echo "MD5"     ;;
        40)  echo "SHA-1"   ;;
        64)  echo "SHA-256" ;;
        128) echo "SHA-512" ;;
        *)   echo "SHA-256" ;;
    esac
}

# ─────────────────────────────────────────────────────────────────────────────
#  STIX PATTERN BUILDER
# ─────────────────────────────────────────────────────────────────────────────
new_stix_pattern() {
    local type="$1" val="$2"
    case "$type" in
        ipv4-addr)            echo "[ipv4-addr:value = '${val}']" ;;
        ipv6-addr)            echo "[ipv6-addr:value = '${val}']" ;;
        domain-name)          echo "[domain-name:value = '${val}']" ;;
        url)                  echo "[url:value = '${val}']" ;;
        email-addr)           echo "[email-message:sender_ref.value = '${val}']" ;;
        user-account)         echo "[user-account:user_id = '${val}']" ;;
        windows-registry-key) echo "[windows-registry-key:key = '${val}']" ;;
        file)
            local algo
            algo=$(get_hash_algo "$val")
            case "$algo" in
                MD5)     echo "[file:hashes.MD5 = '${val}']" ;;
                SHA-1)   echo "[file:hashes.'SHA-1' = '${val}']" ;;
                SHA-256) echo "[file:hashes.'SHA-256' = '${val}']" ;;
                SHA-512) echo "[file:hashes.'SHA-512' = '${val}']" ;;
            esac ;;
        *) echo "" ;;
    esac
}

# ─────────────────────────────────────────────────────────────────────────────
#  BUILD ONE STIX INDICATOR (JSON via python3)
# ─────────────────────────────────────────────────────────────────────────────
new_stix_indicator() {
    local type="$1"
    local value="$2"
    local valid_from_raw="$3"
    local source="$4"
    local threat_actor="$5"
    local tags_csv="$6"
    local confidence="$7"
    local tlp_level="$8"
    local indicator_types="$9"
    local valid_days="${10}"

    local pattern
    pattern=$(new_stix_pattern "$type" "$value")
    local tlp_id="${TLP[$tlp_level]:-${TLP[white]}}"

    # Pass all string args via sys.argv to avoid heredoc shell-escaping issues
    python3 -c "
import json, uuid, datetime, sys

ioc_type, value, source, threat_actor, tags_csv = sys.argv[1:6]
confidence, tlp_id, ind_type, valid_from_raw, pattern = sys.argv[6:11]
valid_days = int(sys.argv[11])

now_dt    = datetime.datetime.utcnow()
now_str   = now_dt.strftime('%Y-%m-%dT%H:%M:%S.') + f'{now_dt.microsecond//1000:03d}Z'
until_str = (now_dt + datetime.timedelta(days=valid_days)).strftime('%Y-%m-%dT%H:%M:%S.') + f'{now_dt.microsecond//1000:03d}Z'

valid_from = now_str
if valid_from_raw:
    for fmt in ('%Y-%m-%d %H:%M:%S','%Y-%m-%dT%H:%M:%S','%Y-%m-%dT%H:%M:%SZ','%Y-%m-%dT%H:%M:%S.%fZ','%Y-%m-%d'):
        try:
            dt = datetime.datetime.strptime(valid_from_raw, fmt)
            valid_from = dt.strftime('%Y-%m-%dT%H:%M:%S.') + f'{dt.microsecond//1000:03d}Z'
            break
        except: pass

if source:
    name = f'{source} - {value}'
elif threat_actor:
    name = f'{threat_actor} - {ioc_type.upper()} - {value}'
else:
    name = f'{ioc_type.upper()} - {value}'

seen, labels = set(), []
for lbl in ([threat_actor] if threat_actor else []) + [ioc_type] + \
           [t.strip() for t in tags_csv.split(',') if t.strip()]:
    if lbl and lbl not in seen:
        labels.append(lbl); seen.add(lbl)

desc = f'IOC ({ioc_type}) associated with {threat_actor}' if threat_actor else f'IOC ({ioc_type}) from {source}'

obj = {
    'type':'indicator','id':f'indicator--{uuid.uuid4()}','spec_version':'2.1',
    'pattern':pattern,'pattern_type':'stix','pattern_version':'2.1',
    'created':now_str,'modified':now_str,'valid_from':valid_from,'valid_until':until_str,
    'name':name,'description':desc,'indicator_types':[ind_type],
    # created_by_ref intentionally omitted: empty string fails STIX validation in Sentinel
    'kill_chain_phases':[],'revoked':False,'labels':labels,'confidence':int(confidence),
    'lang':'en','external_references':[],'object_marking_refs':[tlp_id],
    'granular_markings':[],'extensions':{}
}
print(json.dumps(obj))
" "$type" "$value" "$source" "$threat_actor" "$tags_csv" \
  "$confidence" "$tlp_id" "$indicator_types" "$valid_from_raw" "$pattern" "$valid_days"
}

# ─────────────────────────────────────────────────────────────────────────────
#  READ IOCs FROM FILE  (outputs "type|value|date" lines)
# ─────────────────────────────────────────────────────────────────────────────
read_iocs_from_file() {
    local filepath="$1"
    local ext="${filepath##*.}"
    ext="${ext,,}"   # lowercase

    case "$ext" in
        txt|list|dat|ioc|"")
            grep -vE '^\s*(#|//|;|$)' "$filepath" | sed 's/\r//' | \
            while IFS= read -r line; do
                # Strip inline # comments only (not // — URLs contain //)
                line="${line%%#*}"
                line=$(printf '%s' "$line" | tr -d '\r' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
                [[ -n "$line" ]] && printf "%s|\n" "$line"
            done
            ;;
        csv)
            python3 - <<PYEOF
import csv, sys
rows = list(csv.DictReader(open("${filepath}", encoding='utf-8-sig')))
if not rows: sys.exit()
cols = list(rows[0].keys())
val_col  = next((c for c in cols if c.lower() in ('value','indicator','ioc','ip','domain','hash','url')), cols[0])
date_col = next((c for c in cols if c.lower() in ('date','update_date','first_seen','timestamp')), None)
for row in rows:
    v = (row.get(val_col) or '').strip()
    d = (row.get(date_col, '') or '').strip() if date_col else ''
    if v:
        print(f"{v}|{d}")
PYEOF
            ;;
        json)
            python3 - <<PYEOF
import json, sys
try:
    data = json.load(open("${filepath}", encoding='utf-8'))
except Exception as e:
    print(f"# JSON parse error: {e}", file=sys.stderr)
    sys.exit()
if not isinstance(data, list): data = [data]
for item in data:
    if not isinstance(item, dict): continue
    if item.get('type') == 'indicator' and item.get('pattern'):
        continue  # Already STIX, skip
    v = None
    for f in ('indicator','value','ioc','ip','domain','hash','url','data'):
        if item.get(f):
            v = str(item[f]).strip()
            break
    if not v:
        for k,val in item.items():
            if isinstance(val, str) and val.strip():
                v = val.strip()
                break
    d = item.get('update_date') or item.get('date') or item.get('first_seen') or ''
    if v:
        print(f"{v}|{d}")
PYEOF
            ;;
        *)
            # Treat unknown as plain text
            grep -vE '^\s*(#|//|;|$)' "$filepath" | sed 's/\r//' | \
            while IFS= read -r line; do
                line="${line%%#*}"
                line=$(printf '%s' "$line" | tr -d '\r' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
                [[ -n "$line" ]] && printf "%s|\n" "$line"
            done
            ;;
    esac
}

# ─────────────────────────────────────────────────────────────────────────────
#  WRITE STIX JSON FILE
# ─────────────────────────────────────────────────────────────────────────────
write_stix_file() {
    local outfile="$1"
    local tmpfile="$2"

    mkdir -p "$(dirname "$outfile")"

    if [[ ! -f "$tmpfile" ]] || [[ ! -s "$tmpfile" ]]; then
        echo "[]" > "$outfile"
        return
    fi

    # Pass paths as CLI args — bash local vars do NOT expand inside python3 heredocs
    python3 -c "
import json, sys
tmpfile, outfile = sys.argv[1], sys.argv[2]
indicators = []
for line in open(tmpfile, encoding='utf-8'):
    line = line.strip()
    if not line: continue
    try: indicators.append(json.loads(line))
    except: pass
with open(outfile, 'w', encoding='utf-8') as f:
    json.dump(indicators, f, indent=2, ensure_ascii=False)
" "$tmpfile" "$outfile"
}

# ─────────────────────────────────────────────────────────────────────────────
#  CORE CONVERSION ENGINE
# ─────────────────────────────────────────────────────────────────────────────
convert_iocs_to_stix() {
    local -a files=("${!1}")
    local out_folder="$2"
    local split_by_type="$3"
    local source="$4"
    local threat_actor="$5"
    local tags_csv="$6"
    local confidence="$7"
    local tlp="$8"
    local ind_type="$9"
    local valid_days="${10}"

    mkdir -p "$out_folder"

    # Temp dir for buckets
    local tmpdir
    tmpdir=$(mktemp -d)
    trap "rm -rf '$tmpdir'" EXIT

    # Temp files per type
    declare -A type_tmp
    for t in "${SUPPORTED_TYPES[@]}"; do
        type_tmp[$t]="${tmpdir}/${t}.ndjson"
    done

    # Deduplication set via temp file
    local seen_file="${tmpdir}/seen.txt"
    touch "$seen_file"

    local total_in=0 total_out=0 total_dupes=0 total_unknown=0
    declare -A type_stats

    local -a written_files=()

    for filepath in "${files[@]}"; do
        echo ""
        log "$C_CYAN" "  ▶ Reading: $(basename "$filepath")"

        local raw_count=0
        local ioc_lines=()

        while IFS= read -r line; do
            [[ -z "$line" ]] && continue
            ioc_lines+=("$line")
            (( raw_count++ )) || true
        done < <(read_iocs_from_file "$filepath" 2>/dev/null)

        log "$C_GRAY" "    Found ${raw_count} raw values"
        (( total_in += raw_count )) || true

        for entry in "${ioc_lines[@]}"; do
            local val="${entry%%|*}"
            local date_raw="${entry#*|}"
            val=$(echo "$val" | xargs)   # trim
            [[ -z "$val" ]] && continue

            # Deduplicate (case-insensitive via lowercase key)
            local key="${val,,}"
            if grep -qxF "$key" "$seen_file" 2>/dev/null; then
                (( total_dupes++ )) || true
                continue
            fi
            echo "$key" >> "$seen_file"

            # Detect type
            local ioc_type
            ioc_type=$(get_ioc_type "$val")
            if [[ -z "$ioc_type" ]]; then
                log "$C_DYELLOW" "    [?] Unknown type: $val"
                (( total_unknown++ )) || true
                continue
            fi

            # Build indicator
            local json_obj
            json_obj=$(new_stix_indicator \
                "$ioc_type" "$val" "$date_raw" \
                "$source" "$threat_actor" "$tags_csv" \
                "$confidence" "$tlp" "$ind_type" "$valid_days")

            if [[ -n "$json_obj" ]]; then
                echo "$json_obj" >> "${type_tmp[$ioc_type]}"
                (( total_out++ )) || true
                type_stats[$ioc_type]=$(( ${type_stats[$ioc_type]:-0} + 1 ))
            fi
        done
    done

    # Write output files
    if [[ "$split_by_type" == "true" ]]; then
        for t in "${SUPPORTED_TYPES[@]}"; do
            [[ -f "${type_tmp[$t]}" ]] && [[ -s "${type_tmp[$t]}" ]] || continue
            local outfile="${out_folder}/${TYPE_FILENAMES[$t]}"
            log "$C_GRAY" "  [*] Writing ${type_stats[$t]:-0} indicators → $(basename "$outfile")"
            write_stix_file "$outfile" "${type_tmp[$t]}"
            written_files+=("$outfile")
        done
    else
        # Merge all into one ndjson then write
        local merged="${tmpdir}/all.ndjson"
        for t in "${SUPPORTED_TYPES[@]}"; do
            [[ -f "${type_tmp[$t]}" ]] && cat "${type_tmp[$t]}" >> "$merged" || true
        done
        local outfile="${out_folder}/stix_indicators.json"
        log "$C_GRAY" "  [*] Writing ${total_out} indicators → $(basename "$outfile")"
        write_stix_file "$outfile" "$merged"
        written_files+=("$outfile")
    fi

    # Summary
    echo ""
    sep2
    log "$C_CYAN"  "  CONVERSION SUMMARY"
    sep2
    log "$C_WHITE" "  Input values   : ${total_in}"
    log "$C_GREEN" "  Generated      : ${total_out}"
    log "$C_GRAY"  "  Duplicates     : ${total_dupes}"
    if [[ "$total_unknown" -gt 0 ]]; then
        log "$C_YELLOW" "  Unknown/skip   : ${total_unknown}"
    else
        log "$C_GRAY"   "  Unknown/skip   : 0"
    fi
    echo ""
    log "$C_WHITE" "  By type:"
    for t in $(echo "${!type_stats[@]}" | tr ' ' '\n' | sort); do
        printf "  ${C_CYAN}  %-26s${C_WHITE}%s${C_RESET}\n" "$t" "${type_stats[$t]}"
    done
    echo ""
    log "$C_WHITE" "  Output file(s):"
    for f in "${written_files[@]}"; do
        log "$C_GREEN" "    → $f"
    done
    sep2

    # Return written files for potential API upload
    printf '%s\n' "${written_files[@]}"
}

# ─────────────────────────────────────────────────────────────────────────────
#  SENTINEL API UPLOAD
# ─────────────────────────────────────────────────────────────────────────────
send_to_sentinel_api() {
    local filepath="$1"
    local bearer_token="$2"

    if ! command -v curl &>/dev/null; then
        log "$C_RED" "  [ERROR] curl is required for API upload."
        return 1
    fi

    local url="${CFG_API_ENDPOINT//\{workspaceId\}/$CFG_API_WORKSPACE_ID}"
    local batch_size="$CFG_API_BATCH_SIZE"

    log "$C_CYAN" "  [*] Uploading: $(basename "$filepath")"
    log "$C_GRAY" "      Endpoint  : $url"
    log "$C_GRAY" "      Batch size: $batch_size"
    echo ""

    python3 - <<PYEOF
import json, sys, subprocess, math

indicators = json.load(open("${filepath}", encoding='utf-8'))
if not isinstance(indicators, list): indicators = [indicators]

total      = len(indicators)
batch_size = int("${batch_size}")
batches    = math.ceil(total / batch_size)
url        = "${url}"
token      = "${bearer_token}"
ok = 0; fail = 0

for i in range(batches):
    chunk = indicators[i*batch_size:(i+1)*batch_size]
    body  = json.dumps({"value": chunk})
    cmd   = ["curl","-s","-o","/dev/null","-w","%{http_code}",
             "-X","POST", url,
             "-H","Authorization: Bearer " + token,
             "-H","Content-Type: application/json",
             "--data-raw", body]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        code   = result.stdout.strip()
        if code.startswith('2'):
            ok += len(chunk)
            print(f"    [OK] Batch {i+1}/{batches}: {len(chunk)} indicators uploaded (HTTP {code})")
        else:
            fail += len(chunk)
            print(f"    [ERROR] Batch {i+1}/{batches} failed: HTTP {code}")
    except Exception as e:
        fail += len(chunk)
        print(f"    [ERROR] Batch {i+1}/{batches} exception: {e}")

print(f"\n  Total: {ok} uploaded, {fail} failed")
PYEOF
}

# ─────────────────────────────────────────────────────────────────────────────
#  MENU 1: CONVERT WIZARD
# ─────────────────────────────────────────────────────────────────────────────
menu_convert() {
    echo ""
    log "$C_CYAN" "  ── INPUT ──────────────────────────────────"
    log "$C_GRAY" "  Enter a file path or a folder path."
    log "$C_GRAY" "  Supported formats: .txt  .csv  .json  .list  .dat  .ioc"
    echo ""

    local input_path
    input_path=$(ask "Input path" "$(pwd)")

    if [[ ! -e "$input_path" ]]; then
        log "$C_RED" "  [ERROR] Path not found: $input_path"
        wait_key; return
    fi

    # Gather files
    local -a files=()
    if [[ -d "$input_path" ]]; then
        while IFS= read -r f; do
            files+=("$f")
        done < <(find "$input_path" -maxdepth 1 -type f \
                 \( -iname "*.txt" -o -iname "*.csv" -o -iname "*.json" \
                    -o -iname "*.list" -o -iname "*.dat" -o -iname "*.ioc" \) \
                 | sort)
        if [[ ${#files[@]} -eq 0 ]]; then
            log "$C_YELLOW" "  [!] No supported files found in folder."
            wait_key; return
        fi
        log "$C_GREEN" "  Found ${#files[@]} file(s) in folder:"
        for f in "${files[@]}"; do log "$C_GRAY" "    · $(basename "$f")"; done
    else
        files=("$input_path")
    fi

    echo ""
    log "$C_CYAN" "  ── OUTPUT ─────────────────────────────────"
    local out_folder
    out_folder=$(ask "Output folder" "$CFG_OUTPUT_FOLDER")

    local split_by_type="false"
    ask_bool "Create separate file per IOC type?" false && split_by_type="true"

    echo ""
    log "$C_CYAN" "  ── METADATA (Enter to use config defaults) ─"
    local source threat_actor tags_in confidence tlp ind_type valid_days
    source=$(ask      "Source name"        "$CFG_SOURCE")
    threat_actor=$(ask "Threat actor"      "$CFG_THREAT_ACTOR")
    tags_in=$(ask     "Tags (comma-sep)"   "$CFG_TAGS")
    confidence=$(ask  "Confidence 1-100"   "$CFG_CONFIDENCE")
    tlp=$(ask         "TLP level"          "$CFG_TLP")
    ind_type=$(ask    "Indicator type"     "$CFG_INDICATOR_TYPES")
    valid_days=$(ask  "Valid days"         "$CFG_VALID_DAYS")

    echo ""
    sep2
    log "$C_YELLOW" "  CONVERTING..."
    sep2

    local files_arg="files[@]"
    local -a out_files=()
    while IFS= read -r line; do
        [[ -n "$line" ]] && out_files+=("$line")
    done < <(convert_iocs_to_stix \
        "$files_arg" "$out_folder" "$split_by_type" \
        "$source" "$threat_actor" "$tags_in" \
        "$confidence" "$tlp" "$ind_type" "$valid_days" \
        2>&1 | tee /dev/stderr | grep "^/" || true)

    # Re-run silently to get the file list properly
    local all_output
    all_output=$(convert_iocs_to_stix \
        "$files_arg" "$out_folder" "$split_by_type" \
        "$source" "$threat_actor" "$tags_in" \
        "$confidence" "$tlp" "$ind_type" "$valid_days" 2>/dev/null)

    mapfile -t out_files < <(echo "$all_output" | grep "^/")

    # Offer API upload if enabled
    if [[ "$CFG_API_ENABLED" == "true" ]] && [[ ${#out_files[@]} -gt 0 ]]; then
        echo ""
        if ask_bool "Upload to Sentinel API now?" false; then
            local token
            printf "  ${C_WHITE}Bearer Token: ${C_RESET}" >&2
            read -rs token; echo ""
            for f in "${out_files[@]}"; do
                send_to_sentinel_api "$f" "$token"
            done
        fi
    fi

    wait_key
}

# ─────────────────────────────────────────────────────────────────────────────
#  MENU 2: API UPLOAD
# ─────────────────────────────────────────────────────────────────────────────
menu_api_upload() {
    echo ""
    log "$C_CYAN" "  ── SENTINEL API UPLOAD ────────────────────"

    # Configure inline if needed
    if [[ "$CFG_API_ENABLED" != "true" ]] || [[ -z "$CFG_API_WORKSPACE_ID" ]]; then
        echo ""
        if [[ "$CFG_API_ENABLED" == "true" ]]; then
            log "$C_YELLOW" "  [!] API is enabled but WorkspaceId is missing."
        else
            log "$C_YELLOW" "  [!] API upload is not configured yet."
        fi
        echo ""
        if ! ask_bool "Configure API now?" true; then wait_key; return; fi

        log "$C_GRAY" "  NOTE: Requires a Bearer token with Sentinel Contributor role."
        echo ""
        CFG_API_ENABLED="true"
        CFG_API_WORKSPACE_ID=$(ask "Workspace ID (GUID)" "$CFG_API_WORKSPACE_ID")
        CFG_API_BATCH_SIZE=$(ask   "Batch size"          "$CFG_API_BATCH_SIZE")
        save_config
        echo ""
    fi

    log "$C_GRAY" "  Workspace ID  : $CFG_API_WORKSPACE_ID"
    log "$C_GRAY" "  Batch size    : $CFG_API_BATCH_SIZE"
    echo ""

    local default_file="${CFG_OUTPUT_FOLDER}/stix_indicators.json"
    local filepath
    filepath=$(ask "STIX JSON file to upload" "$default_file")

    if [[ ! -f "$filepath" ]]; then
        log "$C_RED" "  [ERROR] File not found: $filepath"
        wait_key; return
    fi

    local token
    printf "  ${C_WHITE}Bearer Token: ${C_RESET}" >&2
    read -rs token; echo ""

    send_to_sentinel_api "$filepath" "$token"
    wait_key
}

# ─────────────────────────────────────────────────────────────────────────────
#  MENU 3: CONFIGURATION
# ─────────────────────────────────────────────────────────────────────────────
menu_config() {
    show_config

    if ! ask_bool "Edit configuration?" false; then return; fi

    echo ""
    local new_folder
    new_folder=$(ask "Output folder" "$CFG_OUTPUT_FOLDER")
    if [[ -n "$new_folder" ]]; then
        mkdir -p "$new_folder" && CFG_OUTPUT_FOLDER="$new_folder"
    fi

    CFG_THREAT_ACTOR=$(ask  "Threat actor (empty = none)"                 "$CFG_THREAT_ACTOR")
    CFG_SOURCE=$(ask        "Source name (e.g. AlienVault)"               "$CFG_SOURCE")
    CFG_TAGS=$(ask          "Tags (comma-separated)"                      "$CFG_TAGS")
    CFG_CONFIDENCE=$(ask    "Confidence 1-100"                            "$CFG_CONFIDENCE")
    CFG_TLP=$(ask           "TLP level (white/green/amber/red)"           "$CFG_TLP")
    CFG_INDICATOR_TYPES=$(ask "Indicator type (malicious-activity / anomalous-activity / attribution / compromised / benign / unknown)" "$CFG_INDICATOR_TYPES")
    CFG_VALID_DAYS=$(ask    "Validity in days"                            "$CFG_VALID_DAYS")
    CFG_LOG_FILE=$(ask      "Log file path (empty = disabled)"            "$CFG_LOG_FILE")
    [[ -n "$CFG_LOG_FILE" ]] && LOG_FILE="$CFG_LOG_FILE"

    echo ""
    log "$C_DCYAN" "  ── API Configuration (Sentinel TI Upload) ──"
    log "$C_GRAY"  "  NOTE: Requires a Bearer token with Sentinel Contributor role."

    local api_choice="false"
    ask_bool "Enable API upload?" "$( [[ "$CFG_API_ENABLED" == "true" ]] && echo true || echo false)" \
        && api_choice="true"
    CFG_API_ENABLED="$api_choice"

    if [[ "$CFG_API_ENABLED" == "true" ]]; then
        CFG_API_WORKSPACE_ID=$(ask "Workspace ID (GUID)" "$CFG_API_WORKSPACE_ID")
        CFG_API_BATCH_SIZE=$(ask   "Batch size"          "$CFG_API_BATCH_SIZE")
    fi

    save_config
    wait_key
}

# ─────────────────────────────────────────────────────────────────────────────
#  MENU 4: TYPE DETECTION TEST
# ─────────────────────────────────────────────────────────────────────────────
menu_detection_test() {
    echo ""
    log "$C_GRAY" "  Enter a value to test auto-detection (empty to exit):"
    echo ""
    while true; do
        local val
        printf "  ${C_WHITE}Value: ${C_RESET}" >&2
        read -r val
        [[ -z "$val" ]] && break

        local detected
        detected=$(get_ioc_type "$val")
        if [[ -n "$detected" ]]; then
            local pattern
            pattern=$(new_stix_pattern "$detected" "$val")
            printf "  ${C_WHITE}Detected: ${C_GREEN}%-25s${C_RESET}  ${C_GRAY}Pattern: ${C_DCYAN}%s${C_RESET}\n" \
                   "$detected" "$pattern"
        else
            log "$C_YELLOW" "  → Unknown / unsupported type"
        fi
    done
    wait_key
}

# ─────────────────────────────────────────────────────────────────────────────
#  NON-INTERACTIVE (pipeline) MODE
# ─────────────────────────────────────────────────────────────────────────────
run_noninteractive() {
    local input_path="$1"
    local out_folder="${2:-$CFG_OUTPUT_FOLDER}"
    local split="${3:-false}"

    local -a files=()
    if [[ -d "$input_path" ]]; then
        while IFS= read -r f; do files+=("$f"); done < \
            <(find "$input_path" -maxdepth 1 -type f \
              \( -iname "*.txt" -o -iname "*.csv" -o -iname "*.json" \
                 -o -iname "*.list" -o -iname "*.dat" -o -iname "*.ioc" \) | sort)
    else
        files=("$input_path")
    fi

    local files_arg="files[@]"
    convert_iocs_to_stix "$files_arg" "$out_folder" "$split" \
        "$CFG_SOURCE" "$CFG_THREAT_ACTOR" "$CFG_TAGS" \
        "$CFG_CONFIDENCE" "$CFG_TLP" "$CFG_INDICATOR_TYPES" "$CFG_VALID_DAYS"
}

# ─────────────────────────────────────────────────────────────────────────────
#  MAIN LOOP
# ─────────────────────────────────────────────────────────────────────────────
main() {
    check_deps
    load_config

    # Non-interactive mode via arguments
    if [[ $# -ge 1 && "$1" != "" && "$1" != "--interactive" ]]; then
        local input_path="$1"
        local out_folder="${2:-$CFG_OUTPUT_FOLDER}"
        local split="${3:-false}"
        run_noninteractive "$input_path" "$out_folder" "$split"
        exit 0
    fi

    # Interactive loop
    while true; do
        show_banner
        show_menu
        printf "  ${C_YELLOW}Option: ${C_RESET}" >&2
        local choice
        read -r choice

        case "$choice" in
            1) show_banner; menu_convert ;;
            2) show_banner; menu_api_upload ;;
            3) show_banner; menu_config ;;
            4) show_banner; menu_detection_test ;;
            0) echo ""; log "$C_CYAN" "  Bye."; echo ""; exit 0 ;;
            *) log "$C_RED" "  [!] Invalid option."; sleep 1 ;;
        esac
    done
}

main "$@"
