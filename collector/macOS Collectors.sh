#!/usr/bin/env bash
set -euo pipefail

HOST_RAW="$(scutil --get ComputerName 2>/dev/null || hostname -s || hostname)"
HOST="${HOST_RAW// /_}"
TS="$(date '+%Y%m%d_%H%M')"
BASE="${HOST}_${TS}"
WORK="${TMPDIR:-/tmp}/${BASE}_collect"
OUT="$PWD/${BASE}.zip"
QUICK="${COLLECTOR_QUICK:-0}"

if [[ "$QUICK" == "1" ]]; then
  LOG_WINDOW_SHORT="1h"
  LOG_WINDOW_LONG="6h"
  LOG_LIMIT_MAIN="30000"
  LOG_LIMIT_FILTERED="20000"
else
  LOG_WINDOW_SHORT="6h"
  LOG_WINDOW_LONG="24h"
  LOG_LIMIT_MAIN="150000"
  LOG_LIMIT_FILTERED="100000"
fi

mkdir -p "$WORK"/{metadata,system,browser,persistence,security_agents,remote_kvm,network,logs,timeline,accounts}

count_files() {
  local dir="$1"
  local name="$2"
  if [[ -d "$dir" ]]; then
    find "$dir" -type f -name "$name" 2>/dev/null | wc -l | tr -d ' '
  else
    echo "0"
  fi
}

BROWSER_SRC_COUNT=0
BROWSER_SRC_COUNT=$((BROWSER_SRC_COUNT + $(count_files "$HOME/Library/Application Support/Google/Chrome" "History")))
BROWSER_SRC_COUNT=$((BROWSER_SRC_COUNT + $(count_files "$HOME/Library/Application Support/Microsoft Edge" "History")))
BROWSER_SRC_COUNT=$((BROWSER_SRC_COUNT + $(count_files "$HOME/Library/Application Support/Firefox/Profiles" "places.sqlite")))

# Fixed steps + dynamic browser DB copy count.
STEP_TOTAL_FIXED=83
STEP_TOTAL=$((STEP_TOTAL_FIXED + BROWSER_SRC_COUNT))
if (( STEP_TOTAL < 1 )); then
  STEP_TOTAL=1
fi
STEP_DONE=0

progress_step() {
  local action="$1"
  STEP_DONE=$((STEP_DONE + 1))
  if (( STEP_DONE > STEP_TOTAL )); then
    STEP_TOTAL=$STEP_DONE
  fi
  local pct=$(( STEP_DONE * 100 / STEP_TOTAL ))
  printf '[%3d%%] (%d/%d) %s\n' "$pct" "$STEP_DONE" "$STEP_TOTAL" "$action"
}

capture() {
  local cmd="$1"
  local out="$2"
  local timeout_sec="${3:-120}"
  local desc="${4:-$(basename "$out")}"

  progress_step "Collecting: $desc"

  (
    bash -lc "$cmd" > "$out" 2>&1
  ) &
  local pid=$!
  local elapsed=0

  while kill -0 "$pid" 2>/dev/null; do
    sleep 1
    elapsed=$((elapsed + 1))
    if (( elapsed >= timeout_sec )); then
      {
        echo ""
        echo "[timeout] command exceeded ${timeout_sec}s and was terminated"
        echo "[timeout] $cmd"
      } >> "$out"
      kill -TERM "$pid" 2>/dev/null || true
      sleep 1
      kill -KILL "$pid" 2>/dev/null || true
      break
    fi
  done

  wait "$pid" 2>/dev/null || true
}

copy_if_exists() {
  local src="$1"
  local dst="$2"
  local desc="${3:-$(basename "$dst")}"
  progress_step "Copying: $desc"
  if [[ -f "$src" ]]; then
    mkdir -p "$(dirname "$dst")"
    cp "$src" "$dst" 2>/dev/null || true
  else
    echo "[skip] not found: $src"
  fi
}

collect_browser_db() {
  local src="$1"
  local dst="$2"
  local desc="${3:-$(basename "$dst")}"
  progress_step "Collecting browser DB: $desc"
  if [[ -f "$src" ]]; then
    mkdir -p "$(dirname "$dst")"
    cp "$src" "$dst" 2>/dev/null || true
  else
    echo "[skip] not found: $src"
  fi
}

sanitize_name() {
  local raw="$1"
  raw="${raw// /_}"
  raw="${raw//\//_}"
  raw="${raw//:/_}"
  printf '%s' "$raw"
}

echo "[+] Collecting macOS DFIR artifacts into: $WORK"
echo "[i] Planned steps: $STEP_TOTAL (browser DB sources detected: $BROWSER_SRC_COUNT)"

# Metadata
progress_step "Writing collection metadata"
cat > "$WORK/metadata/collection_meta.txt" << META
collector_name=macOS Collectors.sh
host=$HOST_RAW
timestamp=$TS
output_zip=$OUT
META

capture "date" "$WORK/system/date.txt"
capture "whoami" "$WORK/system/whoami.txt"
capture "id" "$WORK/system/id.txt"
capture "uname -a" "$WORK/system/uname.txt"
capture "sw_vers" "$WORK/system/sw_vers.txt"
capture "uptime" "$WORK/system/uptime.txt"
capture "sysctl kern.boottime" "$WORK/system/boot_time.txt"
capture "system_profiler SPHardwareDataType SPSoftwareDataType" "$WORK/system/system_profiler_hw_sw.txt" 240
capture "system_profiler SPApplicationsDataType -detailLevel mini" "$WORK/timeline/installed_apps.txt" 300
capture "pkgutil --pkgs" "$WORK/timeline/pkgutil_pkgs.txt"
copy_if_exists "/Library/Receipts/InstallHistory.plist" "$WORK/timeline/InstallHistory.plist"
copy_if_exists "/var/log/install.log" "$WORK/timeline/install.log"
capture "spctl --status" "$WORK/system/gatekeeper_status.txt"
capture "csrutil status" "$WORK/system/sip_status.txt"
capture "fdesetup status" "$WORK/system/filevault_status.txt"
capture "kextstat" "$WORK/system/kextstat.txt"
capture "kmutil showloaded" "$WORK/system/kmutil_showloaded.txt"
capture "log show --last ${LOG_WINDOW_LONG} --predicate 'eventMessage CONTAINS[c] \"xprotect\" OR eventMessage CONTAINS[c] \"malware\" OR eventMessage CONTAINS[c] \"quarantine\"' --style syslog | head -n ${LOG_LIMIT_FILTERED}" "$WORK/system/xprotect_quarantine_last24h.log" 240
capture "sqlite3 '$HOME/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2' 'select datetime(LSQuarantineTimeStamp+978307200,\"unixepoch\"), LSQuarantineAgentBundleIdentifier, LSQuarantineDataURLString from LSQuarantineEvent order by LSQuarantineTimeStamp desc limit 3000;'" "$WORK/system/quarantine_events.txt"

# Persistence and execution context
capture "ps aux" "$WORK/persistence/ps_aux.txt"
capture "launchctl list" "$WORK/persistence/launchctl_list.txt"
capture "find '$HOME/Library/LaunchAgents' -maxdepth 3 -type f -name '*.plist' 2>/dev/null" "$WORK/persistence/user_launchagents.txt"
capture "find '/Library/LaunchAgents' -maxdepth 3 -type f -name '*.plist' 2>/dev/null" "$WORK/persistence/system_launchagents.txt"
capture "find '/Library/LaunchDaemons' -maxdepth 3 -type f -name '*.plist' 2>/dev/null" "$WORK/persistence/system_launchdaemons.txt"
capture "crontab -l" "$WORK/persistence/user_crontab.txt"
capture "osascript -e 'tell application \"System Events\" to get the name of every login item'" "$WORK/persistence/login_items.txt" 30
capture "ls -la '$HOME/Library/LaunchAgents'" "$WORK/persistence/user_launchagents_ls.txt"
capture "ls -la '/Library/LaunchAgents'" "$WORK/persistence/system_launchagents_ls.txt"
capture "ls -la '/Library/LaunchDaemons'" "$WORK/persistence/system_launchdaemons_ls.txt"
capture "defaults read com.apple.loginwindow AutoLaunchedApplicationDictionary" "$WORK/persistence/auto_launched_apps.txt"
capture "cat '$HOME/.zsh_history'" "$WORK/accounts/zsh_history.txt"
capture "cat '$HOME/.bash_history'" "$WORK/accounts/bash_history.txt"
capture "last -100" "$WORK/accounts/last_logins.txt"
capture "dscl . -list /Users" "$WORK/accounts/local_users.txt"

# Network
capture "ifconfig -a" "$WORK/network/ifconfig.txt"
capture "netstat -anv" "$WORK/network/netstat_anv.txt"
capture "lsof -nP -i" "$WORK/network/lsof_network.txt"
capture "route -n get default" "$WORK/network/route_default.txt"
capture "arp -a" "$WORK/network/arp.txt"
capture "networksetup -listallhardwareports" "$WORK/network/hardware_ports.txt"
capture "networksetup -listallnetworkservices" "$WORK/network/network_services.txt"
capture "scutil --dns" "$WORK/network/dns_config.txt"
capture "cat /etc/hosts" "$WORK/network/etc_hosts.txt"
capture "cat /etc/resolv.conf" "$WORK/network/resolv.conf.txt"
capture "log show --last ${LOG_WINDOW_LONG} --predicate 'eventMessage CONTAINS[c] \"ssh\" OR eventMessage CONTAINS[c] \"screen sharing\" OR eventMessage CONTAINS[c] \"vnc\" OR eventMessage CONTAINS[c] \"ard\"' --style syslog | head -n ${LOG_LIMIT_FILTERED}" "$WORK/network/remote_access_logs.txt" 240

# Remote management / IP-KVM surface
capture "system_profiler SPUSBDataType" "$WORK/remote_kvm/usb_devices.txt" 240
capture "system_profiler SPThunderboltDataType" "$WORK/remote_kvm/thunderbolt_devices.txt" 180
capture "system_profiler SPEthernetDataType" "$WORK/remote_kvm/ethernet_devices.txt" 180
capture "system_profiler SPNetworkDataType" "$WORK/remote_kvm/network_devices.txt" 180
capture "system_profiler SPDisplaysDataType" "$WORK/remote_kvm/displays.txt" 180
capture "pmset -g" "$WORK/remote_kvm/pmset.txt"
capture "grep -iE 'kvm|pikvm|ipmi|idrac|ilo|bmc|remote console|virtual media' '$WORK/remote_kvm/usb_devices.txt' '$WORK/remote_kvm/thunderbolt_devices.txt' '$WORK/remote_kvm/ethernet_devices.txt' '$WORK/remote_kvm/network_devices.txt'" "$WORK/remote_kvm/kvm_keyword_hits.txt"

# Security tooling visibility (Tanium / Falcon / JAMF)
capture "ls -la '/Applications' | grep -iE 'falcon|crowdstrike|tanium|jamf'" "$WORK/security_agents/app_presence.txt"
capture "ps aux | grep -iE 'falcon|crowdstrike|tanium|jamf' | grep -v grep" "$WORK/security_agents/process_presence.txt"
capture "ls -la '/Library/LaunchDaemons' | grep -iE 'falcon|crowdstrike|tanium|jamf'" "$WORK/security_agents/launchdaemons_presence.txt"
capture "ls -la '/Library/LaunchAgents' | grep -iE 'falcon|crowdstrike|tanium|jamf'" "$WORK/security_agents/launchagents_presence.txt"
capture "systemextensionsctl list | grep -iE 'falcon|crowdstrike|tanium|jamf'" "$WORK/security_agents/systemextensions_presence.txt"
capture "profiles status -type enrollment" "$WORK/security_agents/mdm_enrollment_status.txt"
capture "profiles show -type enrollment" "$WORK/security_agents/mdm_enrollment_detail.txt"
capture "jamf checkJSSConnection" "$WORK/security_agents/jamf_checkJSSConnection.txt"
capture "jamf version" "$WORK/security_agents/jamf_version.txt"
capture "grep -iE 'falcon|crowdstrike|tanium|jamf' /var/log/system.log" "$WORK/security_agents/system_log_agent_hits.txt"

copy_if_exists "/usr/local/bin/jamf" "$WORK/security_agents/jamf_binary"
copy_if_exists "/Library/LaunchDaemons/com.jamf.management.daemon.plist" "$WORK/security_agents/com.jamf.management.daemon.plist"
copy_if_exists "/Library/Preferences/com.jamfsoftware.jamf.plist" "$WORK/security_agents/com.jamfsoftware.jamf.plist"
copy_if_exists "/Library/LaunchDaemons/com.crowdstrike.falcond.plist" "$WORK/security_agents/com.crowdstrike.falcond.plist"
copy_if_exists "/Library/CS/falcond" "$WORK/security_agents/falcond_binary"
copy_if_exists "/Library/Logs/Falcon/falconctl.log" "$WORK/security_agents/falconctl.log"
copy_if_exists "/Library/Logs/Falcon/falcond.log" "$WORK/security_agents/falcond.log"
copy_if_exists "/Library/LaunchDaemons/com.tanium.taniumclient.plist" "$WORK/security_agents/com.tanium.taniumclient.plist"
copy_if_exists "/Library/Tanium/TaniumClient/TaniumClient" "$WORK/security_agents/TaniumClient_binary"
copy_if_exists "/Library/Tanium/TaniumClient/Logs/TaniumClient.log" "$WORK/security_agents/TaniumClient.log"

# Browser history databases (copied with .db extension for parser compatibility)
if [[ -d "$HOME/Library/Application Support/Google/Chrome" ]]; then
  while IFS= read -r p; do
    rel="${p#$HOME/Library/Application Support/Google/Chrome/}"
    rel_clean="$(sanitize_name "$rel")"
    collect_browser_db "$p" "$WORK/browser/chrome_${rel_clean}.db" "chrome_${rel_clean}.db"
  done < <(find "$HOME/Library/Application Support/Google/Chrome" -type f -name 'History' 2>/dev/null)
fi

if [[ -d "$HOME/Library/Application Support/Microsoft Edge" ]]; then
  while IFS= read -r p; do
    rel="${p#$HOME/Library/Application Support/Microsoft Edge/}"
    rel_clean="$(sanitize_name "$rel")"
    collect_browser_db "$p" "$WORK/browser/edge_${rel_clean}.db" "edge_${rel_clean}.db"
  done < <(find "$HOME/Library/Application Support/Microsoft Edge" -type f -name 'History' 2>/dev/null)
fi

if [[ -d "$HOME/Library/Application Support/Firefox/Profiles" ]]; then
  while IFS= read -r p; do
    rel="${p#$HOME/Library/Application Support/Firefox/Profiles/}"
    rel_clean="$(sanitize_name "$rel")"
    collect_browser_db "$p" "$WORK/browser/firefox_${rel_clean}.db" "firefox_${rel_clean}.db"
  done < <(find "$HOME/Library/Application Support/Firefox/Profiles" -type f -name 'places.sqlite' 2>/dev/null)
fi

copy_if_exists "$HOME/Library/Safari/History.db" "$WORK/browser/safari_History.db"

# Logs
capture "log show --last ${LOG_WINDOW_SHORT} --style syslog | head -n ${LOG_LIMIT_MAIN}" "$WORK/logs/unified_last6h.log" 300
capture "log show --last ${LOG_WINDOW_SHORT} --predicate 'eventMessage CONTAINS[c] \"ssh\" OR eventMessage CONTAINS[c] \"auth\" OR eventMessage CONTAINS[c] \"screen sharing\" OR eventMessage CONTAINS[c] \"remote\"' --style syslog | head -n ${LOG_LIMIT_FILTERED}" "$WORK/logs/auth_remote_last6h.log" 240
capture "log show --last ${LOG_WINDOW_LONG} --predicate 'eventMessage CONTAINS[c] \"tcc\" OR eventMessage CONTAINS[c] \"privacy\" OR eventMessage CONTAINS[c] \"mdm\" OR eventMessage CONTAINS[c] \"jamf\" OR eventMessage CONTAINS[c] \"tanium\" OR eventMessage CONTAINS[c] \"falcon\"' --style syslog | head -n ${LOG_LIMIT_FILTERED}" "$WORK/logs/security_controls_last24h.log" 240
copy_if_exists "/var/log/system.log" "$WORK/logs/system.log"
copy_if_exists "/var/log/install.log" "$WORK/logs/install.log"
copy_if_exists "/var/log/jamf.log" "$WORK/logs/jamf.log"

# Hash manifest for integrity
capture "find '$WORK' -type f -print0 | xargs -0 shasum -a 256" "$WORK/metadata/hashes_sha256.txt"

# Zip output to current working directory
progress_step "Packaging collected artifacts into ZIP"
if command -v ditto >/dev/null 2>&1; then
  PARENT="$(dirname "$WORK")"
  NAME="$(basename "$WORK")"
  (cd "$PARENT" && ditto -c -k --sequesterRsrc --keepParent "$NAME" "$OUT")
else
  (cd "$WORK" && /usr/bin/zip -r "$OUT" . >/dev/null)
fi

progress_step "Cleaning temporary working directory"
rm -rf "$WORK"
echo "[+] Collection complete: $OUT"
