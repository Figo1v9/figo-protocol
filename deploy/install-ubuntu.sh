#!/usr/bin/env bash
# ==============================================================================
# FGXP (FigoX Protocol) — One-Command Ubuntu / Debian Server Auto-Installer
# Supports:
#   1) Direct IP + Self-Signed ECDSA + SNI Camouflage (Port 443)
#   2) Custom Domain + Let's Encrypt Certbot + Auto-Renewal Hook (Port 443)
#   3) CDN WebSocket Mode (RFC 6455 /ws-... for Imperva / Cloudflare CDN)
#   4) Plaintext HTTP Framing (--no-tls, Port 80, for Worker / HTTP Inject)
# ==============================================================================
set -Eeuo pipefail

export DEBIAN_FRONTEND=noninteractive
export GIT_TERMINAL_PROMPT=0

REQUIRED_GO_VERSION="1.26.5"
DEFAULT_REPO="https://github.com/Figo1v9/figo-protocol.git"
DEFAULT_BRANCH="main"
DEFAULT_PROXY_TARGET="https://example.com"
DEFAULT_STATIC_DIR="/var/www/camouflage"
DEFAULT_SNI="www.cloudflare.com"
SRC_DIR="/opt/figo-protocol"
CFG_DIR="/etc/fgxp"
CERT_DIR="/etc/fgxp/certs"
SERVICE_NAME="fgxp"

# --- ANSI colors (only when stdout is a terminal) ---
if [[ -t 1 ]]; then
  C_RED='\033[0;31m'
  C_GREEN='\033[0;32m'
  C_YELLOW='\033[1;33m'
  C_CYAN='\033[0;36m'
  C_BOLD='\033[1m'
  C_RESET='\033[0m'
else
  C_RED=''
  C_GREEN=''
  C_YELLOW=''
  C_CYAN=''
  C_BOLD=''
  C_RESET=''
fi

log_info()  { printf "${C_CYAN}[INFO]${C_RESET} %s\n" "$*"; }
log_ok()    { printf "${C_GREEN}[OK]${C_RESET}   %s\n" "$*"; }
log_warn()  { printf "${C_YELLOW}[WARN]${C_RESET} %s\n" "$*" >&2; }
log_err()   { printf "${C_RED}[ERR]${C_RESET}  %s\n" "$*" >&2; }

on_error() {
  local line="$1"
  local cmd="$2"
  log_err "Installer failed at line ${line}: ${cmd}"
  exit 1
}
trap 'on_error "$LINENO" "$BASH_COMMAND"' ERR

usage() {
  cat <<'EOF'
FGXP (FigoX Protocol) Ubuntu / Debian Auto-Installer

Usage:
  curl -fsSL https://raw.githubusercontent.com/Figo1v9/figo-protocol/main/deploy/install-ubuntu.sh | sudo bash
  curl -fsSL https://raw.githubusercontent.com/Figo1v9/figo-protocol/main/deploy/install-ubuntu.sh | sudo bash -s -- [OPTIONS]

Options:
  --mode MODE           Setup mode: ip-sni (default), domain, ws (CDN WebSocket), or no-tls
  --domain DOMAIN       Bind a domain and obtain a Let's Encrypt TLS certificate (requires DNS A record + TCP 80 open)
  --email EMAIL         Optional email address for Let's Encrypt expiry notifications
  --psk SECRET          Custom Pre-Shared Key (or set FGXP_PSK env var; auto-generated if omitted)
  --port PORT           Server listen port (default: 443, or 80 with --no-tls)
  --sni HOST            SNI hostname displayed in client commands and self-signed SAN (default: domain or www.cloudflare.com)
  --ws-path PATH        Secret WebSocket upgrade path when using --mode ws (default: auto-generated /ws-...)
  --behind-cdn          Extract client IP from CDN proxy headers (auto-enabled in --mode ws)
  --camouflage MODE     Camouflage mode for active probes: reverse_proxy (default) or static
  --proxy-target URL    Backend URL when camouflage=reverse_proxy (default: https://example.com)
  --static-dir DIR      Directory for camouflage=static (default: /var/www/camouflage)
  --no-tls              Run plaintext HTTP / WS mode (port 80 default, useful behind CDN Flexible SSL or HTTP Inject)
  --repo URL            Git repository URL (default: https://github.com/Figo1v9/figo-protocol.git)
  --branch BRANCH       Git branch to build (default: main)
  --non-interactive     Do not prompt even if /dev/tty is available
  -h, --help            Show this help message
EOF
}

version_ge() {
  local current="$1"
  local required="$2"
  [[ "$(printf '%s\n%s\n' "$required" "$current" | sort -V | head -n1)" == "$required" ]]
}

yaml_single_quote() {
  local val="$1"
  printf "'%s'" "${val//\'/\'\'}"
}

sh_single_quote() {
  local val="$1"
  printf "'%s'" "${val//\'/\'\\\'\'}"
}

ps_single_quote() {
  local val="$1"
  printf "'%s'" "${val//\'/\'\'}"
}

require_root_and_os() {
  if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
    log_err "Please run this installer as root (e.g. with sudo)."
    exit 1
  fi

  if [[ ! -r /etc/os-release ]]; then
    log_err "Cannot detect OS (/etc/os-release missing)."
    exit 1
  fi

  # shellcheck source=/dev/null
  . /etc/os-release
  case "${ID:-}" in
    ubuntu|debian)
      log_info "Detected OS: ${PRETTY_NAME:-$ID}"
      ;;
    *)
      if [[ "${ID_LIKE:-}" == *debian* || "${ID_LIKE:-}" == *ubuntu* ]]; then
        log_info "Detected Debian-like OS: ${PRETTY_NAME:-$ID}"
      else
        log_err "Unsupported OS (${ID:-unknown}). Ubuntu or Debian with apt-get is required."
        exit 1
      fi
      ;;
  esac

  if ! command -v apt-get >/dev/null 2>&1; then
    log_err "apt-get not found. Cannot continue."
    exit 1
  fi
}

detect_arch() {
  local machine
  machine="$(uname -m)"
  case "$machine" in
    x86_64|amd64)
      GO_ARCH="amd64"
      ;;
    aarch64|arm64)
      GO_ARCH="arm64"
      ;;
    *)
      log_err "Unsupported CPU architecture: ${machine}. Supported: x86_64 (amd64), aarch64 (arm64)."
      exit 1
      ;;
  esac
}

detect_public_ip() {
  local ip=""
  for url in "https://api.ipify.org" "https://ifconfig.me" "https://icanhazip.com"; do
    ip="$(curl -4fsS --max-time 5 "$url" 2>/dev/null | tr -d '[:space:]' || true)"
    if [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
      printf '%s\n' "$ip"
      return 0
    fi
  done
  ip="$(hostname -I 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/ && $i !~ /^127\./) {print $i; exit}}' || true)"
  printf '%s\n' "$ip"
}

apt_install_base() {
  log_info "Updating package lists and installing base dependencies..."
  apt-get update -qq
  apt-get install -y -qq -o DPkg::Lock::Timeout=120 \
    curl wget git openssl ufw ca-certificates tar gzip xz-utils

  if [[ -n "$DOMAIN" && "$NO_TLS" -eq 0 ]] && ! command -v certbot >/dev/null 2>&1; then
    log_info "Installing Certbot for Let's Encrypt TLS..."
    apt-get install -y -qq -o DPkg::Lock::Timeout=120 certbot
  fi
  log_ok "Base packages ready."
}

sync_system_clock() {
  if command -v timedatectl >/dev/null 2>&1; then
    timedatectl set-ntp true >/dev/null 2>&1 || true
    log_info "NTP time sync enabled (PSK auth allows max 30s clock skew)."
  fi
}

install_or_verify_go() {
  local existing_go=""
  local existing_ver=""

  if [[ -x /usr/local/go/bin/go ]]; then
    existing_go="/usr/local/go/bin/go"
  elif command -v go >/dev/null 2>&1; then
    existing_go="$(command -v go)"
  fi

  if [[ -n "$existing_go" ]]; then
    existing_ver="$("$existing_go" version 2>/dev/null | sed -E 's/^go version go([0-9]+\.[0-9]+(\.[0-9]+)?).*/\1/' || true)"
    if [[ -n "$existing_ver" ]] && version_ge "$existing_ver" "$REQUIRED_GO_VERSION"; then
      GO_BIN="$existing_go"
      log_ok "Using existing Go ${existing_ver} (${GO_BIN})."
      return 0
    fi
    log_info "Existing Go (${existing_ver:-none}) is older than ${REQUIRED_GO_VERSION}; installing Go ${REQUIRED_GO_VERSION}..."
  else
    log_info "Installing Go ${REQUIRED_GO_VERSION} (${GO_ARCH})..."
  fi

  local tarball="go${REQUIRED_GO_VERSION}.linux-${GO_ARCH}.tar.gz"
  local url="https://dl.google.com/go/${tarball}"
  local tmp_dir
  tmp_dir="$(mktemp -d)"

  local expected_sha=""
  case "$GO_ARCH" in
    amd64) expected_sha="5c2c3b16caefa1d968a94c1daca04a7ca301a496d9b086e17ad77bb81393f053" ;;
    arm64) expected_sha="fe4789e92b1f33358680864bbe8704289e7bb5fc207d80623c308935bd696d49" ;;
  esac

  if curl -fL --retry 3 --connect-timeout 15 -o "${tmp_dir}/${tarball}" "$url"; then
    local remote_sha
    remote_sha="$(curl -fsSL --retry 2 --connect-timeout 10 "${url}.sha256" 2>/dev/null | awk '{print $1}' | tr -d '[:space:]' || true)"
    local verify_sha="${remote_sha:-$expected_sha}"
    if [[ -n "$expected_sha" && -n "$remote_sha" && "$remote_sha" != "$expected_sha" ]]; then
      log_err "Checksum mismatch between pinned hash and dl.google.com .sha256!"
      rm -rf "$tmp_dir"
      exit 1
    fi
    if [[ -n "$verify_sha" ]]; then
      printf '%s  %s\n' "$verify_sha" "${tmp_dir}/${tarball}" | sha256sum -c - >/dev/null
      log_ok "Go ${REQUIRED_GO_VERSION} SHA256 verified."
    fi
    rm -rf /usr/local/go
    tar -C /usr/local -xzf "${tmp_dir}/${tarball}"
    rm -rf "$tmp_dir"
    GO_BIN="/usr/local/go/bin/go"
    cat >/etc/profile.d/go.sh <<'EOF'
export PATH=$PATH:/usr/local/go/bin
EOF
    chmod 644 /etc/profile.d/go.sh
    log_ok "Installed Go $("${GO_BIN}" version | awk '{print $3}')."
  else
    rm -rf "$tmp_dir"
    GO_BIN=""
    log_warn "Could not download Go ${REQUIRED_GO_VERSION}; will attempt prebuilt binary fallback if available."
  fi
}

fetch_source() {
  log_info "Fetching FGXP source (${BRANCH}) from ${REPO_URL}..."
  if [[ -d "${SRC_DIR}/.git" ]]; then
    git -C "$SRC_DIR" remote set-url origin "$REPO_URL"
    git -C "$SRC_DIR" fetch --depth=1 origin "$BRANCH"
    git -C "$SRC_DIR" checkout -B "$BRANCH" "origin/${BRANCH}"
    git -C "$SRC_DIR" reset --hard "origin/${BRANCH}"
  else
    rm -rf "$SRC_DIR"
    git clone --depth=1 --branch "$BRANCH" "$REPO_URL" "$SRC_DIR"
  fi
  log_ok "Source ready at ${SRC_DIR}."
}

build_binaries() {
  local mem_kb
  mem_kb="$(awk '/MemTotal:/ {print $2}' /proc/meminfo 2>/dev/null || echo 0)"
  if [[ "$mem_kb" -gt 0 && "$mem_kb" -lt 1572864 ]]; then
    log_info "Low RAM detected ($((mem_kb / 1024)) MB); building with GOMAXPROCS=1 GOGC=50."
    export GOMAXPROCS=1
    export GOGC=50
  fi

  local built=0
  if [[ -n "${GO_BIN:-}" && -x "${GO_BIN}" ]]; then
    log_info "Compiling fgxp-server and fgxp-client (CGO_ENABLED=0)..."
    if (cd "$SRC_DIR" && CGO_ENABLED=0 "$GO_BIN" build -trimpath -ldflags="-w -s" -o /usr/local/bin/fgxp-server ./cmd/fgxp-server && \
        CGO_ENABLED=0 "$GO_BIN" build -trimpath -ldflags="-w -s" -o /usr/local/bin/fgxp-client ./cmd/fgxp-client); then
      chmod 755 /usr/local/bin/fgxp-server /usr/local/bin/fgxp-client
      built=1
      log_ok "Compiled /usr/local/bin/fgxp-server and /usr/local/bin/fgxp-client."
    else
      log_warn "Go source build failed."
    fi
  fi

  if [[ "$built" -eq 0 ]]; then
    local fallback="${SRC_DIR}/bin/fgxp-server-linux"
    if [[ "$GO_ARCH" == "amd64" && -f "$fallback" ]] && [[ "$(od -An -tx1 -N4 "$fallback" | tr -d ' \n')" == "7f454c46" ]]; then
      cp -f "$fallback" /usr/local/bin/fgxp-server
      chmod 755 /usr/local/bin/fgxp-server
      log_warn "Installed prebuilt ELF fallback binary from ${fallback}."
    else
      log_err "Build failed and no compatible prebuilt binary fallback exists for ${GO_ARCH}."
      exit 1
    fi
  fi
}

setup_user_and_dirs() {
  if ! id -u "$SERVICE_NAME" >/dev/null 2>&1; then
    useradd --system --no-create-home --shell /usr/sbin/nologin "$SERVICE_NAME"
    log_info "Created system user: ${SERVICE_NAME}"
  fi

  mkdir -p "$CFG_DIR" "$CERT_DIR" "$STATIC_DIR"
  chown root:"$SERVICE_NAME" "$CFG_DIR"
  chmod 750 "$CFG_DIR"
  chown "${SERVICE_NAME}:${SERVICE_NAME}" "$CERT_DIR" "$STATIC_DIR"
  chmod 750 "$CERT_DIR"
  chmod 755 "$STATIC_DIR"

  if [[ ! -f "${STATIC_DIR}/index.html" ]]; then
    cat >"${STATIC_DIR}/index.html" <<'EOF'
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Welcome to nginx!</title>
  <style>
    body { width: 35em; margin: 0 auto; font-family: Tahoma, Verdana, Arial, sans-serif; color: #222; }
  </style>
</head>
<body>
  <h1>Welcome to nginx!</h1>
  <p>If you see this page, the nginx web server is successfully installed and working.</p>
  <p><em>Thank you for using nginx.</em></p>
</body>
</html>
EOF
    chown "${SERVICE_NAME}:${SERVICE_NAME}" "${STATIC_DIR}/index.html"
    chmod 644 "${STATIC_DIR}/index.html"
  fi
}

collect_ssh_ports() {
  local ports=("22")
  local p

  if [[ -n "${SSH_CONNECTION:-}" ]]; then
    p="$(printf '%s\n' "$SSH_CONNECTION" | awk '{print $4}')"
    [[ "$p" =~ ^[0-9]+$ ]] && ports+=("$p")
  fi

  if command -v sshd >/dev/null 2>&1; then
    while IFS= read -r p; do
      [[ "$p" =~ ^[0-9]+$ ]] && ports+=("$p")
    done < <(sshd -T 2>/dev/null | awk '/^port /{print $2}' || true)
  fi

  while IFS= read -r p; do
    [[ "$p" =~ ^[0-9]+$ ]] && ports+=("$p")
  done < <(grep -h -E '^[[:space:]]*Port[[:space:]]+[0-9]+' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf 2>/dev/null | awk '{print $2}' || true)

  printf '%s\n' "${ports[@]}" | sort -un
}

configure_firewall() {
  if ! command -v ufw >/dev/null 2>&1 || ! ufw status >/dev/null 2>&1; then
    log_warn "UFW firewall unavailable in this environment (container kernel restriction); ensure TCP ${PORT} is open manually."
    return 0
  fi

  log_info "Configuring UFW firewall (preserving active SSH ports first)..."
  local ssh_port
  while IFS= read -r ssh_port; do
    ufw allow "${ssh_port}/tcp" comment "SSH" >/dev/null
    log_info "UFW allowed SSH TCP port ${ssh_port}."
  done < <(collect_ssh_ports)

  ufw allow "${PORT}/tcp" comment "FGXP" >/dev/null
  if [[ -n "$DOMAIN" && "$NO_TLS" -eq 0 && "$PORT" != "80" ]]; then
    ufw allow "80/tcp" comment "Certbot ACME" >/dev/null
  fi

  if ufw status | grep -qi "Status: inactive"; then
    ufw default deny incoming >/dev/null
    ufw default allow outgoing >/dev/null
    ufw --force enable >/dev/null || {
      log_warn "Could not enable UFW (check container capabilities); ensure TCP ${PORT} is reachable."
      return 0
    }
  else
    ufw reload >/dev/null || true
  fi
  log_ok "UFW configured cleanly."
}

configure_sysctl_bbr() {
  cat >/etc/sysctl.d/99-fgxp.conf <<'EOF'
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
net.ipv4.tcp_fastopen = 3
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.ipv4.tcp_rmem = 4096 87380 16777216
net.ipv4.tcp_wmem = 4096 65536 16777216
EOF
  if sysctl --system >/dev/null 2>&1; then
    log_ok "Kernel BBR & TCP buffer tuning applied."
  else
    log_warn "Some sysctl settings skipped (common in container/restricted kernels)."
  fi
}

provision_certs() {
  if [[ "$NO_TLS" -eq 1 ]]; then
    log_info "Skipping TLS certificate generation (--no-tls mode)."
    return 0
  fi

  if [[ -n "$DOMAIN" ]]; then
    log_info "Requesting Let's Encrypt certificate for ${DOMAIN}..."
    systemctl stop "$SERVICE_NAME" >/dev/null 2>&1 || true

    local email_args=("--register-unsafely-without-email")
    if [[ -n "$EMAIL" ]]; then
      email_args=("--email" "$EMAIL")
    fi

    if ! certbot certonly --standalone --non-interactive --agree-tos "${email_args[@]}" -d "$DOMAIN"; then
      log_err "Certbot failed for domain ${DOMAIN}."
      log_err "Verify: 1) DNS A record points to ${PUBLIC_IP:-this server}, 2) TCP port 80 is free (no nginx/apache holding it) and open in your cloud provider firewall."
      exit 1
    fi

    cp -L "/etc/letsencrypt/live/${DOMAIN}/fullchain.pem" "${CERT_DIR}/cert.pem"
    cp -L "/etc/letsencrypt/live/${DOMAIN}/privkey.pem" "${CERT_DIR}/key.pem"
    chown "${SERVICE_NAME}:${SERVICE_NAME}" "${CERT_DIR}/cert.pem" "${CERT_DIR}/key.pem"
    chmod 644 "${CERT_DIR}/cert.pem"
    chmod 600 "${CERT_DIR}/key.pem"

    mkdir -p /etc/letsencrypt/renewal-hooks/deploy
    cat >/etc/letsencrypt/renewal-hooks/deploy/fgxp-restart.sh <<EOF
#!/usr/bin/env bash
set -euo pipefail
cp -L "/etc/letsencrypt/live/${DOMAIN}/fullchain.pem" "${CERT_DIR}/cert.pem"
cp -L "/etc/letsencrypt/live/${DOMAIN}/privkey.pem" "${CERT_DIR}/key.pem"
chown "${SERVICE_NAME}:${SERVICE_NAME}" "${CERT_DIR}/cert.pem" "${CERT_DIR}/key.pem"
chmod 644 "${CERT_DIR}/cert.pem"
chmod 600 "${CERT_DIR}/key.pem"
systemctl restart "${SERVICE_NAME}"
EOF
    chmod 755 /etc/letsencrypt/renewal-hooks/deploy/fgxp-restart.sh
    log_ok "Let's Encrypt certificate + auto-renewal hook installed."
  else
    log_info "Generating 10-year ECDSA P-256 self-signed certificate (SAN: DNS:${SNI_HOST}${PUBLIC_IP:+, IP:${PUBLIC_IP}})..."
    local san="DNS:${SNI_HOST}"
    if [[ -n "$PUBLIC_IP" ]]; then
      san="${san},IP:${PUBLIC_IP}"
    fi
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
      -nodes -days 3650 \
      -keyout "${CERT_DIR}/key.pem" \
      -out "${CERT_DIR}/cert.pem" \
      -subj "/CN=${SNI_HOST}" \
      -addext "subjectAltName=${san}" >/dev/null 2>&1
    chown "${SERVICE_NAME}:${SERVICE_NAME}" "${CERT_DIR}/cert.pem" "${CERT_DIR}/key.pem"
    chmod 644 "${CERT_DIR}/cert.pem"
    chmod 600 "${CERT_DIR}/key.pem"
    log_ok "Self-signed ECDSA certificate created at ${CERT_DIR}/."
  fi
}

write_server_config() {
  local psk_yaml proxy_yaml static_yaml cert_yaml key_yaml cam_mode_yaml listen_yaml
  local transport_yaml ws_path_yaml no_tls_bool="false" behind_cdn_bool="false"
  psk_yaml="$(yaml_single_quote "$PSK")"
  proxy_yaml="$(yaml_single_quote "$PROXY_TARGET")"
  static_yaml="$(yaml_single_quote "$STATIC_DIR")"
  cert_yaml="$(yaml_single_quote "${CERT_DIR}/cert.pem")"
  key_yaml="$(yaml_single_quote "${CERT_DIR}/key.pem")"
  cam_mode_yaml="$(yaml_single_quote "$CAMOUFLAGE_MODE")"
  listen_yaml="$(yaml_single_quote ":${PORT}")"
  transport_yaml="$(yaml_single_quote "$TRANSPORT")"
  ws_path_yaml="$(yaml_single_quote "$WS_PATH")"
  [[ "$NO_TLS" -eq 1 ]] && no_tls_bool="true"
  [[ "$BEHIND_CDN" -eq 1 ]] && behind_cdn_bool="true"

  cat >"${CFG_DIR}/server.yaml" <<EOF
# Generated by deploy/install-ubuntu.sh
server:
  listen: ${listen_yaml}
  transport: ${transport_yaml}
  no_tls: ${no_tls_bool}
  ws_path: ${ws_path_yaml}
  behind_cdn: ${behind_cdn_bool}

tls:
  cert: ${cert_yaml}
  key: ${key_yaml}

auth:
  method: "psk"
  keys:
    - id: "default"
      secret: ${psk_yaml}

stealth:
  padding:
    enabled: true
    mode: "random"
    min_pad: 16
    max_pad: 128
  timing:
    enabled: true
    jitter_ms: 2
  camouflage:
    mode: ${cam_mode_yaml}
    static_dir: ${static_yaml}
    proxy_target: ${proxy_yaml}
    server_header: "nginx/1.25.3"

streams:
  max_concurrent: 256
  initial_window: 4194304
  max_window: 2147483647

congestion:
  algorithm: "bbr"

compression:
  algorithm: "none"

limits:
  max_connections: 10000
  max_streams_per_conn: 256
  idle_timeout: 5m
  handshake_timeout: 10s

observability:
  metrics:
    enabled: false
    listen: "127.0.0.1:9090"
  logging:
    level: "info"
    format: "json"
EOF
  chown root:"$SERVICE_NAME" "${CFG_DIR}/server.yaml"
  chmod 640 "${CFG_DIR}/server.yaml"
  log_ok "Server configuration written to ${CFG_DIR}/server.yaml."
}

write_and_start_systemd() {
  local extra_flags=""
  if [[ "$NO_TLS" -eq 1 ]]; then
    extra_flags=" --no-tls"
  fi

  cat >"/etc/systemd/system/${SERVICE_NAME}.service" <<EOF
[Unit]
Description=FGXP (FigoX Protocol) Anti-Censorship Tunnel Server
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=${SERVICE_NAME}
Group=${SERVICE_NAME}
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=full
ProtectHome=true
ReadOnlyPaths=${CFG_DIR} ${STATIC_DIR}
LimitNOFILE=1048576
Restart=always
RestartSec=3
ExecStart=/usr/local/bin/fgxp-server --config ${CFG_DIR}/server.yaml${extra_flags}

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  systemctl enable "$SERVICE_NAME" >/dev/null 2>&1
  systemctl restart "$SERVICE_NAME"
  sleep 2

  if ! systemctl is-active --quiet "$SERVICE_NAME"; then
    log_err "${SERVICE_NAME}.service failed to stay running. Recent logs:"
    journalctl -u "$SERVICE_NAME" -n 40 --no-pager >&2 || true
    exit 1
  fi
  log_ok "${SERVICE_NAME}.service is active and running."
}

interactive_wizard_if_needed() {
  if [[ "$NON_INTERACTIVE" -eq 1 ]] || [[ "$MODE_EXPLICIT" -eq 1 ]]; then
    return 0
  fi

  if ! [[ -r /dev/tty ]] || ! (: </dev/tty) 2>/dev/null; then
    return 0
  fi

  printf "\n${C_BOLD}FGXP Quick Setup${C_RESET}\n"
  printf "  [1] Direct IP + Self-Signed + SNI Camouflage on Port 443 (Default - zero DNS setup)\n"
  printf "  [2] Custom Domain + Let's Encrypt TLS on Port 443 (Best stealth, requires DNS A record)\n"
  printf "  [3] CDN WebSocket Mode (RFC 6455 WS/WSS + secret path, for Imperva / Cloudflare CDN)\n"
  printf "  [4] Plaintext HTTP Framing (--no-tls, Port 80, for Worker / HTTP Inject)\n"
  local choice=""
  read -r -p "Choose setup mode [1-4] (Enter = 1): " choice </dev/tty || choice="1"
  choice="${choice:-1}"

  case "$choice" in
    2)
      MODE="domain"
      read -r -p "Enter your domain (e.g. vpn.yourdomain.com): " DOMAIN </dev/tty || true
      DOMAIN="$(printf '%s' "$DOMAIN" | tr -d '[:space:]')"
      if [[ -z "$DOMAIN" ]]; then
        log_err "Domain cannot be empty in Domain mode."
        exit 1
      fi
      read -r -p "Email for Let's Encrypt (optional, Enter to skip): " EMAIL </dev/tty || true
      EMAIL="$(printf '%s' "$EMAIL" | tr -d '[:space:]')"
      ;;
    3)
      MODE="ws"
      TRANSPORT="ws"
      BEHIND_CDN=1
      read -r -p "CDN-origin domain (optional, Enter for self-signed IP origin): " DOMAIN </dev/tty || true
      DOMAIN="$(printf '%s' "$DOMAIN" | tr -d '[:space:]')"
      if [[ -n "$DOMAIN" ]]; then
        read -r -p "Email for Let's Encrypt (optional, Enter to skip): " EMAIL </dev/tty || true
        EMAIL="$(printf '%s' "$EMAIL" | tr -d '[:space:]')"
      fi
      read -r -p "Secret WebSocket path (Enter = auto /ws-xxxxxxxxxxxx): " WS_PATH </dev/tty || true
      WS_PATH="$(printf '%s' "$WS_PATH" | tr -d '[:space:]')"
      ;;
    4)
      MODE="no-tls"
      NO_TLS=1
      [[ "$PORT_EXPLICIT" -eq 0 ]] && PORT="80"
      ;;
    *)
      MODE="ip-sni"
      local custom_sni=""
      read -r -p "Camouflage SNI hostname (Enter = ${DEFAULT_SNI}): " custom_sni </dev/tty || true
      custom_sni="$(printf '%s' "$custom_sni" | tr -d '[:space:]')"
      [[ -n "$custom_sni" ]] && SNI_HOST="$custom_sni"
      ;;
  esac
}

print_and_save_summary() {
  local target_host="${DOMAIN:-${PUBLIC_IP:-YOUR_SERVER_IP}}"
  local psk_sh psk_ps sni_sh sni_ps target_sh target_ps
  psk_sh="$(sh_single_quote "$PSK")"
  psk_ps="$(ps_single_quote "$PSK")"
  sni_sh="$(sh_single_quote "$SNI_HOST")"
  sni_ps="$(ps_single_quote "$SNI_HOST")"
  target_sh="$(sh_single_quote "${target_host}:${PORT}")"
  target_ps="$(ps_single_quote "${target_host}:${PORT}")"

  local summary
  summary="$(cat <<EOF
======================================================================
  FGXP (FigoX Protocol) Server Installed & Running!
======================================================================
  Mode            : ${MODE}
  Transport       : ${TRANSPORT}${WS_PATH:+ (WS Path: ${WS_PATH})}
  Behind CDN      : $( [[ "$BEHIND_CDN" -eq 1 ]] && echo "true" || echo "false" )
  TLS             : $( [[ "$NO_TLS" -eq 1 ]] && echo "disabled (plaintext)" || echo "enabled" )
  Server Endpoint : ${target_host}:${PORT}
  Pre-Shared Key  : ${PSK}
  SNI / Camouflage: ${SNI_HOST} (active probes -> ${CAMOUFLAGE_MODE}: ${PROXY_TARGET})
  Compression     : none
  Config File     : ${CFG_DIR}/server.yaml
  Service Status  : systemctl status ${SERVICE_NAME}
  Live Logs       : journalctl -u ${SERVICE_NAME} -f

----------------------------------------------------------------------
  Client Commands (Run on your PC / Laptop — creates SOCKS5 on 127.0.0.1:1080)
----------------------------------------------------------------------
EOF
)"

  if [[ "$TRANSPORT" == "ws" ]]; then
    local ws_scheme="wss"
    [[ "$NO_TLS" -eq 1 ]] && ws_scheme="ws"
    local ws_direct_url="${ws_scheme}://${target_host}:${PORT}${WS_PATH}"
    local ws_direct_ps ws_direct_sh ws_cdn_ps ws_cdn_sh
    ws_direct_ps="$(ps_single_quote "$ws_direct_url")"
    ws_direct_sh="$(sh_single_quote "$ws_direct_url")"
    ws_cdn_ps="$(ps_single_quote "wss://YOUR-CDN-DOMAIN${WS_PATH}")"
    ws_cdn_sh="$(sh_single_quote "wss://YOUR-CDN-DOMAIN${WS_PATH}")"

    summary+=$'\n'"[Windows PowerShell — Direct WebSocket Mode]"$'\n'
    summary+="  .\\bin\\fgxp-client.exe --ws ${ws_direct_ps} --psk ${psk_ps} --sni ${sni_ps}"$'\n'
    summary+=$'\n'"[Windows PowerShell — Imperva / Cloudflare CDN + Edge IP Fronting]"$'\n'
    summary+="  .\\bin\\fgxp-client.exe --ws ${ws_cdn_ps} --real-ip 45.223.137.195:443 --host YOUR-CDN-DOMAIN --sni ${sni_ps} --psk ${psk_ps}"$'\n'
    summary+=$'\n'"[Linux / macOS — Direct WebSocket Mode]"$'\n'
    summary+="  fgxp-client --ws ${ws_direct_sh} --psk ${psk_sh} --sni ${sni_sh}"$'\n'
  elif [[ "$NO_TLS" -eq 1 ]]; then
    local http_sni_ps http_sni_sh
    http_sni_ps="$(ps_single_quote "http://${SNI_HOST}/")"
    http_sni_sh="$(sh_single_quote "http://${SNI_HOST}/")"
    summary+=$'\n'"[Windows PowerShell — Plaintext HTTP Framing (Direct --no-tls Server)]"$'\n'
    summary+="  .\\bin\\fgxp-client.exe --server ${target_ps} --psk ${psk_ps} --sni ${http_sni_ps}"$'\n'
    summary+=$'\n'"[Windows PowerShell — HTTP Injection Bypass (ISP Transparent Proxy)]"$'\n'
    summary+="  .\\bin\\fgxp-client.exe --server ${target_ps} --psk ${psk_ps} --inject digital.gov.eg --inject-method connect"$'\n'
    summary+=$'\n'"[Windows PowerShell — Cloudflare Worker WebSocket Relay + SNI]"$'\n'
    summary+="  .\\bin\\fgxp-client.exe --psk ${psk_ps} --ws wss://YOUR-WORKER.workers.dev --sni ${sni_ps}"$'\n'
    summary+=$'\n'"[Linux / macOS — Plaintext HTTP Framing]"$'\n'
    summary+="  fgxp-client --server ${target_sh} --psk ${psk_sh} --sni ${http_sni_sh}"$'\n'
  else
    summary+=$'\n'"[Windows PowerShell — Maximum DPI Bypass (uTLS Chrome + SNI)]"$'\n'
    summary+="  .\\bin\\fgxp-client.exe --server ${target_ps} --psk ${psk_ps} --sni ${sni_ps}"$'\n'
    summary+=$'\n'"[Windows PowerShell — Custom CDN / Fronting IP + SNI (optional)]"$'\n'
    summary+="  .\\bin\\fgxp-client.exe --server ${target_ps} --real-ip 104.16.132.229:443 --psk ${psk_ps} --sni ${sni_ps}"$'\n'
    summary+=$'\n'"[Linux / macOS]"$'\n'
    summary+="  fgxp-client --server ${target_sh} --psk ${psk_sh} --sni ${sni_sh}"$'\n'
  fi

  summary+=$'\n'"----------------------------------------------------------------------"$'\n'
  summary+="IMPORTANT: Also open TCP port ${PORT}"
  if [[ -n "$DOMAIN" && "$NO_TLS" -eq 0 && "$PORT" != "80" ]]; then
    summary+=" (and TCP 80 for Certbot)"
  fi
  summary+=" in your Cloud Provider Firewall"$'\n'
  summary+="(AWS Security Group / GCP VPC Firewall / Azure NSG / Oracle Ingress Rules)."$'\n'
  summary+="Then point your browser / Clash / v2rayN / Nekoray to SOCKS5 127.0.0.1:1080."$'\n'
  summary+="======================================================================"

  printf '\n%s\n\n' "$summary"
  umask 077
  printf '%s\n' "$summary" >"${CFG_DIR}/client-info.txt"
  chmod 600 "${CFG_DIR}/client-info.txt"
  log_info "Connection summary saved to ${CFG_DIR}/client-info.txt (chmod 600)."
}

main() {
  MODE="ip-sni"
  MODE_EXPLICIT=0
  TRANSPORT="tcp"
  NO_TLS=0
  WS_PATH=""
  BEHIND_CDN=0
  DOMAIN=""
  EMAIL=""
  PSK="${FGXP_PSK:-}"
  PORT="443"
  PORT_EXPLICIT=0
  SNI_HOST=""
  CAMOUFLAGE_MODE="reverse_proxy"
  PROXY_TARGET="$DEFAULT_PROXY_TARGET"
  STATIC_DIR="$DEFAULT_STATIC_DIR"
  REPO_URL="$DEFAULT_REPO"
  BRANCH="$DEFAULT_BRANCH"
  NON_INTERACTIVE=0

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --mode)
        MODE="${2:?--mode requires a value (ip-sni|domain|ws|no-tls)}"
        MODE_EXPLICIT=1
        case "$MODE" in
          ip-sni|domain)
            ;;
          ws)
            TRANSPORT="ws"
            BEHIND_CDN=1
            ;;
          no-tls)
            NO_TLS=1
            [[ "$PORT_EXPLICIT" -eq 0 ]] && PORT="80"
            ;;
          *)
            log_err "Invalid --mode: ${MODE} (expected ip-sni, domain, ws, or no-tls)"
            exit 1
            ;;
        esac
        shift 2
        ;;
      --domain)
        DOMAIN="${2:?--domain requires a value}"
        if [[ "$MODE_EXPLICIT" -eq 0 ]]; then
          MODE="domain"
          MODE_EXPLICIT=1
        fi
        shift 2
        ;;
      --email)
        EMAIL="${2:?--email requires a value}"
        shift 2
        ;;
      --psk)
        PSK="${2:?--psk requires a value}"
        shift 2
        ;;
      --port)
        PORT="${2:?--port requires a value}"
        PORT_EXPLICIT=1
        shift 2
        ;;
      --sni)
        SNI_HOST="${2:?--sni requires a value}"
        shift 2
        ;;
      --ws-path)
        WS_PATH="${2:?--ws-path requires a value}"
        TRANSPORT="ws"
        shift 2
        ;;
      --behind-cdn)
        BEHIND_CDN=1
        shift
        ;;
      --camouflage)
        CAMOUFLAGE_MODE="${2:?--camouflage requires reverse_proxy or static}"
        shift 2
        ;;
      --proxy-target)
        PROXY_TARGET="${2:?--proxy-target requires a URL}"
        shift 2
        ;;
      --static-dir)
        STATIC_DIR="${2:?--static-dir requires a path}"
        shift 2
        ;;
      --no-tls)
        NO_TLS=1
        if [[ "$MODE_EXPLICIT" -eq 0 ]]; then
          MODE="no-tls"
          MODE_EXPLICIT=1
        fi
        [[ "$PORT_EXPLICIT" -eq 0 ]] && PORT="80"
        shift
        ;;
      --repo)
        REPO_URL="${2:?--repo requires a URL}"
        shift 2
        ;;
      --branch)
        BRANCH="${2:?--branch requires a name}"
        shift 2
        ;;
      --non-interactive)
        NON_INTERACTIVE=1
        shift
        ;;
      -h|--help)
        usage
        exit 0
        ;;
      *)
        log_err "Unknown argument: $1"
        usage
        exit 1
        ;;
    esac
  done

  if ! [[ "$PORT" =~ ^[0-9]+$ ]] || [[ "$PORT" -lt 1 || "$PORT" -gt 65535 ]]; then
    log_err "Invalid port: ${PORT}"
    exit 1
  fi
  if [[ "$CAMOUFLAGE_MODE" != "reverse_proxy" && "$CAMOUFLAGE_MODE" != "static" ]]; then
    log_err "Invalid --camouflage mode: ${CAMOUFLAGE_MODE} (expected reverse_proxy or static)"
    exit 1
  fi
  if [[ "$MODE" == "domain" && -z "$DOMAIN" ]]; then
    log_err "--mode domain requires --domain <host>"
    exit 1
  fi

  require_root_and_os
  detect_arch
  interactive_wizard_if_needed

  if [[ -z "$SNI_HOST" ]]; then
    if [[ -n "$DOMAIN" ]]; then
      SNI_HOST="$DOMAIN"
    else
      SNI_HOST="$DEFAULT_SNI"
    fi
  fi

  apt_install_base
  sync_system_clock

  if [[ -z "$PSK" ]]; then
    PSK="$(openssl rand -hex 24)"
    log_info "Generated strong random Pre-Shared Key."
  fi
  if [[ "$TRANSPORT" == "ws" && -z "$WS_PATH" ]]; then
    WS_PATH="/ws-$(openssl rand -hex 6)"
    log_info "Generated secret WebSocket path: ${WS_PATH}"
  fi
  if [[ -n "$WS_PATH" && "${WS_PATH:0:1}" != "/" ]]; then
    WS_PATH="/${WS_PATH}"
  fi

  PUBLIC_IP="$(detect_public_ip)"
  log_info "Detected Public IPv4: ${PUBLIC_IP:-unknown}"

  install_or_verify_go
  fetch_source
  build_binaries
  setup_user_and_dirs
  configure_firewall
  configure_sysctl_bbr
  provision_certs
  write_server_config
  write_and_start_systemd
  print_and_save_summary
}

main "$@"
