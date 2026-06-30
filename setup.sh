#!/usr/bin/env bash
#
# Acutest backend dev setup — installs the toolchain, prepares config, and builds.
# Intended for Linux / WSL2. Run from the repository root:
#
#   ./setup.sh
#
# It is idempotent: safe to re-run. It will NOT install Docker Desktop (a GUI
# install on Windows) — it only checks for it and tells you what to do.

set -euo pipefail

# Always operate from the repo root (this script's directory).
cd "$(dirname "$(readlink -f "$0")")"

bold() { printf '\033[1m%s\033[0m\n' "$1"; }
warn() { printf '\033[33m! %s\033[0m\n' "$1"; }
ok()   { printf '\033[32m✓ %s\033[0m\n' "$1"; }
step() { printf '\n\033[1m==> %s\033[0m\n' "$1"; }

# --- sanity: not native Windows -------------------------------------------------
if [ "${OS:-}" = "Windows_NT" ] && [ -z "${WSL_DISTRO_NAME:-}" ]; then
  warn "This looks like native Windows. Run this inside WSL2, not PowerShell/CMD."
  exit 1
fi

# --- system build dependencies --------------------------------------------------
# Sourced from the project Dockerfile, which installs: make, pkg-config,
# libssl-dev (a C toolchain comes from the rust base image). On a bare
# Debian/Ubuntu/WSL we add build-essential for that toolchain, plus curl/git/
# ca-certificates to bootstrap mise. The heavy media crates (webp, lcms2, usvg,
# image) build from bundled C source, so they need a compiler but no extra libs.
step "Installing system build dependencies"
SYS_DEPS="build-essential make pkg-config libssl-dev curl git ca-certificates"
if command -v apt-get >/dev/null 2>&1; then
  if [ "$(id -u)" -eq 0 ]; then SUDO=""; else SUDO="sudo"; fi
  $SUDO apt-get update -qq
  # shellcheck disable=SC2086
  $SUDO apt-get install -y $SYS_DEPS
  ok "system build dependencies installed"
else
  warn "Non-apt system detected; install the equivalents of these yourself:"
  warn "  $SYS_DEPS"
  warn "  Fedora/RHEL: gcc gcc-c++ make pkgconf-pkg-config openssl-devel"
  warn "  Arch:        base-devel pkgconf openssl"
fi

# --- git ------------------------------------------------------------------------
step "Checking git"
command -v git >/dev/null 2>&1 || { warn "git not found. Install it first (e.g. sudo apt install git)."; exit 1; }
ok "git present"

# --- mise -----------------------------------------------------------------------
step "Ensuring mise is installed"
if ! command -v mise >/dev/null 2>&1; then
  if [ -x "$HOME/.local/bin/mise" ]; then
    export PATH="$HOME/.local/bin:$PATH"
  else
    bold "Installing mise..."
    curl -fsSL https://mise.run | sh
    export PATH="$HOME/.local/bin:$PATH"
  fi
fi
MISE="$(command -v mise || echo "$HOME/.local/bin/mise")"
"$MISE" --version >/dev/null || { warn "mise install failed."; exit 1; }
ok "mise: $("$MISE" --version)"

warn "If 'mise' is not on your PATH in new shells, add it (bash):"
echo "    echo 'eval \"\$(~/.local/bin/mise activate bash)\"' >> ~/.bashrc"

# mise must trust the repo config before it will run tasks/tools.
"$MISE" trust --quiet . 2>/dev/null || "$MISE" trust . || true

# --- toolchain (Rust, Node, pnpm, nextest) --------------------------------------
step "Installing pinned toolchain (Rust, Node, pnpm, cargo-nextest)"
"$MISE" install
ok "toolchain installed"

# --- config files ---------------------------------------------------------------
step "Preparing configuration"
if [ ! -f livekit.yml ]; then
  cp livekit.example.yml livekit.yml
  ok "created livekit.yml from example"
else
  ok "livekit.yml already exists"
fi
# Revolt.toml ships with working dev defaults; create an overrides file to edit.
if [ ! -f Revolt.overrides.toml ]; then
  cat > Revolt.overrides.toml <<'TOML'
# Local overrides for development. Anything here wins over Revolt.toml.
# Example: point at remapped ports, add Sentry DSNs, etc.
TOML
  ok "created empty Revolt.overrides.toml (edit as needed)"
else
  ok "Revolt.overrides.toml already exists"
fi

# --- docker (checked, not installed) --------------------------------------------
step "Checking Docker (needed to RUN, not to build)"
if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
  ok "Docker daemon is reachable"
  DOCKER_OK=1
else
  warn "Docker is not available."
  warn "Install Docker Desktop and enable the WSL2 integration, then start it:"
  warn "  https://www.docker.com/products/docker-desktop"
  warn "You can still build now; you just can't 'mise start' until Docker runs."
  DOCKER_OK=0
fi

# --- build ----------------------------------------------------------------------
step "Building the workspace (first cold build can take 10-30 min)"
"$MISE" build
ok "build complete"

# --- done -----------------------------------------------------------------------
step "Setup finished"
bold "Next steps:"
if [ "${DOCKER_OK:-0}" = "1" ]; then
  echo "  mise start          # bring up infra + run all services"
else
  echo "  (start Docker Desktop first, then:)"
  echo "  mise start          # bring up infra + run all services"
fi
echo "  open http://localhost:14702/swagger/   # API docs once running"
echo "  open http://localhost:14080            # verification/reset emails (Maildev)"
echo
bold "Run the tests (verifies the fork + game-status changes):"
echo "  TEST_DB=REFERENCE cargo nextest run -p revolt-delta set_game_activity clear_game_activity"
echo "  TEST_DB=REFERENCE cargo nextest run    # full suite"
echo
bold "Stop services:  Ctrl+C in the 'mise start' terminal, then  mise docker:stop"
