#!/usr/bin/env bash
set -euo pipefail

PORT="${1:-${PORT:-8503}}"
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="${ROOT_DIR}/.venv"

cleanup_code_cache() {
  find "${ROOT_DIR}" -type d -name "__pycache__" -prune -exec rm -rf {} +
  find "${ROOT_DIR}" -type d -name ".pytest_cache" -prune -exec rm -rf {} +
  find "${ROOT_DIR}" -type d -name ".mypy_cache" -prune -exec rm -rf {} +
  find "${ROOT_DIR}" -type d -name ".ruff_cache" -prune -exec rm -rf {} +
  rm -rf "${ROOT_DIR}/.streamlit/cache"
}

free_port() {
  if command -v lsof >/dev/null 2>&1; then
    local pids
    pids="$(lsof -ti tcp:"${PORT}" || true)"
    if [[ -n "${pids}" ]]; then
      echo "${pids}" | xargs kill -9 >/dev/null 2>&1 || true
    fi
  fi
}

ensure_venv() {
  if [[ ! -d "${VENV_DIR}" ]]; then
    python3 -m venv "${VENV_DIR}"
  fi
  # shellcheck disable=SC1091
  source "${VENV_DIR}/bin/activate"
}

ensure_env_file() {
  if [[ ! -f "${ROOT_DIR}/.env" && -f "${ROOT_DIR}/.env.example" ]]; then
    cp "${ROOT_DIR}/.env.example" "${ROOT_DIR}/.env"
  fi
}

install_dependencies() {
  "${VENV_DIR}/bin/pip" install --upgrade pip
  "${VENV_DIR}/bin/pip" install -r "${ROOT_DIR}/requirements.txt"
}

clear_runtime_cache() {
  "${VENV_DIR}/bin/python" -m streamlit cache clear >/dev/null 2>&1 || true
  if [[ "${CLEAR_PIP_CACHE:-false}" == "true" ]]; then
    "${VENV_DIR}/bin/python" -m pip cache purge >/dev/null 2>&1 || true
  fi
}

start_streamlit() {
  cd "${ROOT_DIR}"
  exec "${VENV_DIR}/bin/python" -m streamlit run ui.py --server.address 0.0.0.0 --server.port "${PORT}"
}

cleanup_code_cache
free_port
ensure_venv
ensure_env_file
install_dependencies
clear_runtime_cache
start_streamlit
