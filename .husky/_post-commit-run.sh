#!/usr/bin/env sh

set -u
SHA="$1"
TS="$2"
NEED_FRONTEND="$3"
NEED_RUST="$4"

REPO_ROOT="$(git rev-parse --show-toplevel)"
LOG="$REPO_ROOT/.git/post-commit.log"
FAILED=""

cd "$REPO_ROOT" || exit 0

run() {
  _pc_name="$1"
  shift
  if _pc_out=$("$@" 2>&1); then
    printf '[%s] %s %s PASS\n' "$TS" "$SHA" "$_pc_name" >> "$LOG"
  else
    printf '[%s] %s %s FAIL\n' "$TS" "$SHA" "$_pc_name" >> "$LOG"
    printf '  %s\n' "$(echo "$_pc_out" | tail -n 25 | sed 's/^/  /')" >> "$LOG"
    FAILED="${FAILED} ${_pc_name}"
  fi
}

if [ "$NEED_FRONTEND" = "1" ]; then
  run "vitest" npm test --silent
fi

if [ "$NEED_RUST" = "1" ]; then
  ( cd src-tauri && run "cargo-clippy" cargo clippy --all-targets --no-deps -- -D warnings )
  ( cd src-tauri && run "cargo-test" cargo test --all )
fi

if [ -n "$FAILED" ]; then
  # Try to surface a Windows toast; fall back to writing a marker file the user can `cat`.
  if command -v powershell.exe >/dev/null 2>&1; then
    powershell.exe -NoProfile -Command "[reflection.assembly]::loadwithpartialname('System.Windows.Forms') | Out-Null; [System.Windows.Forms.MessageBox]::Show('Post-commit checks FAILED:${FAILED}\nSee .git/post-commit.log','spy-detector','OK','Error') | Out-Null" >/dev/null 2>&1 || true
  fi
  printf '[%s] %s SUMMARY FAILED:%s\n' "$TS" "$SHA" "$FAILED" >> "$LOG"
else
  printf '[%s] %s SUMMARY PASS\n' "$TS" "$SHA" >> "$LOG"
fi
exit 0
