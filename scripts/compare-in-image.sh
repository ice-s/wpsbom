#!/bin/sh
# Runs inside a distribution image: diffs wpsbom's package list against the package manager's own.
set -eu
wpsbom scan / -o table | tail -n +2 | awk '{print $1 " " $2}' | sort > /tmp/wpsbom.txt
if command -v dpkg-query >/dev/null 2>&1; then
  # Same states wpsbom keeps: anything whose files are on disk.
  dpkg-query -W -f='${db:Status-Status} ${Package} ${Version}\n' \
    | awk '$1 != "not-installed" && $1 != "config-files" && $1 != "half-installed" {print $2 " " $3}' \
    | sort -u > /tmp/native.txt
elif command -v apk >/dev/null 2>&1; then
  # apk prints name-version; compare in that form.
  awk '{print $1 "-" $2}' /tmp/wpsbom.txt | sort > /tmp/wpsbom.nv && mv /tmp/wpsbom.nv /tmp/wpsbom.txt
  apk info -v 2>/dev/null | sort > /tmp/native.txt
else
  echo "no supported package manager" >&2
  exit 2
fi
if diff -u /tmp/native.txt /tmp/wpsbom.txt; then
  echo "OK $(wc -l < /tmp/wpsbom.txt) packages"
else
  exit 1
fi
