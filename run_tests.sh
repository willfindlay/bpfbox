#!/bin/bash

# Based on https://github.com/cilium/ebpf/blob/master/run-tests.sh
# Test bpfbox under a different Linux kernel with QEMU.
# Requires virtme and QEMU.

# Git repository containing my kernel images for unit testing
readonly linux_images="https://github.com/willfindlay/linux-images"

readonly kernel_version="${1:-}"
if [[ -z "${kernel_version}" ]]; then
  echo "Expecting kernel version as first argument"
  exit 1
fi

# Use sudo if /dev/kvm isn't accessible by the current user.
sudo=""
if [[ ! -r /dev/kvm || ! -w /dev/kvm ]]; then
  sudo="sudo"
fi
readonly sudo

echo "$kernel_version"
