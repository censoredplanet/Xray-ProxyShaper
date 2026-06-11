//go:build !linux

package proxyshaper

import "os/exec"

func configureGeneratedFlowCommand(cmd *exec.Cmd) {}

func cleanupGeneratedFlowCommand(cmd *exec.Cmd) {}
