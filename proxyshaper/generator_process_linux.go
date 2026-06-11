package proxyshaper

import (
	"errors"
	"os/exec"
	"syscall"
	"time"
)

const generatedFlowWaitDelay = 2 * time.Second

func configureGeneratedFlowCommand(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.WaitDelay = generatedFlowWaitDelay
	cmd.Cancel = func() error {
		return killGeneratedFlowProcessGroup(cmd)
	}
}

func cleanupGeneratedFlowCommand(cmd *exec.Cmd) {
	_ = killGeneratedFlowProcessGroup(cmd)
}

func killGeneratedFlowProcessGroup(cmd *exec.Cmd) error {
	if cmd.Process == nil {
		return nil
	}
	err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	if err == nil || errors.Is(err, syscall.ESRCH) {
		return nil
	}
	if killErr := cmd.Process.Kill(); killErr != nil && !errors.Is(killErr, syscall.ESRCH) {
		return killErr
	}
	return err
}
