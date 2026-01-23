// Copyright (c) 2023-2025, Nubificus LTD
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package hypervisors

import (
	"fmt"
	"strings"
	"syscall"

	"github.com/urunc-dev/urunc/pkg/unikontainers/types"
)

const (
	CloudHypervisorVmm    VmmType = "cloud-hypervisor"
	CloudHypervisorBinary string  = "cloud-hypervisor"
)

type CloudHypervisor struct {
	binaryPath string
	binary     string
}

func (ch *CloudHypervisor) Stop(pid int) error {
	return killProcess(pid)
}

func (ch *CloudHypervisor) Ok() error {
	return nil
}

// UsesKVM returns true as Cloud Hypervisor is a KVM-based VMM
func (ch *CloudHypervisor) UsesKVM() bool {
	return true
}

// SupportsSharedfs returns true as Cloud Hypervisor supports virtiofs
func (ch *CloudHypervisor) SupportsSharedfs(fsType string) bool {
	switch fsType {
	case "virtiofs":
		return true
	default:
		return false
	}
}

func (ch *CloudHypervisor) Path() string {
	return ch.binaryPath
}

func (ch *CloudHypervisor) Execve(args types.ExecArgs, ukernel types.Unikernel) error {
	chMem := BytesToStringMB(args.MemSizeB)

	// Start building the command
	cmdString := ch.binaryPath

	// Memory configuration
	cmdString += fmt.Sprintf(" --memory size=%sM", chMem)

	// CPU configuration
	if args.VCPUs > 0 {
		cmdString += fmt.Sprintf(" --cpus boot=%d", args.VCPUs)
	}

	// Kernel path
	cmdString += " --kernel " + args.UnikernelPath

	// Console configuration - disable graphical output
	cmdString += " --console off --serial tty"

	// Seccomp configuration
	if args.Seccomp {
		cmdString += " --seccomp true"
	} else {
		cmdString += " --seccomp false"
	}

	// Network configuration
	if args.Net.TapDev != "" {
		netCli := ukernel.MonitorNetCli(args.Net.TapDev, args.Net.MAC)
		if netCli == "" {
			// Default network configuration for Cloud Hypervisor
			cmdString += fmt.Sprintf(" --net tap=%s,mac=%s", args.Net.TapDev, args.Net.MAC)
		} else {
			cmdString += netCli
		}
	}

	// Block device configuration
	blockArgs := ukernel.MonitorBlockCli()
	for _, blockArg := range blockArgs {
		if blockArg.ExactArgs != "" {
			cmdString += blockArg.ExactArgs
		} else if blockArg.Path != "" {
			cmdString += fmt.Sprintf(" --disk path=%s", blockArg.Path)
			if blockArg.ID != "" {
				cmdString += fmt.Sprintf(",id=%s", blockArg.ID)
			}
		}
	}

	// Initrd configuration
	if args.InitrdPath != "" {
		cmdString += " --initramfs " + args.InitrdPath
	}

	// Check for extra initrd from unikernel monitor args
	extraMonArgs := ukernel.MonitorCli()
	if extraMonArgs.ExtraInitrd != "" && args.InitrdPath == "" {
		cmdString += " --initramfs " + extraMonArgs.ExtraInitrd
	}

	switch args.Sharedfs.Type {
	case "virtiofs":
		cmdString += fmt.Sprintf(" --fs tag=fs0,socket=/tmp/virtiofsd.sock")
	default:
		// No shared filesystem
	}

	if args.VAccelType == "vsock" {
		cmdString += fmt.Sprintf(" --vsock cid=%d,socket=%s/vaccel.sock",
			args.VSockDevID, args.VSockDevPath)
	}

	cmdString += extraMonArgs.OtherArgs

	exArgs := strings.Split(cmdString, " ")

	// Add the command line arguments for the kernel
	exArgs = append(exArgs, "--cmdline", args.Command)

	vmmLog.WithField("cloud-hypervisor command", exArgs).Debug("Ready to execve cloud-hypervisor")

	return syscall.Exec(ch.Path(), exArgs, args.Environment) //nolint: gosec
}
