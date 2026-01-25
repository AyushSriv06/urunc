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

package unikernels

import (
	"fmt"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"github.com/urunc-dev/urunc/pkg/unikontainers/initrd"
	"github.com/urunc-dev/urunc/pkg/unikontainers/types"
)

const (
	UklUnikernel string = "ukl"
)

type UKL struct {
	App        string
	Command    string
	Monitor    string
	Env        []string
	Net        LinuxNet
	Blk        []types.BlockDevParams
	RootFsType string
	InitrdConf bool
	ProcConfig types.ProcessConfig
}

func (u *UKL) CommandString() (string, error) {
	rdinit := ""
	bootParams := "panic=-1"

	consoleStr := ""

	if runtime.GOARCH == "arm64" && u.Monitor == "qemu" {
		consoleStr = "console=ttyAMA0"
	} else {
		consoleStr = "console=ttyS0"
	}
	bootParams += " " + consoleStr

	switch u.RootFsType {
	case "block":
		rootParams := "root=/dev/vda rw"
		bootParams += " " + rootParams
	case "initrd":
		rootParams := "root=/dev/ram0 rw"
		rdinit = "rd"
		bootParams += " " + rootParams
	case "9pfs":
		rootParams := "root=fs0 rw rootfstype=9p rootflags="
		rootParams += "trans=virtio,version=9p2000.L,msize=5000000,cache=mmap,posixacl"
		bootParams += " " + rootParams
	case "virtiofs":
		rootParams := "root=fs0 rw rootfstype=virtiofs"
		bootParams += " " + rootParams
	}
	if u.Net.Address != "" {
		netParams := fmt.Sprintf("ip=%s::%s:%s:urunc:eth0:off",
			u.Net.Address,
			u.Net.Gateway,
			u.Net.Mask)
		bootParams += " " + netParams
	}
	if !u.InitrdConf {
		for _, eVar := range u.Env {
			bootParams += " " + eVar
		}
	} else {
		if u.RootFsType == "initrd" {
			bootParams += " URUNIT_CONFIG="
			bootParams += urunitConfPath
		} else {
			bootParams += " retain_initrd URUNIT_CONFIG="
			bootParams += retainInitrdPath
		}
	}
	if !IsIPInSubnet(u.Net) {
		bootParams += " URUNIT_DEFROUTE=1"
	}
	if u.App != "" {
		initParams := rdinit + "init=" + u.App + " -- " + u.Command
		bootParams += " " + initParams
	}

	return bootParams, nil
}

func (u *UKL) SupportsBlock() bool {
	return true
}

func (u *UKL) SupportsFS(fsType string) bool {
	switch fsType {
	case "ext2":
		return true
	case "ext3":
		return true
	case "ext4":
		return true
	case "9pfs":
		return true
	case "virtiofs":
		return true
	default:
		return false
	}
}

func (u *UKL) MonitorNetCli(_ string, _ string) string {
	return ""
}

func (u *UKL) MonitorBlockCli() []types.MonitorBlockArgs {
	if len(u.Blk) == 0 {
		return nil
	}
	blkArgs := make([]types.MonitorBlockArgs, 0, len(u.Blk))
	switch u.Monitor {
	case "qemu":
		for _, aBlock := range u.Blk {
			bcli1 := fmt.Sprintf(" -device virtio-blk-pci,serial=%s,drive=%s", aBlock.ID, aBlock.ID)
			bcli2 := fmt.Sprintf(" -drive format=raw,if=none,id=%s,file=%s", aBlock.ID, aBlock.Source)
			blkArgs = append(blkArgs, types.MonitorBlockArgs{
				ExactArgs: bcli1 + bcli2,
			})
		}
	case "firecracker":
		for _, aBlock := range u.Blk {
			id := aBlock.ID
			if u.Monitor == "firecracker" {
				id = "FC" + aBlock.ID
			}
			blkArgs = append(blkArgs, types.MonitorBlockArgs{
				ID:   id,
				Path: aBlock.Source,
			})
		}
	case "cloud-hypervisor":
		// Cloud Hypervisor also supports blocks, logic similar to Firecracker/QEMU logic if needed
		// For now we assume standard cloud-hypervisor handling from hypervisors package
		for _, aBlock := range u.Blk {
			blkArgs = append(blkArgs, types.MonitorBlockArgs{
				ID:   aBlock.ID,
				Path: aBlock.Source,
			})
		}
	default:
		return nil
	}

	return blkArgs
}

func (u *UKL) MonitorCli() types.MonitorCliArgs {
	switch u.Monitor {
	case "qemu":
		extraCliArgs := types.MonitorCliArgs{
			OtherArgs: " -no-reboot -serial stdio -nodefaults",
		}
		if u.InitrdConf && u.RootFsType != "initrd" {
			extraCliArgs.ExtraInitrd = urunitConfPath
		}
		return extraCliArgs
	case "firecracker":
		if u.InitrdConf && u.RootFsType != "initrd" {
			return types.MonitorCliArgs{
				ExtraInitrd: urunitConfPath,
			}
		}
		return types.MonitorCliArgs{}
	case "cloud-hypervisor":
		if u.InitrdConf && u.RootFsType != "initrd" {
			return types.MonitorCliArgs{
				ExtraInitrd: urunitConfPath,
			}
		}
		return types.MonitorCliArgs{}
	default:
		return types.MonitorCliArgs{}
	}
}

func (u *UKL) Init(data types.UnikernelParams) error {
	err := u.parseCmdLine(data.CmdLine)
	if err != nil {
		return err
	}

	u.configureNetwork(data.Net)
	u.Blk = data.Block
	u.RootFsType = data.Rootfs.Type
	u.Env = data.EnvVars
	u.Monitor = data.Monitor
	u.ProcConfig = data.ProcConf

	// if the application contains urunit, then we assume
	// that the init process is based on our urunit
	// and hence it can handle the information we pass to
	// it through initrd.
	u.InitrdConf = strings.Contains(u.App, "urunit")
	if u.InitrdConf {
		err := u.setupUrunitConfig(data.Rootfs)
		if err != nil {
			return err
		}
	}

	return nil
}

// parseCmdLine extracts the application and command from command line arguments.
// Multi-word arguments are wrapped in single quotes for urunit compatibility.
func (u *UKL) parseCmdLine(cmdLine []string) error {
	if len(cmdLine) == 0 {
		return fmt.Errorf("no init was specified")
	}

	// Wrap multi-word arguments in quotes for urunit
	normalizedArgs := make([]string, len(cmdLine))
	for i, arg := range cmdLine {
		arg = strings.TrimSpace(arg)
		if strings.Contains(arg, " ") {
			normalizedArgs[i] = "'" + arg + "'"
		} else {
			normalizedArgs[i] = arg
		}
	}

	u.App = normalizedArgs[0]
	if len(normalizedArgs) > 1 {
		u.Command = strings.Join(normalizedArgs[1:], " ")
	} else {
		u.Command = ""
	}

	return nil
}

// configureNetwork sets up network parameters.
func (u *UKL) configureNetwork(net types.NetDevParams) {
	u.Net.Address = net.IP
	u.Net.Gateway = net.Gateway
	u.Net.Mask = net.Mask
}

// setupUrunitConfig creates the urunit configuration file with environment variables.
func (u *UKL) setupUrunitConfig(rfs types.RootfsParams) error {
	urunitConfig := u.buildUrunitConfig()

	var err error
	if u.RootFsType == "initrd" {
		initrdToUpdate := filepath.Join(rfs.MonRootfs, rfs.Path)
		err = initrd.AddFileToInitrd(initrdToUpdate, urunitConfig, urunitConfPath)
	} else {
		urunitConfigFile := filepath.Join(rfs.MonRootfs, urunitConfPath)
		err = createFile(urunitConfigFile, urunitConfig)
	}

	if err != nil {
		return fmt.Errorf("failed to setup urunit config: %w", err)
	}

	return nil
}

// buildEnvConfig creates the environment configuration content for urunit.
func (u *UKL) buildUrunitConfig() string {
	// Format: UES\n<env1>\n<env2>\n...\nUEE\n
	var sb strings.Builder
	sb.WriteString(envStartMarker)
	sb.WriteString("\n")
	if len(u.Env) > 0 {
		sb.WriteString(strings.Join(u.Env, "\n"))
		sb.WriteString("\n")
	}
	sb.WriteString(envEndMarker)
	sb.WriteString("\n")
	sb.WriteString(lpcStartMarker)
	sb.WriteString("\n")
	sb.WriteString("UID:")
	sb.WriteString(strconv.FormatUint(uint64(u.ProcConfig.UID), 10))
	sb.WriteString("\n")
	sb.WriteString("GID:")
	sb.WriteString(strconv.FormatUint(uint64(u.ProcConfig.GID), 10))
	sb.WriteString("\n")
	sb.WriteString("WD:")
	sb.WriteString(u.ProcConfig.WorkDir)
	sb.WriteString("\n")
	sb.WriteString(lpcEndMarker)
	sb.WriteString("\n")
	sb.WriteString(blkStartMarker)
	sb.WriteString("\n")
	for _, b := range u.Blk {
		if b.ID == "rootfs" {
			continue
		}
		sb.WriteString("ID:")
		if u.Monitor == "firecracker" {
			sb.WriteString("FC")
		}
		sb.WriteString(b.ID)
		sb.WriteString("\n")
		sb.WriteString("MP:")
		sb.WriteString(b.MountPoint)
		sb.WriteString("\n")
	}
	sb.WriteString(blkEndMarker)
	sb.WriteString("\n")
	return sb.String()
}

func newUKL() *UKL {
	uklStruct := new(UKL)
	return uklStruct
}
