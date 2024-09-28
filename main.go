package main

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"runtime"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/shirou/gopsutil/process"
	"golang.org/x/sys/windows"
)

type ProcessInfo struct {
	PID            int32
	ParentPID      int32
	ImageName      string
	Cmdline        string
	CurrentDir     string
	StartTime      time.Time
	ExecutablePath string
	Signer         string
	Environment    string
}

func main() {
	if runtime.GOOS != "windows" {
		fmt.Println("non windows is unsupported")
		return
	}
	fmt.Println("lol how did you get yourself malware again, smh")

	fmt.Println("blocking network accesss...")
	runCmd("ipconfig /release")
	if !amAdmin() {
		runMeElevated()
		return
	}

	fmt.Println("setting reboot to safe mode minimal")
	setSafeMode()

	fmt.Println("saving processes")
	// get a list of all processes
	processes, err := process.Processes()
	if err != nil {
		log.Fatalf("Error retrieving processes: %v", err)
	}

	var procInfos []ProcessInfo
	for _, proc := range processes {
		pid := proc.Pid

		// get parrent pid
		ppid, err := proc.Ppid()
		if err != nil {
			ppid = 0
		}

		// exe name
		name, err := proc.Name()
		if err != nil {
			name = ""
		}

		// args
		cmdline, err := proc.Cmdline()
		if err != nil {
			cmdline = ""
		}

		// working dir
		cwd, err := proc.Cwd()
		if err != nil {
			cwd = ""
		}

		// start time
		createTime, err := proc.CreateTime()
		var startTime time.Time
		if err == nil {
			startTime = time.Unix(0, createTime*int64(time.Millisecond))
		}

		exe, err := proc.Exe()
		if err != nil {
			exe = "???"
		}

		exeEnv, err := proc.Environ()
		if err != nil {
			exeEnv[0] = "COULDNT_READ_ENV=1"
		}

		info := ProcessInfo{
			PID:            pid,
			ParentPID:      ppid,
			ImageName:      name,
			Cmdline:        cmdline,
			CurrentDir:     cwd,
			StartTime:      startTime,
			ExecutablePath: exe,
			Environment:    strings.Join(exeEnv, ";"),
		}
		procInfos = append(procInfos, info)
	}

	// Sort the processes by PID
	sort.Slice(procInfos, func(i, j int) bool {
		return procInfos[i].PID < procInfos[j].PID
	})

	// fmt.Printf("%-6s %-6s %-20s %-30s %-30s %-20s\n", "PID", "PPID", "ImageName", "Cmdline", "CurrentDir", "StartTime")
	// for _, info := range procInfos {
	// fmt.Printf("%-6d %-6d %-20s %-30s %-30s %-20s\n",
	// info.PID, info.ParentPID, info.ImageName, info.Cmdline, info.CurrentDir, info.StartTime.Format(time.RFC3339))
	// }

	dirPath := `C:\saveme`
	err = os.MkdirAll(dirPath, os.ModePerm)
	if err != nil {
		log.Fatalf("Error creating directory %s: %v", dirPath, err)
	}

	filePath := `C:\saveme\processes.log`
	file, err := os.Create(filePath)
	if err != nil {
		log.Fatalf("Error creating file %s: %v", filePath, err)
	}
	defer file.Close()

	fmt.Fprintf(file, "PID\tName\tCmdline\tCurrentDir\tStartTime\tParentPID\tPath\tEnvironment\n")
	for _, info := range procInfos {
		fmt.Fprintf(file, "%d\t%s\t%s\t%s\t%s\t%d\t%s\n", info.PID, info.ImageName, info.Cmdline, info.CurrentDir, info.StartTime.Format(time.RFC3339), info.ParentPID, info.ExecutablePath, info.Environment)
	}

	fmt.Println("done saving processes")

	runCmd("msg * finished; check C:saveme; running rkill; reboot asap")
	runRKill()
}

func runMeElevated() {
	verb := "runas"
	exe, _ := os.Executable()
	cwd, _ := os.Getwd()
	args := strings.Join(os.Args[1:], " ")

	verbPtr, _ := syscall.UTF16PtrFromString(verb)
	exePtr, _ := syscall.UTF16PtrFromString(exe)
	cwdPtr, _ := syscall.UTF16PtrFromString(cwd)
	argPtr, _ := syscall.UTF16PtrFromString(args)

	var showCmd int32 = 1 //SW_NORMAL

	err := windows.ShellExecute(0, verbPtr, exePtr, argPtr, cwdPtr, showCmd)
	if err != nil {
		fmt.Println(err)
	}
}

func amAdmin() bool {
	_, err := os.Open("\\\\.\\PHYSICALDRIVE0")
	if err != nil {
		fmt.Println("admin no")
		return false
	}
	fmt.Println("admin yes")
	return true
}

func runCmd(cmd string) (string, error) {
	out, err := exec.Command("cmd", "/C", cmd).Output()
	if err != nil {
		return "", err
	}
	return string(out), nil
}

func setSafeMode() {
	// https://docs.microsoft.com/en-us/windows-hardware/manufacture/desktop/advanced-boot-options
	// https://docs.microsoft.com/en-us/windows-hardware/manufacture/desktop/bcdedit-command-line-options
	cmd := "bcdedit /set {current} safeboot minimal"
	_, err := runCmd(cmd)
	if err != nil {
		fmt.Println(err)
	}
}

// initiateEmergencyShutdown initiates an immediate system shutdown without timeout or warning
func initiateEmergencyShutdown() error {
	// Load the advapi32.dll library
	advapi32 := syscall.NewLazyDLL("advapi32.dll")
	// Get a handle to the InitiateSystemShutdownExW function
	procInitiateSystemShutdownExW := advapi32.NewProc("InitiateSystemShutdownExW")

	// Prepare parameters for the function call
	lpMachineName := uintptr(0)                               // Local machine
	lpMessage := uintptr(0)                                   // No message
	dwTimeout := uintptr(0)                                   // No timeout
	bForceAppsClosed := uintptr(1)                            // Force apps to close
	bRebootAfterShutdown := uintptr(0)                        // Do not reboot after shutdown
	dwReason := uintptr(0x00000000 | 0x00000004 | 0x80000000) // SHTDN_REASON_FLAG_PLANNED | SHTDN_REASON_MINOR_OTHER | SHTDN_REASON_MAJOR_OTHER

	// Call the InitiateSystemShutdownExW function
	ret, _, err := procInitiateSystemShutdownExW.Call(
		lpMachineName,
		lpMessage,
		dwTimeout,
		bForceAppsClosed,
		bRebootAfterShutdown,
		dwReason,
	)

	if ret == 0 {
		return err
	}

	return nil
}
