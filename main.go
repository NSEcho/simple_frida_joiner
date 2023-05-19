package main

import (
	"bufio"
	"fmt"
	"os"
	"strconv"

	"github.com/frida/frida-go/frida"
)

func main() {
	if len(os.Args) != 4 {
		fmt.Fprintf(os.Stderr, "usage: %s portal_address target mode\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "usage: %s 172.22.4.112 yldyn (attach|spawn)\n", os.Args[0])
		os.Exit(1)
	}

	portalAddress := os.Args[1]
	target := os.Args[2]
	mode := os.Args[3]

	frida.PatchAndroidSELinux() // Comment this line out if you are not on Android

	var session *frida.Session

	mgr := frida.NewDeviceManager()
	mgr.EnumerateDevices()

	dev, _ := mgr.LocalDevice()

	fmt.Println("[*] Got local device:", dev.Name())

	if mode == "spawn" {
		pid, err := dev.Spawn(target, nil)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] Error spawning application: %d => %v\n", pid, err)
			os.Exit(1)
		}
		fmt.Printf("[*] Spawned %s with pid %d\n", target, pid)

		session, err = dev.Attach(pid, nil)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] Error attaching to the pid: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("[*] Attached to the %s(%d)\n", target, pid)
		dev.Resume(pid)
	} else {
		targetPid, err := strconv.Atoi(target)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] Error converting pid: %v\n", err)
			os.Exit(1)
		}

		opts := frida.NewSessionOptions(frida.RealmNative, 300)

		session, err = dev.Attach(targetPid, opts)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] Error attaching to the pid: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("[*] Attached to the pid: %d\n", targetPid)
	}

	defer session.Detach()

	session.On("detached", func(reason frida.SessionDetachReason) {
		fmt.Printf("[*] Session detached: %s\n", reason)
	})

	fmt.Printf("[*] Attached to the target \"%s\"\n", target)

	popts := frida.NewPortalOptions()

	if _, err := session.JoinPortal(portalAddress, popts); err != nil {
		fmt.Fprintf(os.Stderr, "[-] Error joining portal: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("[*] Successfully connected to the portal @%s\n", portalAddress)

	r := bufio.NewReader(os.Stdin)
	r.ReadLine()
}
