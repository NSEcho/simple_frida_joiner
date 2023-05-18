package main

import (
	"bufio"
	"fmt"
	"github.com/frida/frida-go/frida"
	"os"
	"strconv"
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

	var session *frida.Session
	var err error

	if mode == "spawn" {
		dev := frida.LocalDevice()
		if dev == nil {
			fmt.Fprintf(os.Stderr, "[-] Error getting local device: %v\n", err)
			os.Exit(1)
		}
		pid, err := dev.Spawn(target, nil)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] Error spawning application: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("[*] Spawned %s with pid %d\n", target, pid)

		session, err = dev.Attach(pid, nil)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] Error attaching to the pid: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("[*] Attached to the %s(%d)\n", target, pid)
	} else {
		targetPid, err := strconv.Atoi(target)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] Error converting pid: %v\n", err)
			os.Exit(1)
		}
		session, err = frida.Attach(targetPid)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] Error attaching to the pid: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("[*] Attached to the pid: %d\n", targetPid)
	}

	defer session.Detach()

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
