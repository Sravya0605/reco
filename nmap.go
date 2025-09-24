package main

import (
	"fmt"
	"os/exec"
)

func nmap() {
	cmd := exec.Command("nmap", "-sS", "127.0.0.1")
	fmt.Println(cmd)
	op, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Printf("%s", err)
		return
	}
	fmt.Printf("%s", string(op))
}
