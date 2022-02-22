package main

import (
	"fmt"
	"github.com/hamster-shared/hamster-gateway/module/p2p"
	"os"
)

func main() {

	identity, err := p2p.CreateIdentity()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	host, _, err := p2p.MakeRoutedHost(4001, identity.PrivKey, []string{})
	if err != nil {
		return
	}
	fmt.Println(host.ID())

	select {}
}
