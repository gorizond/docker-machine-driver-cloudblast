package main

import (
	"github.com/docker/machine/libmachine/drivers/plugin"
	"github.com/gorizond/docker-machine-driver-cloudblast/cloudblast"
)

func main() {
	plugin.RegisterDriver(cloudblast.NewDriver("", ""))
}
