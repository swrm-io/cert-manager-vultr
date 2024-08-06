package main

import (
	"fmt"
	"os"

	"github.com/cert-manager/cert-manager/pkg/acme/webhook/cmd"
	"go.uber.org/zap"
)

var GroupName = os.Getenv("GROUP_NAME")

func main() {
	logger, _ := zap.NewProduction()
	defer func() {
		err := logger.Sync()
		if err != nil {
			logger.Error(err.Error())
		}
	}()

	if GroupName == "" {
		logger.Fatal("GROUP_NAME must be specified")
	}

	logger.Info("Starting Cert-Manager Vultr Webhook")

	fmt.Println(logger)
	cmd.RunWebhookServer(
		GroupName,
		&VultrSolver{logger: logger},
	)
}
