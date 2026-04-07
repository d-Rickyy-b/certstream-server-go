package main

import (
	"fmt"
	"log"
	"os"

	"github.com/spf13/cobra"

	"github.com/d-Rickyy-b/certstream-server-go/internal/config"
)

// validateCmd represents the validate command.
var validateCmd = &cobra.Command{
	Use:   "validate",
	Short: "Tests whether the config file is valid",
	Long: `Validates a configuration file, then exits.

This command deserializes the config and checks for errors.`,
	PreRunE: func(cmd *cobra.Command, _ []string) error {
		// Check if config file exists
		configPath, err := cmd.Flags().GetString("config")
		if err != nil {
			return fmt.Errorf("failed to obtain 'config' flag: %w", err)
		}

		// Check if path exists and is a file
		_, statErr := os.Stat(configPath)
		if os.IsNotExist(statErr) {
			return fmt.Errorf("config file '%s' does not exist: %w", configPath, statErr)
		}

		return nil
	},
	RunE: func(cmd *cobra.Command, _ []string) error {
		configPath, err := cmd.Flags().GetString("config")
		if err != nil {
			return fmt.Errorf("failed to obtain 'config' flag: %w", err)
		}

		readConfErr := config.ValidateConfig(configPath)
		if readConfErr != nil {
			log.Fatalln(readConfErr)
		}

		log.Println("Config file is valid!")

		return nil
	},
}

func init() {
	rootCmd.AddCommand(validateCmd)
}
