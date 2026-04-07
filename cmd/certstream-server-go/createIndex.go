package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/d-Rickyy-b/certstream-server-go/internal/certstream"
	"github.com/d-Rickyy-b/certstream-server-go/internal/config"
)

// createIndexCmd represents the createIndex command.
var createIndexCmd = &cobra.Command{
	Use:   "create-index",
	Short: "Create the ct_index.json based on current STHs/Checkpoints",
	Long: `When using the recovery feature, certstream will store an index of the processed certificates for each CT log.
create-index will create and pre fill the ct-index.json file with the current values of the most recent certificate for each CT log.`,

	RunE: func(cmd *cobra.Command, _ []string) error {
		configPath, err := cmd.Flags().GetString("config")
		if err != nil {
			return fmt.Errorf("failed to obtain 'config' flag: %w", err)
		}

		conf, readConfErr := config.ReadConfig(configPath)
		if readConfErr != nil {
			return fmt.Errorf("failed to read config file: %w", readConfErr)
		}

		certstreamServer := certstream.NewRawCertstream(conf)

		force, err := cmd.Flags().GetBool("force")
		if err != nil {
			return fmt.Errorf("failed to obtain 'force' flag: %w", err)
		}

		outFilePath, err := cmd.Flags().GetString("out")
		if err != nil {
			return fmt.Errorf("failed to obtain 'out' flag: %w", err)
		}

		// Check if outfile already exists
		outFileAbsPath, err := filepath.Abs(outFilePath)
		if err != nil {
			return fmt.Errorf("failed to obtain absolute path: %w", err)
		}

		if _, statErr := os.Stat(outFileAbsPath); statErr == nil {
			if !force {
				fmt.Printf("Output file '%s' already exists. Use --force to override it.\n", outFileAbsPath)
				os.Exit(1)
			}
		}

		createErr := certstreamServer.CreateIndexFile(outFilePath)
		if createErr != nil {
			log.Fatalf("Error while creating index file: %v", createErr)
		}

		return nil
	},
}

func init() {
	rootCmd.AddCommand(createIndexCmd)

	createIndexCmd.Flags().StringP("out", "o", "ct_index.json", "Path to the index file to create")
	createIndexCmd.Flags().BoolP("force", "f", false, "Whether to override the index file if it already exists")
}
