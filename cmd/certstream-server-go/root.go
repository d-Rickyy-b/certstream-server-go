package main

import (
	"fmt"
	"log"
	"os"

	"github.com/spf13/cobra"

	"github.com/d-Rickyy-b/certstream-server-go/internal/certstream"
	"github.com/d-Rickyy-b/certstream-server-go/internal/config"
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "certstream-server-go",
	Short: "A drop-in replacement for the certstream server by Calidog",
	Long: `This tool aggregates, parses, and streams certificate data from multiple 
certificate transparency logs via websocket connections to connected clients.`,

	RunE: func(cmd *cobra.Command, args []string) error {
		// Handle --version flag
		versionBool, err := cmd.Flags().GetBool("version")
		if err != nil {
			return err
		}
		if versionBool {
			fmt.Printf("certstream-server-go v%s\n", config.Version)
			return nil
		}

		// Handle --config flag
		configPath, err := cmd.Flags().GetString("config")
		if err != nil {
			return err
		}
		// Check if path exists and is a file
		_, statErr := os.Stat(configPath)
		if os.IsNotExist(statErr) {
			return fmt.Errorf("config file '%s' does not exist", configPath)
		}

		cs, err := certstream.NewCertstreamFromConfigFile(configPath)
		if err != nil {
			log.Fatalf("Error while creating certstream server: %v", err)
		}

		cs.Start()

		return nil
	},
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	rootCmd.PersistentFlags().StringP("config", "c", "config.yml", "Path to the config file")
	rootCmd.Flags().BoolP("version", "v", false, "Print the version and exit")
}
