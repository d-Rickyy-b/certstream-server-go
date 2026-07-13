package config

import (
	"log"
	"strings"
)

type LogConfig struct {
	Operator    string `mapstructure:"operator"`
	URL         string `mapstructure:"url"`
	Description string `mapstructure:"description"`
}

type General struct {
	// DisableDefaultLogs indicates whether the default logs used in Google Chrome and provided by Google should be disabled.
	DisableDefaultLogs bool `mapstructure:"disable_default_logs"`
	// AdditionalLogs contains additional logs provided by the user that can be used in addition to the default logs.
	AdditionalLogs      []LogConfig `mapstructure:"additional_logs"`
	AdditionalTiledLogs []LogConfig `mapstructure:"additional_tiled_logs"`
	ExcludedLogs        []LogConfig `mapstructure:"excluded_logs"`
	// BufferSizes contains the buffer sizes for the different components of the server. They usually don't need any adjustments.
	BufferSizes BufferSizes `mapstructure:"buffer_sizes"`
	// DropOldLogs indicates whether downloading CT-Logs should start at the latest index (true) or should from the beginning (false).
	DropOldLogs *bool `mapstructure:"drop_old_logs"`
	Recovery    struct {
		Enabled     bool   `mapstructure:"enabled"`
		CTIndexFile string `mapstructure:"ct_index_file"`
	} `mapstructure:"recovery"`
}

func (g *General) Valid() bool {
	var validLogs, validTiledLogs, validExcludedLogs []LogConfig

	if len(g.AdditionalLogs) > 0 {
		for _, ctLog := range g.AdditionalLogs {
			if !URLRegex.MatchString(ctLog.URL) {
				log.Println("Ignoring invalid additional log URL: ", ctLog.URL)
				continue
			}

			validLogs = append(validLogs, ctLog)
		}
	}

	if len(g.AdditionalTiledLogs) > 0 {
		for _, ctLog := range g.AdditionalTiledLogs {
			if !URLRegex.MatchString(ctLog.URL) {
				log.Println("Ignoring invalid additional log URL: ", ctLog.URL)
				continue
			}

			validTiledLogs = append(validTiledLogs, ctLog)
		}
	}

	if len(g.ExcludedLogs) > 0 {
		for _, excludedLog := range g.ExcludedLogs {
			excludedLog.Operator = strings.TrimSpace(excludedLog.Operator)
			excludedLog.URL = strings.TrimSpace(excludedLog.URL)

			if excludedLog.Operator == "" && excludedLog.URL == "" {
				log.Println("Ignoring empty excluded_logs entry. Set operator and/or url.")
				continue
			}

			if excludedLog.URL != "" && !URLRegex.MatchString(excludedLog.URL) {
				log.Println("Ignoring invalid excluded log URL: ", excludedLog.URL)
				continue
			}

			validExcludedLogs = append(validExcludedLogs, excludedLog)
		}
	}

	g.AdditionalLogs = validLogs
	g.AdditionalTiledLogs = validTiledLogs
	g.ExcludedLogs = validExcludedLogs

	if len(g.AdditionalLogs) == 0 && len(g.AdditionalTiledLogs) == 0 && g.DisableDefaultLogs {
		log.Fatalln("Default logs are disabled, but no additional logs are configured. Please add at least one log to the config or enable default logs.")
	}

	if g.BufferSizes.Websocket <= 0 {
		g.BufferSizes.Websocket = 300
	}

	if g.BufferSizes.CTLog <= 0 {
		g.BufferSizes.CTLog = 1000
	}

	// For backward compatibility, copy value from deprecated BroadcastManager field
	if g.BufferSizes.BroadcastManager != 0 {
		g.BufferSizes.Dispatcher = g.BufferSizes.BroadcastManager
	}

	if g.BufferSizes.Dispatcher <= 0 {
		g.BufferSizes.Dispatcher = 10000
	}

	// If the cleanup flag is not set, default to true
	if g.DropOldLogs == nil {
		log.Println("drop_old_logs is not set, defaulting to true")

		defaultCleanup := true
		g.DropOldLogs = &defaultCleanup
	}

	if g.Recovery.Enabled && g.Recovery.CTIndexFile == "" {
		log.Println("Recovery enabled but no index file specified. Defaulting to ./ct_index.json")

		g.Recovery.CTIndexFile = "./ct_index.json"
	}

	return true
}
