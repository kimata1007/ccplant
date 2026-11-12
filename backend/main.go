package main

import (
	"log"
	"os"
	_ "time/tzdata" // embed IANA timezone database so time.LoadLocation works in containers without tzdata installed

	"github.com/spf13/cobra"
	"github.com/takutakahashi/agentapi-proxy/cmd"
	"github.com/takutakahashi/agentapi-proxy/internal/buildinfo"
)

var rootCmd = &cobra.Command{
	Use:               "ccplant",
	Short:             "AgentAPI Proxy Server",
	Long:              "A reverse proxy server for AgentAPI that routes requests based on configuration",
	Version:           buildinfo.Version,
	PersistentPreRunE: cmd.RunAutomaticUpdate,
}

func init() {
	rootCmd.AddCommand(cmd.ExecutorServerCmd)
	rootCmd.AddCommand(cmd.ExecutorClientCmd)
	rootCmd.AddCommand(cmd.ServerCmd)
	rootCmd.AddCommand(cmd.WorkerCmd)
	rootCmd.AddCommand(cmd.SessionManagerCmd)
	rootCmd.AddCommand(cmd.HelpersCmd)
	rootCmd.AddCommand(cmd.ClientCmd)
	rootCmd.AddCommand(cmd.TaskCommands()...)
	rootCmd.AddCommand(cmd.AgentProvisionerCmd)
	rootCmd.AddCommand(cmd.NativeSessionManagerCmd)
	rootCmd.AddCommand(cmd.NativeCmd)
	rootCmd.AddCommand(cmd.OneshotCmd)
	rootCmd.AddCommand(cmd.AcpServerCmd)
	rootCmd.AddCommand(cmd.DoctorCmd)
	rootCmd.AddCommand(cmd.ControlPlaneCmd)
	rootCmd.AddCommand(cmd.HelmCmd)
	rootCmd.AddCommand(cmd.KVStoreCmd)
	rootCmd.AddCommand(cmd.CodexAuthWorkerCmd)
	rootCmd.AddCommand(cmd.AdminCmd)
	rootCmd.AddCommand(cmd.VersionCmd)
	rootCmd.AddCommand(cmd.UpdateCmd)
}

func main() {
	if args, ok := cmd.ExecutorClientArgsForBasename(os.Args); ok {
		os.Args = append([]string{"ccplant", "executor-client"}, args...)
		// A non-zero remote shell status is an expected process result, not a
		// Cobra command failure. Keep shell stderr byte-for-byte compatible.
		rootCmd.SilenceErrors = true
		rootCmd.SilenceUsage = true
	}
	if err := rootCmd.Execute(); err != nil {
		if code, ok := cmd.ExecutorExitCode(err); ok {
			os.Exit(code)
		}
		log.Printf("Fatal error executing command: %v", err)
		os.Exit(1)
	}
}
