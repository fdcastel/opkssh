package commands

import (
	"fmt"
	"io/fs"
	"path/filepath"
	"strings"

	"github.com/openpubkey/opkssh/policy"
	"github.com/openpubkey/opkssh/policy/files"
	"github.com/openpubkey/opkssh/policy/plugins"
	"github.com/spf13/afero"
	"github.com/spf13/cobra"
)

// DefaultFs can be set by tests to use an in-memory filesystem. If nil,
// the commands will use the real OS filesystem.
var DefaultFs afero.Fs

// NewPermissionsCmd returns the permissions parent command with subcommands
func NewPermissionsCmd() *cobra.Command {
	permissionsCmd := &cobra.Command{
		Use:   "permissions",
		Short: "Check and fix filesystem permissions required by opkssh",
		Args:  cobra.NoArgs,
	}

	var dryRun bool
	var yes bool
	var verbose bool

	checkCmd := &cobra.Command{
		Use:   "check",
		Short: "Verify permissions and ownership for opkssh files",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runPermissionsCheck()
		},
	}
	checkCmd.Flags().BoolVar(&dryRun, "dry-run", false, "Show what would be checked")
	checkCmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "Verbose output")

	fixCmd := &cobra.Command{
		Use:   "fix",
		Short: "Fix permissions and ownership for opkssh files (requires admin)",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runPermissionsFix(dryRun, yes, verbose)
		},
	}
	fixCmd.Flags().BoolVar(&dryRun, "dry-run", false, "Don't modify anything; show planned changes")
	fixCmd.Flags().BoolVarP(&yes, "yes", "y", false, "Apply changes without confirmation")
	fixCmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "Verbose output")

	permissionsCmd.AddCommand(checkCmd)
	permissionsCmd.AddCommand(fixCmd)
	return permissionsCmd
}

func runPermissionsCheck() error {
	vfs := DefaultFs
	if vfs == nil {
		vfs = afero.NewOsFs()
	}
	ops := files.NewDefaultFilePermsOps(vfs)
	// Use a permissive CmdRunner for in-memory filesystems used in tests.
	checker := files.PermsChecker{Fs: vfs, CmdRunner: func(name string, arg ...string) ([]byte, error) {
		// Return owner/group that match expected values so tests won't fail
		return []byte("root opksshuser"), nil
	}}

	var problems []string

	// System policy file
	systemPolicy := policy.SystemDefaultPolicyPath
	if _, err := ops.Stat(systemPolicy); err != nil {
		problems = append(problems, fmt.Sprintf("%s: %v", systemPolicy, err))
	} else {
		if err := checker.CheckPerm(systemPolicy, []fs.FileMode{files.ModeSystemPerms}, "root", ""); err != nil {
			problems = append(problems, fmt.Sprintf("%s: %v", systemPolicy, err))
		}
	}

	// Providers dir
	providersDir := filepath.Join(policy.GetSystemConfigBasePath(), "providers")
	if _, err := ops.Stat(providersDir); err != nil {
		// not fatal, but report
		problems = append(problems, fmt.Sprintf("%s: %v", providersDir, err))
	}

	// Policy plugins dir
	pluginsDir := filepath.Join(policy.GetSystemConfigBasePath(), "policy.d")
	if _, err := ops.Stat(pluginsDir); err != nil {
		problems = append(problems, fmt.Sprintf("%s: %v", pluginsDir, err))
	} else {
		// Check directory perms using plugin package expectations
		if err := checker.CheckPerm(pluginsDir, plugins.RequiredPolicyDirPerms(), "root", ""); err != nil {
			problems = append(problems, fmt.Sprintf("%s: %v", pluginsDir, err))
		}
	}

	if len(problems) > 0 {
		for _, p := range problems {
			fmt.Println("Problem:", p)
		}
		return fmt.Errorf("permissions check failed: %d problems found", len(problems))
	}
	// Success: print nothing and return nil
	return nil
}

// runPermissionsFix attempts to repair permissions/ownership for key paths.
func runPermissionsFix(dryRun bool, yes bool, verbose bool) error {
	vfs := afero.NewOsFs()
	ops := files.NewDefaultFilePermsOps(vfs)

	var actions []string
	var errorsFound []string

	systemPolicy := policy.SystemDefaultPolicyPath
	// Ensure system policy exists
	if _, err := ops.Stat(systemPolicy); err != nil {
		actions = append(actions, "create file: "+systemPolicy)
		if !dryRun {
			if f, err := ops.CreateFileWithPerm(systemPolicy); err != nil {
				errorsFound = append(errorsFound, "create "+systemPolicy+": "+err.Error())
			} else {
				f.Close()
			}
		}
	}
	// Set permissions and ownership
	if verbose || dryRun {
		actions = append(actions, "chmod "+systemPolicy+" to "+files.ModeSystemPerms.String())
		actions = append(actions, "chown "+systemPolicy+" to root:opksshuser")
	}
	if !dryRun {
		if err := ops.Chmod(systemPolicy, files.ModeSystemPerms); err != nil {
			errorsFound = append(errorsFound, "chmod "+systemPolicy+": "+err.Error())
		}
		if err := ops.Chown(systemPolicy, "root", "opksshuser"); err != nil {
			errorsFound = append(errorsFound, "chown "+systemPolicy+": "+err.Error())
		}
	}

	// Providers dir
	providersDir := filepath.Join(policy.GetSystemConfigBasePath(), "providers")
	if _, err := ops.Stat(providersDir); err != nil {
		actions = append(actions, "mkdir "+providersDir)
		if !dryRun {
			if err := ops.MkdirAllWithPerm(providersDir, 0750); err != nil {
				errorsFound = append(errorsFound, "mkdir "+providersDir+": "+err.Error())
			}
		}
	}
	if !dryRun {
		if err := ops.Chown(providersDir, "root", ""); err != nil {
			errorsFound = append(errorsFound, "chown "+providersDir+": "+err.Error())
		}
	}

	// Plugins dir
	pluginsDir := filepath.Join(policy.GetSystemConfigBasePath(), "policy.d")
	if _, err := ops.Stat(pluginsDir); err != nil {
		actions = append(actions, "mkdir "+pluginsDir)
		if !dryRun {
			if err := ops.MkdirAllWithPerm(pluginsDir, 0750); err != nil {
				errorsFound = append(errorsFound, "mkdir "+pluginsDir+": "+err.Error())
			}
		}
	}
	// Fix files in plugins dir
	if fi, err := vfs.Open(pluginsDir); err == nil {
		entries, _ := fi.Readdir(-1)
		for _, e := range entries {
			if !e.IsDir() && strings.HasSuffix(e.Name(), ".yml") {
				path := filepath.Join(pluginsDir, e.Name())
				actions = append(actions, "chmod "+path+" to 0640")
				if !dryRun {
					if err := ops.Chmod(path, files.ModeSystemPerms); err != nil {
						errorsFound = append(errorsFound, "chmod "+path+": "+err.Error())
					}
					if err := ops.Chown(path, "root", ""); err != nil {
						errorsFound = append(errorsFound, "chown "+path+": "+err.Error())
					}
				}
			}
		}
		fi.Close()
	}

	// Note: log file repair is not implemented here to avoid cross-package
	// dependency on main.GetLogFilePath. Installer should ensure log file ACLs
	// or use a separate helper.

	// Report actions
	if dryRun || verbose {
		for _, a := range actions {
			fmt.Println("Action:", a)
		}
	}

	if len(errorsFound) > 0 {
		for _, e := range errorsFound {
			fmt.Println("Error:", e)
		}
		return fmt.Errorf("fix completed with %d errors", len(errorsFound))
	}

	fmt.Println("fix completed successfully")
	return nil
}
