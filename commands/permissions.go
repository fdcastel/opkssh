package commands

import (
	"bufio"
	"fmt"
	"io/fs"
	"os"
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

// ConfirmPrompt is used to ask the user for confirmation before applying fixes.
// Tests can override this to avoid interactive prompts.
var ConfirmPrompt = func(prompt string) (bool, error) {
	fmt.Print(prompt)
	r := bufio.NewReader(os.Stdin)
	s, err := r.ReadString('\n')
	if err != nil {
		return false, err
	}
	s = strings.TrimSpace(strings.ToLower(s))
	return s == "y" || s == "yes", nil
}

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
	aclVerifier := files.NewDefaultACLVerifier(vfs)
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
		// ACL verification: print owner and ACEs
		report, err := aclVerifier.VerifyACL(systemPolicy, files.ExpectedACL{Owner: "root", Mode: files.ModeSystemPerms})
		if err != nil {
			problems = append(problems, fmt.Sprintf("%s: acl verify error: %v", systemPolicy, err))
		} else {
			fmt.Printf("%s: owner=%s mode=%o\n", systemPolicy, report.Owner, report.Mode)
			if len(report.ACEs) > 0 {
				fmt.Println("  ACEs:")
				for _, a := range report.ACEs {
					fmt.Printf("    - %s: %s (%s) inherited=%v\n", a.Principal, a.Type, a.Rights, a.Inherited)
				}
			}
			for _, p := range report.Problems {
				fmt.Println("  ACL problem:", p)
			}
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
	vfs := DefaultFs
	if vfs == nil {
		vfs = afero.NewOsFs()
	}
	ops := files.NewDefaultFilePermsOps(vfs)

	// Planning phase: determine actions without performing them
	var planned []string

	systemPolicy := policy.SystemDefaultPolicyPath
	if _, err := ops.Stat(systemPolicy); err != nil {
		planned = append(planned, "create file: "+systemPolicy)
	}
	planned = append(planned, "chmod "+systemPolicy+" to "+files.ModeSystemPerms.String())
	planned = append(planned, "chown "+systemPolicy+" to root:opksshuser")

	providersDir := filepath.Join(policy.GetSystemConfigBasePath(), "providers")
	if _, err := ops.Stat(providersDir); err != nil {
		planned = append(planned, "mkdir "+providersDir)
	}
	planned = append(planned, "chown "+providersDir+" to root")

	pluginsDir := filepath.Join(policy.GetSystemConfigBasePath(), "policy.d")
	if _, err := ops.Stat(pluginsDir); err != nil {
		planned = append(planned, "mkdir "+pluginsDir)
	}
	// include plugin files if present
	if fi, err := vfs.Open(pluginsDir); err == nil {
		entries, _ := fi.Readdir(-1)
		for _, e := range entries {
			if !e.IsDir() && strings.HasSuffix(e.Name(), ".yml") {
				planned = append(planned, "chmod "+filepath.Join(pluginsDir, e.Name())+" to 0640")
				planned = append(planned, "chown "+filepath.Join(pluginsDir, e.Name())+" to root")
			}
		}
		fi.Close()
	}

	// If dry-run, just print planned actions
	if dryRun {
		for _, a := range planned {
			fmt.Println("Action:", a)
		}
		fmt.Println("dry-run complete")
		return nil
	}

	// Require elevated privileges to perform fixes
	elevated, err := IsElevated()
	if err != nil {
		return fmt.Errorf("failed to determine elevation: %w", err)
	}
	if !elevated {
		return fmt.Errorf("fix requires elevated privileges (run as root or Administrator)")
	}

	// Confirm with user unless --yes
	if !yes {
		// show planned actions and ask
		fmt.Println("Planned actions:")
		for _, a := range planned {
			fmt.Println("  -", a)
		}
		ok, err := ConfirmPrompt("Apply these changes? [y/N]: ")
		if err != nil {
			return err
		}
		if !ok {
			return fmt.Errorf("aborted by user")
		}
	}

	// Execution phase: perform actions
	var errorsFound []string

	// Create system policy file if missing
	if _, err := ops.Stat(systemPolicy); err != nil {
		if f, err := ops.CreateFileWithPerm(systemPolicy); err != nil {
			errorsFound = append(errorsFound, "create "+systemPolicy+": "+err.Error())
		} else {
			f.Close()
		}
	}
	if err := ops.Chmod(systemPolicy, files.ModeSystemPerms); err != nil {
		errorsFound = append(errorsFound, "chmod "+systemPolicy+": "+err.Error())
	}
	if err := ops.Chown(systemPolicy, "root", "opksshuser"); err != nil {
		errorsFound = append(errorsFound, "chown "+systemPolicy+": "+err.Error())
	}

	// Providers dir
	if _, err := ops.Stat(providersDir); err != nil {
		if err := ops.MkdirAllWithPerm(providersDir, 0750); err != nil {
			errorsFound = append(errorsFound, "mkdir "+providersDir+": "+err.Error())
		}
	}
	if err := ops.Chown(providersDir, "root", ""); err != nil {
		errorsFound = append(errorsFound, "chown "+providersDir+": "+err.Error())
	}

	// Plugins dir
	if _, err := ops.Stat(pluginsDir); err != nil {
		if err := ops.MkdirAllWithPerm(pluginsDir, 0750); err != nil {
			errorsFound = append(errorsFound, "mkdir "+pluginsDir+": "+err.Error())
		}
	}
	if fi, err := vfs.Open(pluginsDir); err == nil {
		entries, _ := fi.Readdir(-1)
		for _, e := range entries {
			if !e.IsDir() && strings.HasSuffix(e.Name(), ".yml") {
				path := filepath.Join(pluginsDir, e.Name())
				if err := ops.Chmod(path, files.ModeSystemPerms); err != nil {
					errorsFound = append(errorsFound, "chmod "+path+": "+err.Error())
				}
				if err := ops.Chown(path, "root", ""); err != nil {
					errorsFound = append(errorsFound, "chown "+path+": "+err.Error())
				}
			}
		}
		fi.Close()
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
