package commands

import (
	"fmt"
	"time"

	"github.com/spf13/cobra"
	"github.com/youichi-uda/sbomhub-cli/internal/api"
)

var (
	projectDescription string
)

var projectsCmd = &cobra.Command{
	Use:   "projects",
	Short: "プロジェクト管理",
	Long: `プロジェクトの一覧表示、詳細表示、作成を行います。

使用例:
  sbomhub projects list              # プロジェクト一覧を表示
  sbomhub projects show <id>         # プロジェクト詳細を表示
  sbomhub projects create <name>     # プロジェクトを作成`,
}

var projectsListCmd = &cobra.Command{
	Use:   "list",
	Short: "プロジェクト一覧を表示",
	RunE:  runProjectsList,
}

var projectsShowCmd = &cobra.Command{
	Use:   "show <id>",
	Short: "プロジェクト詳細を表示",
	Args:  cobra.ExactArgs(1),
	RunE:  runProjectsShow,
}

var projectsCreateCmd = &cobra.Command{
	Use:   "create <name>",
	Short: "プロジェクトを作成",
	Args:  cobra.ExactArgs(1),
	RunE:  runProjectsCreate,
}

func init() {
	rootCmd.AddCommand(projectsCmd)
	projectsCmd.AddCommand(projectsListCmd)
	projectsCmd.AddCommand(projectsShowCmd)
	projectsCmd.AddCommand(projectsCreateCmd)

	projectsCreateCmd.Flags().StringVarP(&projectDescription, "description", "d", "", "プロジェクトの説明")
}

// loadConfigAndClient resolves credentials with the documented precedence
// (CLI flag > env var > config file > default) and returns an api.Client.
//
// Codex R9 fix: previously this used config.Load + a manual --api-key
// override, which silently ignored SBOMHUB_API_URL and the --api-url flag.
// That broke self-host flows like
//
//	SBOMHUB_API_URL=http://localhost:8080 SBOMHUB_API_KEY=sbh_xxx \
//	    sbomhub projects list
//
// where the CLI would still talk to https://api.sbomhub.app. Routing
// through resolveCredentials (introduced in R2-2e for scan) gives every
// API-backed command the same precedence semantics.
func loadConfigAndClient() (*api.Client, error) {
	cfg, err := resolveCredentials(getConfigDir())
	if err != nil {
		return nil, fmt.Errorf("設定の読み込みに失敗しました: %w", err)
	}
	if cfg.APIKey == "" {
		return nil, fmt.Errorf("API Keyが設定されていません。 'sbomhub login' で対話設定するか、 --api-key フラグ・ 環境変数 SBOMHUB_API_KEY を指定してください")
	}
	if cfg.APIURL == "" {
		return nil, fmt.Errorf("API URLが設定されていません。 'sbomhub login' で設定するか、 --api-url フラグ・ 環境変数 SBOMHUB_API_URL を指定してください")
	}

	return api.NewClient(cfg.APIURL, cfg.APIKey), nil
}

func runProjectsList(cmd *cobra.Command, args []string) error {
	client, err := loadConfigAndClient()
	if err != nil {
		return err
	}

	projects, err := client.ListProjects()
	if err != nil {
		return fmt.Errorf("プロジェクト一覧の取得に失敗しました: %w", err)
	}

	out := GetOutputConfig()

	// JSON output
	if out.IsJSON() {
		return out.PrintJSON(map[string]interface{}{
			"projects": projects,
			"total":    len(projects),
		})
	}

	// Human-readable output
	if len(projects) == 0 {
		printInfo("プロジェクトがありません")
		return nil
	}

	out.Println("プロジェクト一覧")
	out.Println("----------------")
	for _, p := range projects {
		out.Print("  %s  %s\n", p.ID, p.Name)
		if p.Description != "" {
			out.Print("      %s\n", p.Description)
		}
	}
	out.Print("\n合計: %d プロジェクト\n", len(projects))

	return nil
}

func runProjectsShow(cmd *cobra.Command, args []string) error {
	projectID := args[0]

	client, err := loadConfigAndClient()
	if err != nil {
		return err
	}

	project, err := client.GetProject(projectID)
	if err != nil {
		return fmt.Errorf("プロジェクトの取得に失敗しました: %w", err)
	}

	fmt.Println("プロジェクト詳細")
	fmt.Println("----------------")
	fmt.Printf("ID:          %s\n", project.ID)
	fmt.Printf("名前:        %s\n", project.Name)
	fmt.Printf("説明:        %s\n", project.Description)
	if project.CreatedAt != "" {
		if t, err := time.Parse(time.RFC3339, project.CreatedAt); err == nil {
			fmt.Printf("作成日時:    %s\n", t.Format("2006-01-02 15:04:05"))
		}
	}
	if project.UpdatedAt != "" {
		if t, err := time.Parse(time.RFC3339, project.UpdatedAt); err == nil {
			fmt.Printf("更新日時:    %s\n", t.Format("2006-01-02 15:04:05"))
		}
	}

	return nil
}

func runProjectsCreate(cmd *cobra.Command, args []string) error {
	projectName := args[0]

	client, err := loadConfigAndClient()
	if err != nil {
		return err
	}

	project, created, err := client.CreateProject(projectName, projectDescription)
	if err != nil {
		return fmt.Errorf("プロジェクトの作成に失敗しました: %w", err)
	}

	if created {
		printSuccess("プロジェクトを作成しました")
	} else {
		printInfo("既存のプロジェクトが見つかりました")
	}

	fmt.Printf("  ID:   %s\n", project.ID)
	fmt.Printf("  名前: %s\n", project.Name)
	if project.Description != "" {
		fmt.Printf("  説明: %s\n", project.Description)
	}

	return nil
}
