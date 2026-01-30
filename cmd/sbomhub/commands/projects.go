package commands

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"
	"github.com/youichi-uda/sbomhub-cli/internal/api"
	"github.com/youichi-uda/sbomhub-cli/internal/config"
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

func loadConfigAndClient() (*api.Client, error) {
	configDir := filepath.Join(os.Getenv("HOME"), ".sbomhub")
	if os.Getenv("USERPROFILE") != "" {
		configDir = filepath.Join(os.Getenv("USERPROFILE"), ".sbomhub")
	}

	cfg, err := config.Load(configDir)
	if err != nil {
		return nil, fmt.Errorf("設定の読み込みに失敗しました: %w", err)
	}

	if apiKey != "" {
		cfg.APIKey = apiKey
	}
	if cfg.APIKey == "" {
		return nil, fmt.Errorf("API Keyが設定されていません。'sbomhub login' でログインしてください")
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

	if len(projects) == 0 {
		printInfo("プロジェクトがありません")
		return nil
	}

	fmt.Println("プロジェクト一覧")
	fmt.Println("----------------")
	for _, p := range projects {
		fmt.Printf("  %s  %s\n", p.ID, p.Name)
		if p.Description != "" {
			fmt.Printf("      %s\n", p.Description)
		}
	}
	fmt.Printf("\n合計: %d プロジェクト\n", len(projects))

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
