package commands

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	"github.com/youichi-uda/sbomhub-cli/internal/api"
	"github.com/youichi-uda/sbomhub-cli/internal/config"
)

var projectsCmd = &cobra.Command{
	Use:   "projects",
	Short: "プロジェクト管理",
}

var projectsListCmd = &cobra.Command{
	Use:   "list",
	Short: "プロジェクト一覧を表示",
	RunE:  runProjectsList,
}

func init() {
	rootCmd.AddCommand(projectsCmd)
	projectsCmd.AddCommand(projectsListCmd)
}

func runProjectsList(cmd *cobra.Command, args []string) error {
	// 設定の読み込み
	configDir := filepath.Join(os.Getenv("HOME"), ".sbomhub")
	if os.Getenv("USERPROFILE") != "" {
		configDir = filepath.Join(os.Getenv("USERPROFILE"), ".sbomhub")
	}

	cfg, err := config.Load(configDir)
	if err != nil {
		return fmt.Errorf("設定の読み込みに失敗しました: %w", err)
	}

	if apiKey != "" {
		cfg.APIKey = apiKey
	}
	if cfg.APIKey == "" {
		return fmt.Errorf("API Keyが設定されていません")
	}

	// API クライアントの作成
	client := api.NewClient(cfg.APIURL, cfg.APIKey)

	// プロジェクト一覧取得
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

	return nil
}
