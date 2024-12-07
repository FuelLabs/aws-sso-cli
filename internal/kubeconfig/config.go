package kubeconfig

import (
	"fmt"
	"os"
	"strings"

	"github.com/synfinatic/aws-sso-cli/internal/logger"
	"github.com/synfinatic/aws-sso-cli/internal/sso"
	"github.com/synfinatic/aws-sso-cli/internal/utils"
	"github.com/synfinatic/flexlog"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/tools/clientcmd/api"
)

var stdout = os.Stdout
var log flexlog.FlexLogger

func init() {
	log = logger.GetLogger()
}

// load kube config file based on default CLI rules
func getKubeConfig() (api.Config, string, error) {
	loadingRules := clientcmd.NewDefaultClientConfigLoadingRules()
	configOverrides := &clientcmd.ConfigOverrides{}
	clientConfig := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(loadingRules, configOverrides)

	configFilename := clientConfig.ConfigAccess().GetExplicitFile()
	if configFilename == "" {
		configFilename = clientConfig.ConfigAccess().GetDefaultFilename()
	}

	rawConfig, err := clientConfig.RawConfig()
	return rawConfig, configFilename, err
}

// Create the exec config for cluster/user using sso-cli auth
func generateExecConfigFromAwsProfile(cluster EksClusterInfo) (api.ExecConfig, error) {
	return api.ExecConfig{
		APIVersion:         "client.authentication.k8s.io/v1beta1",
		InteractiveMode:    api.IfAvailableExecInteractiveMode,
		ProvideClusterInfo: false,
		Command:            "aws", // assume aws cli installed on path
		Args: []string{
			"--region",
			cluster.Region,
			"eks",
			"get-token",
			"--cluster-name",
			cluster.Name,
			"--output",
			"json",
		},
		Env: []api.ExecEnvVar{
			api.ExecEnvVar{
				Name:  "AWS_PROFILE",
				Value: cluster.Profile,
			},
		},
	}, nil
}

func UpdateKubeConfig(s *sso.Settings, eksClusters []EksClusterInfo, roleName string, cfile string, diff, force bool) error {
	diffBytes, newConfig, cfgFile, err := generateKubeConfigDiff(s, eksClusters, roleName)
	if err != nil {
		return err
	}

	if len(diffBytes) == 0 {
		// do nothing if there is no diff
		log.Info("no changes made config file", "file", cfgFile)
		return nil
	}

	if !force {
		approved, err := utils.Prompt(cfgFile, diffBytes)
		if err != nil {
			return nil
		}
		if !approved {
			return nil
		}
	}

	return os.WriteFile(cfgFile, newConfig, 0600)
}

// PrintKubeConfig just prints what our new AWS config file block would look like
func PrintKubeConfig(s *sso.Settings, eksClusters []EksClusterInfo, roleName string) error {
	_, newConfig, _, err := generateKubeConfigDiff(s, eksClusters, roleName)
	if err != nil {
		return err
	}

	fmt.Println(newConfig)

	return nil
}

func generateKubeConfigDiff(s *sso.Settings, eksClusters []EksClusterInfo, roleName string) (string, []byte, string, error) {
	config, cfgFile, err := getKubeConfig()
	if err != nil {
		return "", nil, "", err
	}

	oldConfig, err := clientcmd.Write(config)
	if err != nil {
		return "", nil, "", err
	}

	newConfig, err := generateNewKubeConfig(s, config, eksClusters, roleName)
	if err != nil {
		return "", nil, "", err
	}

	diffBytes := utils.DiffBytes(oldConfig, newConfig, cfgFile, fmt.Sprintf("%s.new", cfgFile))
	return diffBytes, newConfig, cfgFile, nil
}

func generateNewKubeConfig(s *sso.Settings, config api.Config, eksClusters []EksClusterInfo, roleName string) ([]byte, error) {
	//seenSsoClusters := []string{}

	for _, eksCluster := range eksClusters {
		// Setup name values
		effectiveClusterName := fmt.Sprintf("aws-sso-cli:%s", eksCluster.Arn)
		effectiveUserName := fmt.Sprintf("aws-sso-cli:%s:%s", roleName, eksCluster.Arn)
		effectiveContextName := fmt.Sprintf("%s-%s",
			strings.TrimPrefix(strings.ReplaceAll(eksCluster.Name, "fuel-", ""), "-"),
			roleName)

		//seenSsoClusters = append(seenSsoClusters, effectiveClusterName)

		// Setup cluster section
		if _, ok := config.Clusters[effectiveClusterName]; !ok {
			config.Clusters[effectiveClusterName] = &api.Cluster{}
		}
		config.Clusters[effectiveClusterName].CertificateAuthorityData = eksCluster.CertificateAuthority
		config.Clusters[effectiveClusterName].Server = eksCluster.Endpoint

		// Setup user section
		if _, ok := config.AuthInfos[effectiveUserName]; !ok {
			config.AuthInfos[effectiveUserName] = &api.AuthInfo{}
		}
		clusterAuthInfo, err := generateExecConfigFromAwsProfile(eksCluster)
		if err != nil {
			return nil, err
		}
		config.AuthInfos[effectiveUserName].Exec = &clusterAuthInfo

		// Setup contexts
		if _, ok := config.Contexts[effectiveContextName]; !ok {
			config.Contexts[effectiveContextName] = &api.Context{}
		}
		config.Contexts[effectiveContextName].Cluster = effectiveClusterName
		config.Contexts[effectiveContextName].AuthInfo = effectiveUserName
	}

	return clientcmd.Write(config)
}

// getProfileMap returns our validated sso.ProfileMap
func getProfileMap(s *sso.Settings) (*sso.ProfileMap, error) {
	profiles, err := s.GetAllProfiles()
	if err != nil {
		return profiles, err
	}

	if err := profiles.UniqueCheck(s); err != nil {
		return profiles, err
	}

	return profiles, nil
}
