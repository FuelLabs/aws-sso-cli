package kubeconfig

import (
	"context"
	"encoding/base64"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/eks"
	"github.com/aws/aws-sdk-go-v2/service/eks/types"
	"github.com/synfinatic/aws-sso-cli/internal/sso"
	"github.com/synfinatic/aws-sso-cli/internal/storage"
	"github.com/synfinatic/aws-sso-cli/internal/utils"
)

var EKS_REGIONS = []string{"us-east-1", "ca-central-1", "us-west-1"}

type EksClusterInfo struct {
	Name                    string
	Arn                     string
	CertificateAuthority    []byte
	CertificateAuthorityB64 string
	Endpoint                string
	Region                  string
	AccountId               int64
	Profile                 string
}

// GetAllClusters loops through all available profiles and tries to find EKS clusters
func GetAllClusters(s *sso.Settings, awsSSO *sso.AWSSSO, roleName string) ([]EksClusterInfo, error) {
	var results []EksClusterInfo
	profiles, err := getEksProfiles(s, roleName)
	if err != nil {
		return results, err
	}

	for _, profile := range profiles {
		clusters, err := getEksClustersForProfile(profile, awsSSO)
		if err != nil {
			return results, err
		}
		for _, cluster := range clusters {
			results = append(results, cluster)
		}
	}

	return results, err
}

func getEksClustersForProfile(p sso.ProfileConfig, awsSSO *sso.AWSSSO) ([]EksClusterInfo, error) {
	var results []EksClusterInfo
	accountId, role, err := utils.ParseRoleARN(p.Arn)
	if err != nil {
		return results, err
	}
	credentials, err := awsSSO.GetRoleCredentials(accountId, role)
	if err != nil {
		return results, err
	}

	for _, region := range EKS_REGIONS {
		clusters, err := getEksClustersInRegion(credentials, region)
		if err != nil {
			return results, err
		}
		for _, cluster := range clusters {
			certAuthorityData, err := base64.StdEncoding.DecodeString(*cluster.CertificateAuthority.Data)
			if err != nil {
				return results, err
			}
			results = append(results, EksClusterInfo{
				Name:                    *cluster.Name,
				Arn:                     *cluster.Arn,
				CertificateAuthorityB64: *cluster.CertificateAuthority.Data,
				CertificateAuthority:    certAuthorityData,
				Endpoint:                *cluster.Endpoint,
				Region:                  region,
				AccountId:               accountId,
				Profile:                 p.Profile,
			})
		}
	}

	return results, err
}

func getEksClustersInRegion(creds storage.RoleCredentials, region string) ([]*types.Cluster, error) {
	awsConfig, err := awsConfig(creds, region)
	if err != nil {
		return nil, err
	}
	eksClient := eks.NewFromConfig(awsConfig)
	var clusterIds []string

	// paginate through all potential clusters
	listClusterInput := &eks.ListClustersInput{
		MaxResults: aws.Int32(100),
	}
	paginator := eks.NewListClustersPaginator(eksClient, listClusterInput)
	for paginator.HasMorePages() {
		output, err := paginator.NextPage(context.TODO())
		if err != nil {
			return nil, err
		}
		for _, cluster := range output.Clusters {
			clusterIds = append(clusterIds, cluster)
		}
	}

	var clusterDetails []*types.Cluster
	// get details for each found cluster
	for _, cluster := range clusterIds {
		describeClusterInput := &eks.DescribeClusterInput{
			Name: aws.String(cluster),
		}
		result, err := eksClient.DescribeCluster(context.TODO(), describeClusterInput)
		if err != nil {
			return nil, err
		}
		clusterDetails = append(clusterDetails, result.Cluster)
	}

	return clusterDetails, nil
}

func getEksProfiles(s *sso.Settings, roleName string) ([]sso.ProfileConfig, error) {
	profiles, err := getProfileMap(s)
	if err != nil {
		return nil, err
	}

	var results []sso.ProfileConfig
	for _, ctxProfiles := range *profiles {
		for _, profile := range ctxProfiles {
			_, role, err := utils.ParseRoleARN(profile.Arn)
			if err != nil {
				return nil, err
			}
			if role == roleName {
				results = append(results, profile)
			}
		}
	}

	return results, nil
}

func awsConfig(creds storage.RoleCredentials, region string) (aws.Config, error) {
	cfgCreds := credentials.NewStaticCredentialsProvider(
		creds.AccessKeyId,
		creds.SecretAccessKey,
		creds.SessionToken,
	)

	cfg, err := config.LoadDefaultConfig(context.TODO(),
		config.WithRegion(region),
		config.WithCredentialsProvider(cfgCreds),
	)

	return cfg, err
}
