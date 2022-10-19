package main

import (
	"context"
	"fmt"
	"github.com/aidansteele/vpcshark/cleanup"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

func cleanupAll(ctx context.Context, profile, region string) error {
	cfg, err := config.LoadDefaultConfig(ctx, config.WithSharedConfigProfile(profile), config.WithRegion(region))
	if err != nil {
		return fmt.Errorf(": %w", err)
	}

	api := ec2.NewFromConfig(cfg)

	err = cleanup.TerminateInstances(ctx, api, []types.Filter{
		{
			Name:   aws.String("tag-key"),
			Values: []string{"vpcshark"},
		},
		{
			Name:   aws.String("instance-state-name"),
			Values: []string{"running"},
		},
	})
	if err != nil {
		return fmt.Errorf(": %w", err)
	}

	filters := []types.Filter{
		{
			Name:   aws.String("description"),
			Values: []string{trafficMirrorDescription},
		},
	}

	_, err = cleanup.DeleteSessions(ctx, api, filters)
	if err != nil {
		return fmt.Errorf(": %w", err)
	}

	err = cleanup.DeleteTargets(ctx, api, filters)
	if err != nil {
		return fmt.Errorf(": %w", err)
	}

	err = cleanup.DeleteFilters(ctx, api, filters)
	if err != nil {
		return fmt.Errorf(": %w", err)
	}

	return nil
}
