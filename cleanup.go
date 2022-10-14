package main

import (
	"context"
	"fmt"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

func runCleanup(ctx context.Context, profile string) error {
	fmt.Println("Deleting resources created by vpcshark")

	cfg, err := config.LoadDefaultConfig(ctx, config.WithSharedConfigProfile(profile))
	if err != nil {
		return fmt.Errorf(": %w", err)
	}

	api := ec2.NewFromConfig(cfg)

	filters := []types.Filter{
		{
			Name:   aws.String("description"),
			Values: []string{trafficMirrorDescription},
		},
	}

	ip := ec2.NewDescribeInstancesPaginator(api, &ec2.DescribeInstancesInput{
		Filters: []types.Filter{
			{
				Name:   aws.String("tag-key"),
				Values: []string{"vpcshark"},
			},
			{
				Name:   aws.String("instance-state-name"),
				Values: []string{"running"},
			},
		},
	})
	for ip.HasMorePages() {
		page, err := ip.NextPage(ctx)
		if err != nil {
			return fmt.Errorf(": %w", err)
		}

		for _, reservation := range page.Reservations {
			for _, instance := range reservation.Instances {
				instanceId := instance.InstanceId
				fmt.Printf("Terminating %s\n", *instanceId)
				_, err = api.TerminateInstances(ctx, &ec2.TerminateInstancesInput{InstanceIds: []string{*instanceId}})
				if err != nil {
					return fmt.Errorf(": %w", err)
				}
			}
		}
	}

	sp := ec2.NewDescribeTrafficMirrorSessionsPaginator(api, &ec2.DescribeTrafficMirrorSessionsInput{Filters: filters})
	for sp.HasMorePages() {
		page, err := sp.NextPage(ctx)
		if err != nil {
			return fmt.Errorf(": %w", err)
		}

		for _, session := range page.TrafficMirrorSessions {
			sessionId := session.TrafficMirrorSessionId
			fmt.Printf("Deleting %s\n", *sessionId)
			_, err = api.DeleteTrafficMirrorSession(ctx, &ec2.DeleteTrafficMirrorSessionInput{TrafficMirrorSessionId: sessionId})
			if err != nil {
				return fmt.Errorf(": %w", err)
			}
		}
	}

	tp := ec2.NewDescribeTrafficMirrorTargetsPaginator(api, &ec2.DescribeTrafficMirrorTargetsInput{Filters: filters})
	for tp.HasMorePages() {
		page, err := tp.NextPage(ctx)
		if err != nil {
			return fmt.Errorf(": %w", err)
		}

		for _, target := range page.TrafficMirrorTargets {
			targetId := target.TrafficMirrorTargetId
			fmt.Printf("Deleting %s\n", *targetId)
			_, err = api.DeleteTrafficMirrorTarget(ctx, &ec2.DeleteTrafficMirrorTargetInput{TrafficMirrorTargetId: targetId})
			if err != nil {
				return fmt.Errorf(": %w", err)
			}
		}
	}

	fp := ec2.NewDescribeTrafficMirrorFiltersPaginator(api, &ec2.DescribeTrafficMirrorFiltersInput{Filters: filters})
	for fp.HasMorePages() {
		page, err := fp.NextPage(ctx)
		if err != nil {
			return fmt.Errorf(": %w", err)
		}

		for _, filter := range page.TrafficMirrorFilters {
			filterId := filter.TrafficMirrorFilterId
			fmt.Printf("Deleting %s\n", *filterId)
			_, err = api.DeleteTrafficMirrorFilter(ctx, &ec2.DeleteTrafficMirrorFilterInput{TrafficMirrorFilterId: filterId})
			if err != nil {
				return fmt.Errorf(": %w", err)
			}
		}
	}

	return nil
}
