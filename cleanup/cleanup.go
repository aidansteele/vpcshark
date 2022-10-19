package cleanup

import (
	"context"
	"fmt"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

func TerminateInstances(ctx context.Context, api *ec2.Client, filters []types.Filter) error {
	ip := ec2.NewDescribeInstancesPaginator(api, &ec2.DescribeInstancesInput{Filters: filters})
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

	return nil
}

func DeleteSessions(ctx context.Context, api *ec2.Client, filters []types.Filter) ([]types.TrafficMirrorSession, error) {
	sessions := []types.TrafficMirrorSession{}

	sp := ec2.NewDescribeTrafficMirrorSessionsPaginator(api, &ec2.DescribeTrafficMirrorSessionsInput{Filters: filters})
	for sp.HasMorePages() {
		page, err := sp.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf(": %w", err)
		}

		for _, session := range page.TrafficMirrorSessions {
			session := session
			sessions = append(sessions, session)
			sessionId := session.TrafficMirrorSessionId
			fmt.Printf("Deleting %s\n", *sessionId)
			_, err = api.DeleteTrafficMirrorSession(ctx, &ec2.DeleteTrafficMirrorSessionInput{TrafficMirrorSessionId: sessionId})
			if err != nil {
				return nil, fmt.Errorf(": %w", err)
			}
		}
	}

	return sessions, nil
}

func DeleteFilters(ctx context.Context, api *ec2.Client, filters []types.Filter) error {
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

func DeleteTargets(ctx context.Context, api *ec2.Client, filters []types.Filter) error {
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

	return nil
}
