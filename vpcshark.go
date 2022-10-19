package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	_ "embed"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/aidansteele/vpcshark/awsdial"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	ssmtypes "github.com/aws/aws-sdk-go-v2/service/ssm/types"
	"github.com/aws/aws-sdk-go/aws/endpoints"
	"github.com/bramvdbogaerde/go-scp"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh"
	"golang.org/x/sync/errgroup"
	"gopkg.in/ini.v1"
	"io"
	mrand "math/rand"
	"net"
	"os"
	"sort"
	"strings"
	"syscall"
	"time"
)

const trafficMirrorVNI = 0xBEEF
const trafficMirrorDescription = "vpcshark"

func main() {
	var err error
	os.Stderr, err = os.OpenFile("/tmp/vpcshark.log", os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0777)
	if err != nil {
		panic(fmt.Sprintf("%+v", err))
	}

	mrand.Seed(time.Now().UnixNano())
	fmt.Fprintf(os.Stderr, "%x\n", mrand.Int63())

	j, _ := json.MarshalIndent(os.Args, "", "  ")
	fmt.Fprintln(os.Stderr, string(j))

	rootCmd := &cobra.Command{RunE: runVpcshark}
	pf := rootCmd.PersistentFlags()
	pf.Float32("extcap-version", 0, "")
	pf.Bool("cleanup", false, "")
	pf.Bool("extcap-config", false, "")
	pf.Bool("extcap-interfaces", false, "")
	pf.Bool("extcap-dlts", false, "")
	pf.Bool("capture", false, "")
	pf.String("extcap-reload-option", "", "")
	pf.String("extcap-interface", "", "")
	pf.String("fifo", "", "")
	pf.String("extcap-control-out", "", "")
	pf.String("extcap-control-in", "", "")
	pf.String("profile", "", "")
	pf.String("region", "", "")
	pf.String("vpc", "", "")
	pf.String("eni", "", "")
	pf.String("launch-template-id", "", "")
	pf.String("connectivity", "", "")

	ctx := context.Background()
	err = rootCmd.ExecuteContext(ctx)
	if err != nil {
		panic(fmt.Sprintf("%+v", err))
	}

	fmt.Fprintln(os.Stderr, "Exited cleanly")
}

func runVpcshark(cmd *cobra.Command, args []string) error {
	ctx := cmd.Context()

	pf := cmd.PersistentFlags()
	cleanup, _ := pf.GetBool("cleanup")
	extcapConfig, _ := pf.GetBool("extcap-config")
	extcapInterfaces, _ := pf.GetBool("extcap-interfaces")
	extcapDLTs, _ := pf.GetBool("extcap-dlts")
	capture, _ := pf.GetBool("capture")
	extcapReloadOption, _ := pf.GetString("extcap-reload-option")
	//extcapInterface, _ := pf.GetString("extcap-interface")
	fifo, _ := pf.GetString("fifo")
	extcapControlOut, _ := pf.GetString("extcap-control-out")
	extcapControlIn, _ := pf.GetString("extcap-control-in")
	eni, _ := pf.GetString("eni")
	profile, _ := pf.GetString("profile")
	region, _ := pf.GetString("region")
	vpc, _ := pf.GetString("vpc")
	launchTemplateId, _ := pf.GetString("launch-template-id")
	connectivity, _ := pf.GetString("connectivity")

	if cleanup {
		return cleanupAll(ctx, profile, region)
	} else if extcapInterfaces {
		return runExtcapInterfaces(ctx)
	} else if extcapConfig {
		return runExtcapConfig(ctx, profile, region, vpc, extcapReloadOption)
	} else if extcapDLTs {
		return runExtcapDLTs(ctx)
	} else if capture {
		return runCapture(ctx, profile, region, launchTemplateId, connectivity, eni, extcapControlIn, extcapControlOut, fifo)
	} else {
		return fmt.Errorf("unexpected command")
	}
}

type vpcshark struct {
	gui    *Wireshark
	ec2    *ec2.Client
	ssm    *ssm.Client
	region string
}

func runExtcapInterfaces(ctx context.Context) error {
	fmt.Println(`extcap {version=0.0.1}{help=https://github.com/aidansteele/vpcshark}
interface {value=awsvpc}{display=AWS VPC Traffic Mirroring}
control {number=0}{type=button}{role=logger}{display=Log}{tooltip=Show capture log}`)
	return nil
}

func getTag(tags []types.Tag, name string) string {
	for _, tag := range tags {
		if aws.ToString(tag.Key) == name {
			return aws.ToString(tag.Value)
		}
	}

	return ""
}

func runExtcapConfig(ctx context.Context, profile, region, vpc, reloadOption string) error {
	opts := []func(*config.LoadOptions) error{
		config.WithSharedConfigProfile(profile),
		config.WithRegion(region),
	}

	if reloadOption == "vpc" {
		cfg, err := config.LoadDefaultConfig(ctx, opts...)
		if err != nil {
			return fmt.Errorf(": %w", err)
		}

		api := ec2.NewFromConfig(cfg)
		p := ec2.NewDescribeVpcsPaginator(api, &ec2.DescribeVpcsInput{})

		lines := []string{}

		for p.HasMorePages() {
			page, err := p.NextPage(ctx)
			if err != nil {
				return fmt.Errorf(": %w", err)
			}

			for _, vpc := range page.Vpcs {
				vpcId := *vpc.VpcId
				display := vpcId
				if name := getTag(vpc.Tags, "Name"); name != "" {
					display = fmt.Sprintf("%s (%s)", vpcId, name)
				}

				lines = append(lines, fmt.Sprintf("value {arg=3}{value=%s}{display=%s}\n", vpcId, display))
			}
		}

		sort.Strings(lines)
		fmt.Println(strings.Join(lines, ""))
		return nil
	}

	if reloadOption == "launch-template-id" {
		cfg, err := config.LoadDefaultConfig(ctx, opts...)
		if err != nil {
			return fmt.Errorf(": %w", err)
		}

		api := ec2.NewFromConfig(cfg)
		p := ec2.NewDescribeLaunchTemplatesPaginator(api, &ec2.DescribeLaunchTemplatesInput{})

		lines := []string{}

		for p.HasMorePages() {
			page, err := p.NextPage(ctx)
			if err != nil {
				return fmt.Errorf(": %w", err)
			}

			for _, template := range page.LaunchTemplates {
				id := *template.LaunchTemplateId
				name := *template.LaunchTemplateName
				lines = append(lines, fmt.Sprintf("value {arg=5}{value=%s}{display=%s (%s)}\n", id, id, name))
			}
		}

		sort.Strings(lines)
		fmt.Println(strings.Join(lines, ""))
		return nil
	}

	if reloadOption == "eni" {
		cfg, err := config.LoadDefaultConfig(ctx, opts...)
		if err != nil {
			return fmt.Errorf(": %w", err)
		}

		api := ec2.NewFromConfig(cfg)
		p := ec2.NewDescribeInstancesPaginator(api, &ec2.DescribeInstancesInput{
			Filters: []types.Filter{
				{
					Name:   aws.String("vpc-id"),
					Values: []string{vpc},
				},
			},
		})

		lines := []string{}

		for p.HasMorePages() {
			page, err := p.NextPage(ctx)
			if err != nil {
				return fmt.Errorf(": %w", err)
			}

			for _, reservation := range page.Reservations {
				for _, instance := range reservation.Instances {
					for _, networkInterface := range instance.NetworkInterfaces {
						eniId := *networkInterface.NetworkInterfaceId
						display := fmt.Sprintf("%s: %s", eniId, *instance.InstanceId)
						if name := getTag(instance.Tags, "Name"); name != "" {
							display = fmt.Sprintf("%s (%s)", display, name)
						}

						lines = append(lines, fmt.Sprintf("value {arg=4}{value=%s}{display=%s}\n", eniId, display))
					}
				}
			}
		}

		sort.Strings(lines)
		fmt.Println(strings.Join(lines, ""))
		return nil
	}

	fmt.Printf("arg {number=1}{call=--profile}{group=AWS}{display=AWS Profile}{type=selector}{required=true}\n")
	fmt.Printf("arg {number=2}{call=--region}{group=AWS}{display=AWS Region}{type=selector}{required=true}\n")
	fmt.Printf("arg {number=3}{call=--vpc}{group=Traffic source}{display=VPC}{type=selector}{required=true}{reload=true}{placeholder=Load VPCs...}\n")
	fmt.Printf("arg {number=4}{call=--eni}{group=Traffic source}{display=Capture ENI}{tooltip=Select ENI(s) to monitor}{type=selector}{reload=true}{placeholder=Load ENIs...}{required=true}\n")
	fmt.Printf("arg {number=5}{call=--launch-template-id}{group=Mirror target}{display=Launch template}{tooltip=Select launch template for mirror target}{type=selector}{reload=true}{placeholder=Load templates...}{required=true}\n")
	fmt.Printf("arg {number=6}{call=--connectivity}{group=Mirror target}{display=Connectivity}{tooltip=Select connectivity to mirror target}{type=selector}{required=true}\n")
	fmt.Printf("value {arg=6}{value=public-ssh}{display=Via public IP address over SSH}\n")
	fmt.Printf("value {arg=6}{value=ssm-tunnel}{display=Via port-forwarding over AWS Session Manager}\n")

	regionMap, _ := endpoints.RegionsForService(endpoints.DefaultPartitions(), endpoints.AwsPartitionID, "ec2")
	regions := []string{}
	for r := range regionMap {
		regions = append(regions, r)
	}

	sort.Strings(regions)
	for _, region := range regions {
		fmt.Printf("value {arg=2}{value=%s}{display=%s}\n", region, region)
	}

	profiles, err := getProfiles(ctx)
	if err != nil {
		return fmt.Errorf("loading aws profile names: %w", err)
	}

	for _, profileName := range profiles {
		fmt.Printf("value {arg=1}{value=%s}{display=%s}\n", profileName, profileName)
	}

	return nil
}

func getProfiles(ctx context.Context) ([]string, error) {
	cfg, err := ini.Load(config.DefaultSharedConfigFilename())
	if err != nil {
		return nil, fmt.Errorf(": %w", err)
	}

	profiles := []string{}

	sections := cfg.Sections()
	for _, section := range sections {
		name := section.Name()
		if strings.HasPrefix(name, "profile ") {
			profileName := strings.TrimPrefix(name, "profile ")
			profiles = append(profiles, profileName)
		}
	}

	sort.Strings(profiles)
	return profiles, nil
}

func runExtcapDLTs(ctx context.Context) error {
	fmt.Println(`dlt {number=1}{name=LINKTYPE_ETHERNET}{display=Ethernet}`)
	return nil
}

func runCapture(ctx context.Context, profile, region, launchTemplateId, connectivity, eni, extcapControlIn, extcapControlOut, fifo string) error {
	fmt.Fprintln(os.Stderr, "starting capture")

	controlOut, err := os.OpenFile(extcapControlOut, os.O_WRONLY, os.ModeNamedPipe)
	if err != nil {
		return fmt.Errorf(": %w", err)
	}

	controlIn, err := os.OpenFile(extcapControlIn, os.O_RDONLY, os.ModeNamedPipe)
	if err != nil {
		return fmt.Errorf(": %w", err)
	}

	go handleControlIn(controlIn)

	pcap, err := os.OpenFile(fifo, os.O_WRONLY, os.ModeNamedPipe)
	if err != nil {
		return fmt.Errorf(": %w", err)
	}

	w := &Wireshark{
		controlIn:  controlIn,
		controlOut: controlOut,
		pcap:       pcap,
	}
	w.log = &wiresharkLog{w: w}

	fmt.Fprintf(os.Stderr, "loading aws config\n")
	cfg, err := config.LoadDefaultConfig(
		ctx,
		config.WithSharedConfigProfile(profile),
		config.WithRegion(region),
		config.WithClientLogMode(aws.LogRequestWithBody|aws.LogResponseWithBody),
		//config.WithClientLogMode(aws.LogRequest|aws.LogResponse),
	)
	if err != nil {
		return fmt.Errorf(": %w", err)
	}

	v := &vpcshark{
		gui:    w,
		region: region,
		ec2:    ec2.NewFromConfig(cfg),
		ssm:    ssm.NewFromConfig(cfg),
	}

	err = v.ctxmain(ctx, launchTemplateId, connectivity, eni)
	if err != nil {
		_, _ = fmt.Fprintf(v.gui.Log(), "err: %+v\n", err)
		return err
	}

	return nil
}

func (v *vpcshark) startInstance(ctx context.Context, pubkey ssh.PublicKey, launchTemplateId string) (types.Instance, error) {
	pubAuthorizedKey := ssh.MarshalAuthorizedKey(pubkey)

	userdata := fmt.Sprintf(`#!/bin/sh
set -eux

mkdir -p /home/ec2-user/.ssh
echo '%s' >> /home/ec2-user/.ssh/authorized_keys
`, string(pubAuthorizedKey))

	run, err := v.ec2.RunInstances(ctx, &ec2.RunInstancesInput{
		MinCount:                          aws.Int32(1),
		MaxCount:                          aws.Int32(1),
		UserData:                          aws.String(base64.StdEncoding.EncodeToString([]byte(userdata))),
		InstanceInitiatedShutdownBehavior: types.ShutdownBehaviorTerminate,
		LaunchTemplate: &types.LaunchTemplateSpecification{
			LaunchTemplateId: &launchTemplateId,
		},
	})
	if err != nil {
		return types.Instance{}, fmt.Errorf("launching instance: %w", err)
	}

	instance := run.Instances[0]
	v.gui.StatusBar(fmt.Sprintf("Started mirror capture instance %s", *instance.InstanceId))

	return instance, nil
}

func (v *vpcshark) waitForPublicIp(ctx context.Context, instanceId string) (string, error) {
	v.gui.StatusBar(fmt.Sprintf("Waiting for public IP for %s", instanceId))

	// poll until we have an ec2 instance and public ip address
	attempts := 0
	for attempts < 10 {
		attempts++
		time.Sleep(5 * time.Second)
		//fmt.Fprintln(w.Log(), "waiting for instance public ip")

		describe, err := v.ec2.DescribeInstances(ctx, &ec2.DescribeInstancesInput{InstanceIds: []string{instanceId}})
		if err != nil {
			return "", fmt.Errorf("describing instances: %w", err)
		}

		instance := describe.Reservations[0].Instances[0]
		if address := aws.ToString(instance.PublicIpAddress); address != "" {
			v.gui.StatusBar(fmt.Sprintf("Got public IP %s", address))
			return address, nil
		}
	}

	return "", fmt.Errorf("couldn't find public ip for instance %s", instanceId)
}

func (v *vpcshark) waitForManagedInstance(ctx context.Context, instanceId string) error {
	// poll until we have a managed instance registered with SSM
	attempts := 0
	for attempts < 10 {
		attempts++
		v.gui.StatusBar(fmt.Sprintf("Waiting for managed instance %s", instanceId))
		time.Sleep(5 * time.Second)

		describe, err := v.ssm.DescribeInstanceInformation(ctx, &ssm.DescribeInstanceInformationInput{
			Filters: []ssmtypes.InstanceInformationStringFilter{
				{
					Key:    aws.String("InstanceIds"),
					Values: []string{instanceId},
				},
			},
		})
		if err != nil {
			return fmt.Errorf("listing managed instances: %w", err)
		}

		if len(describe.InstanceInformationList) == 0 {
			continue
		}

		instance := describe.InstanceInformationList[0]
		if instance.PingStatus == ssmtypes.PingStatusOnline {
			v.gui.StatusBar(fmt.Sprintf("Got managed instance %s", instanceId))
			return nil
		}
	}

	return fmt.Errorf("couldn't find managed instance %s", instanceId)
}

func (v *vpcshark) sshClient(ctx context.Context, connectivity string, sshcfg *ssh.ClientConfig, instance types.Instance) (*ssh.Client, error) {
	instanceId := *instance.InstanceId
	var dial func(ctx context.Context) (net.Conn, error)

	switch connectivity {
	case "public-ssh":
		publicIp, err := v.waitForPublicIp(ctx, *instance.InstanceId)
		if err != nil {
			return nil, fmt.Errorf("getting public ip: %w", err)
		}
		v.gui.StatusBar(fmt.Sprintf("Trying to establish SSH connectivity to %s", publicIp))

		dial = func(ctx context.Context) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "tcp", publicIp+":22")
		}
	case "ssm-tunnel":
		err := v.waitForManagedInstance(ctx, instanceId)
		if err != nil {
			return nil, fmt.Errorf("waiting for managed instance: %w", err)
		}
		v.gui.StatusBar(fmt.Sprintf("Trying to establish SSH over SSM connectivity to %s", instanceId))

		dialer := &awsdial.Dialer{Client: v.ssm, Region: v.region}
		dial = func(ctx context.Context) (net.Conn, error) {
			return dialer.Dial(ctx, instanceId, 22)
		}
	default:
		return nil, fmt.Errorf("unexpected connectivity option: %s", connectivity)
	}

	// now we poll until we can connect to the ssh server
	attempts := 0
	for attempts < 10 {
		attempts++
		fmt.Fprintln(v.gui.Log(), time.Now().String()+" waiting for instance ssh connectivity")

		start := time.Now()

		conn, err := dial(ctx)
		if err != nil {
			time.Sleep(sshcfg.Timeout - time.Now().Sub(start))
			continue
		}

		_, _, _, err = ssh.NewClientConn(conn, instanceId, sshcfg)
		if err != nil {
			conn.Close()
			time.Sleep(sshcfg.Timeout - time.Now().Sub(start))
			continue
		}

		conn.Close()
		break
	}

	conn, err := dial(ctx)
	if err != nil {
		return nil, fmt.Errorf("establishing port forwarding to ec2 instance: %w", err)
	}

	cc, chans, reqs, err := ssh.NewClientConn(conn, instanceId, sshcfg)
	if err != nil {
		return nil, fmt.Errorf("establishing ssh over port-forwarded ssm tunnel: %w", err)
	}

	return ssh.NewClient(cc, chans, reqs), nil
}

func (v *vpcshark) ctxmain(ctx context.Context, launchTemplateId, connectivity, eni string) error {
	v.gui.StatusBar("starting")

	describeSourceInstance, err := v.ec2.DescribeInstances(ctx, &ec2.DescribeInstancesInput{
		Filters: []types.Filter{
			{
				Name:   aws.String("network-interface.network-interface-id"),
				Values: []string{eni},
			},
		},
	})
	if err != nil {
		return fmt.Errorf("describing mirror source instance: %w", err)
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("generating ssh keypair: %w", err)
	}

	sshpub, err := ssh.NewPublicKey(pub)
	if err != nil {
		return fmt.Errorf("converting key to ssh: %w", err)
	}

	tags := []types.Tag{
		{Key: aws.String("Name"), Value: aws.String("vpcshark")},
		{Key: aws.String("vpcshark"), Value: aws.String("")},
	}

	instance, err := v.startInstance(ctx, sshpub, launchTemplateId)
	if err != nil {
		return fmt.Errorf(": %w", err)
	}

	defer func(ctx context.Context) {
		instanceId := *instance.InstanceId
		fmt.Fprintf(os.Stderr, "Terminating %s\n", instanceId)
		_, err = v.ec2.TerminateInstances(ctx, &ec2.TerminateInstancesInput{InstanceIds: []string{instanceId}})
		fmt.Fprintf(os.Stderr, "Error terminating %s: %+v\n", instanceId, err)
	}(ctx)

	captureEni := *instance.NetworkInterfaces[0].NetworkInterfaceId
	targetId, cleanup, err := v.createTrafficMirror(ctx, eni, captureEni, tags)
	if err != nil {
		return err
	}

	defer cleanup()

	signer, err := ssh.NewSignerFromSigner(priv)
	if err != nil {
		return fmt.Errorf("getting ssh signer: %w", err)
	}

	sshcfg := &ssh.ClientConfig{
		User:    "ec2-user",
		Timeout: 5 * time.Second,
		Auth:    []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			// allow any host key
			return nil
		},
	}

	client, err := v.sshClient(ctx, connectivity, sshcfg, instance)
	if err != nil {
		return fmt.Errorf(": %w", err)
	}
	defer client.Close()

	err = v.installRemoteTool(ctx, client)
	if err != nil {
		return fmt.Errorf("installing socat: %w", err)
	}

	v.gui.StatusBar("Good to go")

	ctx, cancel := context.WithCancel(ctx)
	g, ctx := errgroup.WithContext(ctx)
	pktch := make(chan []byte)

	g.Go(func() error {
		defer cancel()
		err := v.writePcapToFifo(ctx, eni, *describeSourceInstance.Reservations[0].Instances[0].InstanceId, pktch, v.gui.Pcap())
		if errors.Is(err, syscall.EPIPE) {
			fmt.Fprintln(os.Stderr, "Wireshark closed pcap fifo")
			return nil
		}

		return err
	})

	g.Go(func() error {
		return v.runRemoteTool(ctx, client, targetId, pktch)
	})

	err = g.Wait()
	return err
}

func (v *vpcshark) createTrafficMirror(ctx context.Context, mirroredEni, captureEni string, tags []types.Tag) (targetId string, cleanup func(), err error) {
	target, err := v.ec2.CreateTrafficMirrorTarget(ctx, &ec2.CreateTrafficMirrorTargetInput{
		NetworkInterfaceId: &captureEni,
		Description:        aws.String(trafficMirrorDescription),
		TagSpecifications: []types.TagSpecification{
			{ResourceType: types.ResourceTypeTrafficMirrorTarget, Tags: tags},
		},
	})
	if err != nil {
		return "", cleanup, fmt.Errorf("creating traffic mirror target: %w", err)
	}

	targetId = *target.TrafficMirrorTarget.TrafficMirrorTargetId
	v.gui.StatusBar(fmt.Sprintf("Created traffic mirror target %s", targetId))

	filter, err := v.ec2.CreateTrafficMirrorFilter(ctx, &ec2.CreateTrafficMirrorFilterInput{
		Description: aws.String(trafficMirrorDescription),
		TagSpecifications: []types.TagSpecification{
			{ResourceType: types.ResourceTypeTrafficMirrorFilter, Tags: tags},
		},
	})
	if err != nil {
		return "", cleanup, fmt.Errorf("creating traffic mirror filter: %w", err)
	}

	filterId := filter.TrafficMirrorFilter.TrafficMirrorFilterId
	v.gui.StatusBar(fmt.Sprintf("Created traffic mirror filter %s", *filterId))

	_, err = v.ec2.ModifyTrafficMirrorFilterNetworkServices(ctx, &ec2.ModifyTrafficMirrorFilterNetworkServicesInput{
		TrafficMirrorFilterId: filterId,
		AddNetworkServices:    []types.TrafficMirrorNetworkService{types.TrafficMirrorNetworkServiceAmazonDns},
	})
	if err != nil {
		return "", cleanup, fmt.Errorf("enabling dns resolution in mirror filter: %w", err)
	}

	_, err = v.ec2.CreateTrafficMirrorFilterRule(ctx, &ec2.CreateTrafficMirrorFilterRuleInput{
		TrafficMirrorFilterId: filterId,
		DestinationCidrBlock:  aws.String("0.0.0.0/0"),
		SourceCidrBlock:       aws.String("0.0.0.0/0"),
		TrafficDirection:      types.TrafficDirectionIngress,
		RuleAction:            types.TrafficMirrorRuleActionAccept,
		RuleNumber:            aws.Int32(100),
	})
	if err != nil {
		return "", cleanup, fmt.Errorf("creating filter ingress rule: %w", err)
	}

	_, err = v.ec2.CreateTrafficMirrorFilterRule(ctx, &ec2.CreateTrafficMirrorFilterRuleInput{
		TrafficMirrorFilterId: filterId,
		DestinationCidrBlock:  aws.String("0.0.0.0/0"),
		SourceCidrBlock:       aws.String("0.0.0.0/0"),
		TrafficDirection:      types.TrafficDirectionEgress,
		RuleAction:            types.TrafficMirrorRuleActionAccept,
		RuleNumber:            aws.Int32(100),
	})
	if err != nil {
		return "", cleanup, fmt.Errorf("creating filter egress rule: %w", err)
	}

	session, err := v.ec2.CreateTrafficMirrorSession(ctx, &ec2.CreateTrafficMirrorSessionInput{
		NetworkInterfaceId:    &mirroredEni,
		SessionNumber:         aws.Int32(int32(1_000 + mrand.Intn(30_000))),
		TrafficMirrorFilterId: filterId,
		TrafficMirrorTargetId: &targetId,
		VirtualNetworkId:      aws.Int32(trafficMirrorVNI),
		Description:           aws.String(trafficMirrorDescription),
		TagSpecifications: []types.TagSpecification{
			{ResourceType: types.ResourceTypeTrafficMirrorSession, Tags: tags},
		},
	})
	if err != nil {
		return "", cleanup, fmt.Errorf("creating traffic mirror session: %w", err)
	}

	sessionId := session.TrafficMirrorSession.TrafficMirrorSessionId
	v.gui.StatusBar(fmt.Sprintf("Created traffic mirror session %s", *sessionId))

	cleanup = func() {
		fmt.Fprintf(os.Stderr, "Deleting %s\n", *sessionId)
		v.ec2.DeleteTrafficMirrorSession(ctx, &ec2.DeleteTrafficMirrorSessionInput{TrafficMirrorSessionId: sessionId})

		fmt.Fprintf(os.Stderr, "Deleting %s\n", *filterId)
		v.ec2.DeleteTrafficMirrorFilter(ctx, &ec2.DeleteTrafficMirrorFilterInput{TrafficMirrorFilterId: filterId})

		fmt.Fprintf(os.Stderr, "Deleting %s\n", targetId)
		v.ec2.DeleteTrafficMirrorTarget(ctx, &ec2.DeleteTrafficMirrorTargetInput{TrafficMirrorTargetId: &targetId})
	}

	return targetId, cleanup, nil
}

func (v *vpcshark) runRemoteTool(ctx context.Context, client *ssh.Client, targetId string, packets chan []byte) error {
	sess, err := client.NewSession()
	if err != nil {
		return fmt.Errorf("opening ssh session for remote tool: %w", err)
	}
	defer sess.Close()

	go func() {
		<-ctx.Done()
		sess.Close()
	}()

	sess.Stdout = os.Stderr
	sess.Stderr = os.Stderr

	err = sess.Run(fmt.Sprintf("%s %s %s", remotePath, v.region, targetId))
	if err != nil {
		return fmt.Errorf("running remote cmd: %w", err)
	}

	time.Sleep(time.Second)

	conn, err := client.Dial("tcp", "127.0.0.1:4790")
	if err != nil {
		return fmt.Errorf("dialing 4790: %w", err)
	}
	defer conn.Close()

	go func() {
		<-ctx.Done()
		conn.Close()
	}()

	lenbuf := make([]byte, 2)
	for {
		_, err := conn.Read(lenbuf)
		if err != nil {
			return fmt.Errorf("reading conn: %w", err)
		}

		pktlen := binary.BigEndian.Uint16(lenbuf)
		pkt := make([]byte, pktlen)
		_, err = io.ReadFull(conn, pkt)
		if err != nil {
			return fmt.Errorf(": %w", err)
		}

		select {
		case <-ctx.Done():
			return nil
		case packets <- pkt:
			// no-op
		}
	}
}

func (v *vpcshark) writePcapToFifo(ctx context.Context, eni, instanceId string, packets chan []byte, fifo io.WriteCloser) error {
	w, err := pcapgo.NewNgWriterInterface(fifo, pcapgo.NgInterface{
		Name:        eni,
		Description: instanceId,
		LinkType:    layers.LinkTypeEthernet,
		Statistics:  pcapgo.NgInterfaceStatistics{},
	}, pcapgo.NgWriterOptions{})
	if err != nil {
		return fmt.Errorf(": %w", err)
	}

	for {
		select {
		case <-ctx.Done():
			return nil
		case pktbuf := <-packets:
			pkt := gopacket.NewPacket(pktbuf, layers.LayerTypeVXLAN, gopacket.Default)
			vxlan := pkt.Layers()[0].(*layers.VXLAN)
			payload := vxlan.LayerPayload()

			err = w.WritePacket(gopacket.CaptureInfo{
				Timestamp:     time.Now(),
				CaptureLength: len(payload),
				Length:        len(payload),
				//InterfaceIndex: 0,
				//AncillaryData:  nil,
			}, payload)
			if err != nil {
				return fmt.Errorf("write : %w", err)
			}

			err = w.Flush()
			if err != nil {
				return fmt.Errorf("flush : %w", err)
			}

			if err != nil {
				return fmt.Errorf("sync : %w", err)
			}
		}
	}
}

//go:embed remote/remote
var remoteBinary []byte

const remotePath = "/tmp/vpcshark-remote"

func (v *vpcshark) installRemoteTool(ctx context.Context, client *ssh.Client) error {
	v.gui.StatusBar("Copying remote helper to instance")

	c, err := scp.NewClientBySSH(client)
	if err != nil {
		return fmt.Errorf("creating scp client: %w", err)
	}

	err = c.Copy(ctx, bytes.NewReader(remoteBinary), remotePath, "0755", int64(len(remoteBinary)))
	if err != nil {
		return fmt.Errorf("copying remote binary over scp: %w", err)
	}

	return nil
}
