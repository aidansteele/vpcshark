package main

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
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
	"strings"
	"time"
)

const trafficMirrorVNI = 0xBEEF
const trafficMirrorDescription = "vpcshark"

func main() {
	j, _ := json.MarshalIndent(os.Args, "", "  ")
	fmt.Fprintln(os.Stderr, string(j))

	mrand.Seed(time.Now().UnixNano())

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
	pf.String("vpc", "", "")
	pf.String("eni", "", "")
	pf.String("launch-template-id", "", "")

	ctx := context.Background()
	err := rootCmd.ExecuteContext(ctx)
	if err != nil {
		panic(fmt.Sprintf("%+v", err))
	}
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
	vpc, _ := pf.GetString("vpc")
	launchTemplateId, _ := pf.GetString("launch-template-id")

	if cleanup {
		return runCleanup(ctx, profile)
	} else if extcapInterfaces {
		return runExtcapInterfaces(ctx)
	} else if extcapConfig {
		return runExtcapConfig(ctx, profile, vpc, extcapReloadOption)
	} else if extcapDLTs {
		return runExtcapDLTs(ctx)
	} else if capture {
		return runCapture(ctx, profile, launchTemplateId, eni, extcapControlIn, extcapControlOut, fifo)
	} else {
		return fmt.Errorf("unexpected command")
	}
}

type vpcshark struct {
	gui *Wireshark
	ec2 *ec2.Client
	ssm *ssm.Client
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

func runExtcapConfig(ctx context.Context, profile string, vpc string, reloadOption string) error {
	if reloadOption == "vpc" {
		cfg, err := config.LoadDefaultConfig(ctx, config.WithSharedConfigProfile(profile))
		if err != nil {
			return fmt.Errorf(": %w", err)
		}

		api := ec2.NewFromConfig(cfg)
		p := ec2.NewDescribeVpcsPaginator(api, &ec2.DescribeVpcsInput{})

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

				fmt.Printf("value {arg=2}{value=%s}{display=%s}\n", vpcId, display)
			}
		}

		return nil
	}

	if reloadOption == "launch-template-id" {
		cfg, err := config.LoadDefaultConfig(ctx, config.WithSharedConfigProfile(profile))
		if err != nil {
			return fmt.Errorf(": %w", err)
		}

		api := ec2.NewFromConfig(cfg)
		p := ec2.NewDescribeLaunchTemplatesPaginator(api, &ec2.DescribeLaunchTemplatesInput{})

		for p.HasMorePages() {
			page, err := p.NextPage(ctx)
			if err != nil {
				return fmt.Errorf(": %w", err)
			}

			for _, template := range page.LaunchTemplates {
				id := *template.LaunchTemplateId
				name := *template.LaunchTemplateName
				fmt.Printf("value {arg=4}{value=%s}{display=%s (%s)}\n", id, id, name)
			}
		}

		return nil
	}

	if reloadOption == "eni" {
		cfg, err := config.LoadDefaultConfig(ctx, config.WithSharedConfigProfile(profile))
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

						fmt.Printf("value {arg=3}{value=%s}{display=%s}\n", eniId, display)
					}
				}
			}
		}

		return nil
	}

	fmt.Printf("arg {number=1}{call=--profile}{display=AWS Profile}{type=selector}{required=true}\n")
	fmt.Printf("arg {number=2}{call=--vpc}{display=VPC}{type=selector}{required=true}{reload=true}{placeholder=Load VPCs...}\n")
	fmt.Printf("arg {number=3}{call=--eni}{display=Capture ENI}{tooltip=Select ENI(s) to monitor}{type=selector}{reload=true}{placeholder=Load ENIs...}{required=true}\n")
	fmt.Printf("arg {number=4}{call=--launch-template-id}{display=Mirror target launch template}{tooltip=Select launch template for mirror target}{type=selector}{reload=true}{placeholder=Load templates...}{required=true}\n")

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

	return profiles, nil
}

func runExtcapDLTs(ctx context.Context) error {
	fmt.Println(`dlt {number=1}{name=LINKTYPE_ETHERNET}{display=Ethernet}`)
	return nil
}

func runCapture(ctx context.Context, profile, launchTemplateId, eni, extcapControlIn, extcapControlOut, fifo string) error {
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

	cfg, err := config.LoadDefaultConfig(ctx, config.WithSharedConfigProfile(profile))
	if err != nil {
		return fmt.Errorf(": %w", err)
	}

	v := &vpcshark{
		gui: w,
		ec2: ec2.NewFromConfig(cfg),
		ssm: ssm.NewFromConfig(cfg),
	}

	err = v.ctxmain(ctx, launchTemplateId, eni)
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

func (v *vpcshark) ctxmain(ctx context.Context, launchTemplateId, eni string) error {
	v.gui.StatusBar("starting")

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
	}

	instance, err := v.startInstance(ctx, sshpub, launchTemplateId)
	if err != nil {
		return fmt.Errorf(": %w", err)
	}

	captureEni := *instance.NetworkInterfaces[0].NetworkInterfaceId
	err = v.createTrafficMirror(ctx, eni, captureEni, tags)
	if err != nil {
		return err
	}

	publicIp, err := v.waitForPublicIp(ctx, *instance.InstanceId)
	if err != nil {
		return fmt.Errorf("getting public ip: %w", err)
	}

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

	v.gui.StatusBar(fmt.Sprintf("Trying to establish SSH connectivity to %s", publicIp))
	// now we poll until we can connect to the ssh server
	attempts := 0
	for attempts < 10 {
		attempts++
		fmt.Fprintln(v.gui.Log(), time.Now().String()+" waiting for instance ssh connectivity")

		start := time.Now()
		client, err := ssh.Dial("tcp", publicIp+":22", sshcfg)
		if err != nil {
			time.Sleep(sshcfg.Timeout - time.Now().Sub(start))
			continue
		}

		client.Close()
		break
	}

	client, err := ssh.Dial("tcp", publicIp+":22", sshcfg)
	if err != nil {
		return fmt.Errorf("dialing ssh server: %w", err)
	}
	defer client.Close()

	v.gui.StatusBar(fmt.Sprintf("Configuring socat on instance %s", *instance.InstanceId))

	err = installSocat(ctx, client)
	if err != nil {
		return fmt.Errorf("installing socat: %w", err)
	}

	v.gui.StatusBar("Good to go")

	pr, pw := io.Pipe()
	g, ctx := errgroup.WithContext(ctx)

	g.Go(func() error {
		defer v.gui.Pcap().Close()
		return writePcapToFifo(pr, v.gui.Pcap())
	})

	g.Go(func() error {
		return runSocat(client, pw)
	})

	err = g.Wait()
	return err
}

func (v *vpcshark) createTrafficMirror(ctx context.Context, mirroredEni, captureEni string, tags []types.Tag) error {
	target, err := v.ec2.CreateTrafficMirrorTarget(ctx, &ec2.CreateTrafficMirrorTargetInput{
		NetworkInterfaceId: &captureEni,
		Description:        aws.String(trafficMirrorDescription),
		TagSpecifications: []types.TagSpecification{
			{ResourceType: types.ResourceTypeTrafficMirrorTarget, Tags: tags},
		},
	})
	if err != nil {
		return fmt.Errorf("creating traffic mirror target: %w", err)
	}

	targetId := target.TrafficMirrorTarget.TrafficMirrorTargetId
	v.gui.StatusBar(fmt.Sprintf("Created traffic mirror target %s", *targetId))

	filter, err := v.ec2.CreateTrafficMirrorFilter(ctx, &ec2.CreateTrafficMirrorFilterInput{
		Description: aws.String(trafficMirrorDescription),
		TagSpecifications: []types.TagSpecification{
			{ResourceType: types.ResourceTypeTrafficMirrorFilter, Tags: tags},
		},
	})
	if err != nil {
		return fmt.Errorf("creating traffic mirror filter: %w", err)
	}

	filterId := filter.TrafficMirrorFilter.TrafficMirrorFilterId
	v.gui.StatusBar(fmt.Sprintf("Created traffic mirror filter %s", *filterId))

	_, err = v.ec2.ModifyTrafficMirrorFilterNetworkServices(ctx, &ec2.ModifyTrafficMirrorFilterNetworkServicesInput{
		TrafficMirrorFilterId: filterId,
		AddNetworkServices:    []types.TrafficMirrorNetworkService{types.TrafficMirrorNetworkServiceAmazonDns},
	})
	if err != nil {
		return fmt.Errorf("enabling dns resolution in mirror filter: %w", err)
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
		return fmt.Errorf("creating filter ingress rule: %w", err)
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
		return fmt.Errorf("creating filter egress rule: %w", err)
	}

	session, err := v.ec2.CreateTrafficMirrorSession(ctx, &ec2.CreateTrafficMirrorSessionInput{
		NetworkInterfaceId:    &mirroredEni,
		SessionNumber:         aws.Int32(int32(mrand.Intn(100))),
		TrafficMirrorFilterId: filterId,
		TrafficMirrorTargetId: targetId,
		VirtualNetworkId:      aws.Int32(trafficMirrorVNI),
		Description:           aws.String(trafficMirrorDescription),
		TagSpecifications: []types.TagSpecification{
			{ResourceType: types.ResourceTypeTrafficMirrorSession, Tags: tags},
		},
	})
	if err != nil {
		return fmt.Errorf("creating traffic mirror session: %w", err)
	}

	sessionId := session.TrafficMirrorSession.TrafficMirrorSessionId
	v.gui.StatusBar(fmt.Sprintf("Created traffic mirror session %s", *sessionId))

	return nil
}

func runSocat(client *ssh.Client, pw io.Writer) error {
	setup, err := client.NewSession()
	if err != nil {
		return fmt.Errorf(": %w", err)
	}
	defer setup.Close()

	setup.Stdin = strings.NewReader(`#!/bin/sh
		trap "sudo shutdown -h now" EXIT
		socat -u udp4-recvfrom:4789,fork exec:"/usr/bin/xxd -p -c0"
	`)
	err = setup.Run("cat - > script.sh")
	if err != nil {
		return fmt.Errorf("copying script to instance: %w", err)
	}

	sess, err := client.NewSession()
	if err != nil {
		return fmt.Errorf("opening ssh session for socat: %w", err)
	}
	defer sess.Close()

	sess.Stdout = pw
	sess.Stderr = os.Stderr
	// requesting a pty ensures that socat doesn't ignore us disconnecting
	err = sess.RequestPty("xterm", 80, 40, ssh.TerminalModes{})
	if err != nil {
		return fmt.Errorf("requesting pty: %w", err)
	}

	err = sess.Run("sh script.sh")
	if err != nil {
		return fmt.Errorf("starting socat: %w", err)
	}

	return nil
}

func writePcapToFifo(pr io.Reader, fifo io.WriteCloser) error {
	w, err := pcapgo.NewNgWriter(fifo, layers.LinkTypeEthernet)
	if err != nil {
		return fmt.Errorf(": %w", err)
	}

	scan := bufio.NewScanner(pr)
	for scan.Scan() {
		raw, err := hex.DecodeString(scan.Text())
		if err != nil {
			return fmt.Errorf("decoding base64: %w", err)
		}

		pkt := gopacket.NewPacket(raw, layers.LayerTypeVXLAN, gopacket.Default)
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

		fmt.Printf("%d\n", len(raw))
	}

	return nil
}

func installSocat(ctx context.Context, client *ssh.Client) error {
	sess, err := client.NewSession()
	if err != nil {
		return fmt.Errorf("opening ssh session: %w", err)
	}
	defer sess.Close()

	sess.Stdout = os.Stdout
	sess.Stderr = os.Stderr
	err = sess.Run("sudo yum install -y socat")
	if err != nil {
		return fmt.Errorf("running yum: %s: %w", err)
	}

	return nil
}

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
