//go:build linux

package main

import (
	"context"
	"encoding/binary"
	"fmt"
	"github.com/aidansteele/vpcshark/cleanup"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"golang.org/x/sys/unix"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"time"
)

func main() {
	daemonizeIfParent()

	ctx := context.Background()
	sigctx, done := signal.NotifyContext(ctx, os.Interrupt, os.Kill, unix.SIGHUP)
	defer done()

	f, err := os.OpenFile("/tmp/vpcshark.log", os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0644)
	if err != nil {
		panic(fmt.Sprintf("%+v", err))
	}
	defer f.Close()

	fmt.Fprintf(f, "%s pre-packetForwardLoop\n", time.Now())
	err = packetForwardLoop(sigctx)
	fmt.Fprintf(f, "%s got error %+v\n", time.Now(), err)

	awsRegion, targetId := os.Args[1], os.Args[2]
	fmt.Fprintf(f, "%s region=%s target=%s\n", time.Now(), awsRegion, targetId)

	fmt.Fprintf(f, "%s post-packetForwardLoop\n", time.Now())
	fmt.Fprintf(f, "%s pre-cleanup\n", time.Now())
	err = cleanupAfterMe(ctx, awsRegion, targetId)
	fmt.Fprintf(f, "%s got error %+v\n", time.Now(), err)
	fmt.Fprintf(f, "%s post-cleanup\n", time.Now())

	cmd := exec.Command("sudo", "shutdown", "now")
	err = cmd.Run()
	if err != nil {
		panic(fmt.Sprintf("%+v", err))
	}

	fmt.Fprintf(f, "%s post-shutdown (???)\n", time.Now())
}

func daemonizeIfParent() {
	if _, isChild := os.LookupEnv("CHILD"); isChild {
		return
	}

	exe, err := os.Executable()
	if err != nil {
		panic(fmt.Sprintf("%+v", err))
	}

	cmd := exec.Command(exe, os.Args[1:]...)
	cmd.Env = append(os.Environ(), "CHILD=true")
	err = cmd.Start()
	if err != nil {
		panic(fmt.Sprintf("%+v", err))
	}

	os.Exit(0)
}

func cleanupAfterMe(ctx context.Context, awsRegion, targetId string) error {
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(awsRegion))
	if err != nil {
		return fmt.Errorf(": %w", err)
	}

	api := ec2.NewFromConfig(cfg)
	sessions, err := cleanup.DeleteSessions(ctx, api, []types.Filter{
		{
			Name:   aws.String("traffic-mirror-target-id"),
			Values: []string{targetId},
		},
	})
	if err != nil {
		return fmt.Errorf(": %w", err)
	}

	filterIds := map[string]struct{}{}
	for _, session := range sessions {
		filterIds[*session.TrafficMirrorFilterId] = struct{}{}
	}

	for filterId := range filterIds {
		_, err = api.DeleteTrafficMirrorFilter(ctx, &ec2.DeleteTrafficMirrorFilterInput{TrafficMirrorFilterId: &filterId})
		if err != nil {
			return fmt.Errorf(": %w", err)
		}
	}

	_, err = api.DeleteTrafficMirrorTarget(ctx, &ec2.DeleteTrafficMirrorTargetInput{TrafficMirrorTargetId: &targetId})
	if err != nil {
		return fmt.Errorf(": %w", err)
	}

	return nil
}

func packetForwardLoop(ctx context.Context) error {
	clientListener, err := net.Listen("tcp", "127.0.0.1:4790")
	if err != nil {
		return fmt.Errorf(": %w", err)
	}

	go func() {
		<-ctx.Done()
		clientListener.Close()
	}()

	clientConn, err := clientListener.Accept()
	if err != nil {
		return fmt.Errorf(": %w", err)
	}

	vxlanConn, err := net.ListenUDP("udp", &net.UDPAddr{Port: 4789})
	if err != nil {
		return fmt.Errorf(": %w", err)
	}

	go func() {
		<-ctx.Done()
		vxlanConn.Close()
	}()

	buf := make([]byte, 9003)

	for {
		n, err := vxlanConn.Read(buf[2:])
		if err != nil {
			return fmt.Errorf(": %w", err)
		}

		binary.BigEndian.PutUint16(buf, uint16(n))
		_, err = clientConn.Write(buf[:n+2])
		if err != nil {
			return fmt.Errorf(": %w", err)
		}
	}
}
