module github.com/aidansteele/vpcshark

go 1.19

require (
	github.com/aws/aws-sdk-go-v2 v1.16.16
	github.com/aws/aws-sdk-go-v2/config v1.17.8
	github.com/aws/aws-sdk-go-v2/service/ec2 v1.63.1
	github.com/aws/aws-sdk-go-v2/service/ssm v1.31.0
	github.com/aws/session-manager-plugin v0.0.0-20221012155945-c523002ee02c
	github.com/davecgh/go-spew v1.1.1
	github.com/google/gopacket v1.1.19
	github.com/google/uuid v1.3.0
	github.com/mmmorris1975/ssm-session-client v0.204.0
	github.com/spf13/cobra v1.6.0
	golang.org/x/crypto v0.0.0-20221010152910-d6f0a8c073c2
	golang.org/x/sync v0.0.0-20220929204114-8fcdb60fdcc0
	gopkg.in/ini.v1 v1.67.0
)

require (
	github.com/aws/aws-sdk-go v1.44.76 // indirect
	github.com/aws/aws-sdk-go-v2/credentials v1.12.21 // indirect
	github.com/aws/aws-sdk-go-v2/feature/ec2/imds v1.12.17 // indirect
	github.com/aws/aws-sdk-go-v2/internal/configsources v1.1.23 // indirect
	github.com/aws/aws-sdk-go-v2/internal/endpoints/v2 v2.4.17 // indirect
	github.com/aws/aws-sdk-go-v2/internal/ini v1.3.24 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/presigned-url v1.9.17 // indirect
	github.com/aws/aws-sdk-go-v2/service/sso v1.11.23 // indirect
	github.com/aws/aws-sdk-go-v2/service/ssooidc v1.13.6 // indirect
	github.com/aws/aws-sdk-go-v2/service/sts v1.16.19 // indirect
	github.com/aws/smithy-go v1.13.3 // indirect
	github.com/cihub/seelog v0.0.0-20170130134532-f561c5e57575 // indirect
	github.com/fsnotify/fsnotify v1.5.4 // indirect
	github.com/gorilla/websocket v1.5.0 // indirect
	github.com/inconshreveable/mousetrap v1.0.1 // indirect
	github.com/jmespath/go-jmespath v0.4.0 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/spf13/pflag v1.0.5 // indirect
	github.com/stretchr/objx v0.4.0 // indirect
	github.com/stretchr/testify v1.8.0 // indirect
	github.com/twinj/uuid v0.0.0-20151029044442-89173bcdda19 // indirect
	github.com/xtaci/smux v1.5.16 // indirect
	golang.org/x/net v0.0.0-20220812174116-3211cb980234 // indirect
	golang.org/x/sys v0.0.0-20220811171246-fbc7d0a398ab // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

replace github.com/mmmorris1975/ssm-session-client => github.com/aidansteele/ssm-session-client v0.0.0-20221014002521-e2f645594da8
