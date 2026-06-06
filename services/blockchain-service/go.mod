module github.com/fraud-detection/blockchain-service

go 1.25.0

require (
	github.com/fraud-detection/shared v0.0.0
	github.com/hyperledger/fabric-gateway v1.11.0
	github.com/hyperledger/fabric-protos-go-apiv2 v0.3.7
	github.com/rs/zerolog v1.33.0
	github.com/segmentio/kafka-go v0.4.47
	github.com/stretchr/testify v1.11.1
	google.golang.org/grpc v1.80.0
	google.golang.org/protobuf v1.36.11
)

require (
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/klauspost/compress v1.15.9 // indirect
	github.com/kr/pretty v0.1.0 // indirect
	github.com/mattn/go-colorable v0.1.13 // indirect
	github.com/mattn/go-isatty v0.0.19 // indirect
	github.com/miekg/pkcs11 v1.1.2 // indirect
	github.com/pierrec/lz4/v4 v4.1.15 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	golang.org/x/net v0.49.0 // indirect
	golang.org/x/sys v0.40.0 // indirect
	golang.org/x/text v0.33.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260120221211-b8f7ae30c516 // indirect
	gopkg.in/check.v1 v1.0.0-20180628173108-788fd7840127 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

replace github.com/fraud-detection/shared => ../../shared/go

exclude google.golang.org/genproto v0.0.0-20190819201941-24fa4b261c55
