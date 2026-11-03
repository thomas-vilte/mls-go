module github.com/thomas-vilte/mls-go/interop/testrunner

go 1.26.1

require (
	github.com/google/uuid v1.6.0
	github.com/thomas-vilte/mls-go/interop/server v0.0.0
	google.golang.org/grpc v1.85.0
)

require (
	golang.org/x/net v0.62.0 // indirect
	golang.org/x/sys v0.49.0 // indirect
	golang.org/x/text v0.43.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20261026165753-2ffab32bce7e // indirect
	google.golang.org/protobuf v1.36.12 // indirect
)

replace github.com/thomas-vilte/mls-go/interop/server => ../server
