module github.com/thomas-vilte/mls-go/interop/testrunner

go 1.26.1

require (
	github.com/google/uuid v1.6.0
	github.com/thomas-vilte/mls-go/interop/server v0.0.0
	google.golang.org/grpc v1.79.2
)

require (
	golang.org/x/net v0.52.0 // indirect
	golang.org/x/sys v0.42.0 // indirect
	golang.org/x/text v0.35.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260311181403-84a4fc48630c // indirect
	google.golang.org/protobuf v1.36.11 // indirect
)

replace github.com/thomas-vilte/mls-go/interop/server => ../server
