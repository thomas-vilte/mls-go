module github.com/thomas-vilte/mls-go/interop/server

go 1.26.1

require (
	github.com/thomas-vilte/mls-go v0.3.0
	google.golang.org/grpc v1.79.3
	google.golang.org/protobuf v1.36.11
)

require (
	golang.org/x/crypto v0.53.0 // indirect
	golang.org/x/net v0.56.0 // indirect
	golang.org/x/sys v0.46.0 // indirect
	golang.org/x/text v0.38.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260311181403-84a4fc48630c // indirect
)

replace github.com/thomas-vilte/mls-go => ../..
