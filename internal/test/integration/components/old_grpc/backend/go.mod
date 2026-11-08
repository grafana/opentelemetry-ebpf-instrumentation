module go.opentelemetry.io/obi/internal/test/integration/components/old_grpc/backend

go 1.25.11

require (
	github.com/caarlos0/env/v7 v7.1.0
	go.opentelemetry.io/obi/internal/test/integration/components/old_grpc/worker v0.0.0-20251206001222-296c1ac98db8
	google.golang.org/grpc v1.83.2
	google.golang.org/protobuf v1.36.11
)

require (
	github.com/golang/protobuf v1.5.4 // indirect
	golang.org/x/net v0.58.0 // indirect
	golang.org/x/sys v0.47.0 // indirect
	golang.org/x/text v0.41.0 // indirect
	google.golang.org/genproto v0.0.0-20230410155749-daa745c078e1 // indirect
)

replace go.opentelemetry.io/obi v0.0.0 => ../../../../../../../

replace go.opentelemetry.io/obi/internal/test/integration/components/old_grpc/worker => ../worker/
