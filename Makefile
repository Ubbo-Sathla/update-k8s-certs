.PHONY: all build clean

BINARY_NAME="update-k8s-certs"

build: gotool gobuild

gotool:
	go mod tidy

gobuild:
	CGO_ENABLED=0 GOARCH=amd64 GOOS=darwin go build -o ${BINARY_NAME}-darwin main.go
	CGO_ENABLED=0 GOARCH=amd64 GOOS=linux go build -o ${BINARY_NAME}-linux main.go

clean:
	rm -rf  ${BINARY_NAME}-darwin
	rm -rf  ${BINARY_NAME}-linux
