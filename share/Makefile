all:
	@protoc *.proto --go_out=plugins=grpc:.
	@sed -i 's:"golang.org/x/net/context":"context":' *.go
