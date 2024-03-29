all:
	# go build --ldflags '-extldflags "-static"'
	go build -ldflags='-s -w' -ldflags="-X google.golang.org/protobuf/reflect/protoregistry.conflictPolicy=warn"
