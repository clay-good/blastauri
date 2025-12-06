module github.com/example/testproject

go 1.21

require (
	github.com/gin-gonic/gin v1.9.1
	github.com/stretchr/testify v1.8.4
	github.com/spf13/cobra v1.8.0
)

require (
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/spf13/pflag v1.0.5 // indirect
)

replace github.com/old/module => github.com/new/module v1.0.0
