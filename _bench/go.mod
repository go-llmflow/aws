module github.com/go-llmflow/aws/_bench

go 1.27.1

require (
	github.com/aws/aws-sdk-go-v2 v1.48.0
	github.com/aws/aws-sdk-go-v2/aws/protocol/eventstream v1.7.27
	github.com/go-llmflow/aws v0.1.2
)

require github.com/aws/smithy-go v1.28.9 // indirect

replace github.com/go-llmflow/aws => ../
