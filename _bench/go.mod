module github.com/go-llmflow/aws/_bench

go 1.27.1

require (
	github.com/aws/aws-sdk-go-v2 v1.47.5
	github.com/aws/aws-sdk-go-v2/aws/protocol/eventstream v1.7.25
	github.com/go-llmflow/aws v0.0.0
)

require github.com/aws/smithy-go v1.28.7 // indirect

replace github.com/go-llmflow/aws => ../
