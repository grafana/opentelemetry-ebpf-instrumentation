// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ecs

import (
	"context"
	"fmt"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsecs "github.com/aws/aws-sdk-go-v2/service/ecs"
	"github.com/aws/aws-sdk-go-v2/service/ecs/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakeClient struct {
	taskARNs      []string
	tasksByARN    map[string]types.Task
	describeCalls int
	listStatus    types.DesiredStatus
}

func (f *fakeClient) ListTasks(_ context.Context, input *awsecs.ListTasksInput, _ ...func(*awsecs.Options)) (*awsecs.ListTasksOutput, error) {
	f.listStatus = input.DesiredStatus
	if input.NextToken == nil {
		middle := len(f.taskARNs) / 2
		return &awsecs.ListTasksOutput{TaskArns: f.taskARNs[:middle], NextToken: aws.String("next")}, nil
	}
	return &awsecs.ListTasksOutput{TaskArns: f.taskARNs[len(f.taskARNs)/2:]}, nil
}

func (f *fakeClient) DescribeTasks(_ context.Context, input *awsecs.DescribeTasksInput, _ ...func(*awsecs.Options)) (*awsecs.DescribeTasksOutput, error) {
	f.describeCalls++
	out := &awsecs.DescribeTasksOutput{}
	for _, arn := range input.Tasks {
		out.Tasks = append(out.Tasks, f.tasksByARN[arn])
	}
	return out, nil
}

func TestInventoryRefresh(t *testing.T) {
	client := &fakeClient{tasksByARN: map[string]types.Task{}}
	for index := range 101 {
		arn := fmt.Sprintf("task-%d", index)
		client.taskARNs = append(client.taskARNs, arn)
		client.tasksByARN[arn] = ecsServiceTask(fmt.Sprintf("10.0.0.%d", index+1), "service-a")
	}
	inventory := NewInventory(client, "cluster")

	require.NoError(t, inventory.Refresh(t.Context()))
	assert.Equal(t, types.DesiredStatusRunning, client.listStatus)
	assert.Equal(t, 2, client.describeCalls)
	name, ok := inventory.ServiceNameForIP("10.0.0.101")
	assert.True(t, ok)
	assert.Equal(t, "service-a", name)

	client.taskARNs = []string{"replacement"}
	client.tasksByARN = map[string]types.Task{
		"replacement": ecsServiceTask("10.1.0.1", "service-b"),
	}
	require.NoError(t, inventory.Refresh(t.Context()))
	_, ok = inventory.ServiceNameForIP("10.0.0.101")
	assert.False(t, ok)
	name, ok = inventory.ServiceNameForIP("10.1.0.1")
	assert.True(t, ok)
	assert.Equal(t, "service-b", name)
}

func TestInventorySkipsStandaloneTasks(t *testing.T) {
	client := &fakeClient{
		taskARNs: []string{"standalone"},
		tasksByARN: map[string]types.Task{
			"standalone": {
				Group:       aws.String("family:batch-job"),
				Attachments: taskAttachment("10.2.0.1"),
			},
		},
	}
	inventory := NewInventory(client, "cluster")

	require.NoError(t, inventory.Refresh(t.Context()))
	_, ok := inventory.ServiceNameForIP("10.2.0.1")
	assert.False(t, ok)
}

func ecsServiceTask(ip, name string) types.Task {
	return types.Task{
		Group:       aws.String("service:" + name),
		Attachments: taskAttachment(ip),
	}
}

func taskAttachment(ip string) []types.Attachment {
	return []types.Attachment{{
		Details: []types.KeyValuePair{{
			Name:  aws.String("privateIPv4Address"),
			Value: aws.String(ip),
		}},
	}}
}
