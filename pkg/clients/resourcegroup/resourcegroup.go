/*
Copyright 2019 The Crossplane Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package resourcegroup

import (
	"context"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armresources"
	"github.com/crossplane/crossplane-runtime/pkg/meta"

	"github.com/crossplane/provider-azure/apis/v1alpha3"
	azure "github.com/crossplane/provider-azure/pkg/clients"
)

// A GroupsClient handles CRUD operations for Azure Resource Group resources.
type GroupsClient interface {
	CreateOrUpdate(ctx context.Context, resourceGroupName string, parameters armresources.ResourceGroup, options *armresources.ResourceGroupsClientCreateOrUpdateOptions) (armresources.ResourceGroupsClientCreateOrUpdateResponse, error)
	CheckExistence(ctx context.Context, resourceGroupName string, options *armresources.ResourceGroupsClientCheckExistenceOptions) (armresources.ResourceGroupsClientCheckExistenceResponse, error)
	Get(ctx context.Context, resourceGroupName string, options *armresources.ResourceGroupsClientGetOptions) (armresources.ResourceGroupsClientGetResponse, error)
	BeginDelete(ctx context.Context, resourceGroupName string, options *armresources.ResourceGroupsClientBeginDeleteOptions) (armresources.ResourceGroupsClientDeletePollerResponse, error)
}

// NewParameters returns Resource Group resource creation parameters suitable for
// use with the Azure API.
func NewParameters(r *v1alpha3.ResourceGroup) armresources.ResourceGroup {
	return armresources.ResourceGroup{
		Name:     azure.ToStringPtr(meta.GetExternalName(r)),
		Location: azure.ToStringPtr(r.Spec.Location),
	}
}
