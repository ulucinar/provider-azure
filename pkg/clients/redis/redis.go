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

package redis

import (
	"context"
	"reflect"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/redis/armredis"
	"github.com/Azure/azure-sdk-for-go/services/redis/mgmt/2018-03-01/redis"

	"github.com/crossplane/provider-azure/apis/cache/v1beta1"
	azure "github.com/crossplane/provider-azure/pkg/clients"
)

// Resource states
const (
	ProvisioningStateCreating  = string(armredis.ProvisioningStateCreating)
	ProvisioningStateDeleting  = string(armredis.ProvisioningStateDeleting)
	ProvisioningStateFailed    = string(armredis.ProvisioningStateFailed)
	ProvisioningStateSucceeded = string(armredis.ProvisioningStateSucceeded)
)

type ClientAPI interface {
	BeginCreate(ctx context.Context, resourceGroupName string, name string, parameters armredis.CreateParameters, options *armredis.ClientBeginCreateOptions) (armredis.ClientCreatePollerResponse, error)
	BeginDelete(ctx context.Context, resourceGroupName string, name string, options *armredis.ClientBeginDeleteOptions) (armredis.ClientDeletePollerResponse, error)
	Get(ctx context.Context, resourceGroupName string, name string, options *armredis.ClientGetOptions) (armredis.ClientGetResponse, error)
	ListKeys(ctx context.Context, resourceGroupName string, name string, options *armredis.ClientListKeysOptions) (armredis.ClientListKeysResponse, error)
	Update(ctx context.Context, resourceGroupName string, name string, parameters armredis.UpdateParameters, options *armredis.ClientUpdateOptions) (armredis.ClientUpdateResponse, error)
}

// NewCreateParameters returns Redis resource creation parameters suitable for
// use with the Azure API.
func NewCreateParameters(cr *v1beta1.Redis) armredis.CreateParameters {

	return armredis.CreateParameters{
		Location: azure.ToStringPtr(cr.Spec.ForProvider.Location),
		Zones:    azure.ToArrayOfStringPointers(cr.Spec.ForProvider.Zones),
		Tags:     azure.ToStringPtrMap(cr.Spec.ForProvider.Tags),
		Properties: &armredis.CreateProperties{
			SKU:                NewSKU(cr.Spec.ForProvider.SKU),
			SubnetID:           cr.Spec.ForProvider.SubnetID,
			StaticIP:           cr.Spec.ForProvider.StaticIP,
			EnableNonSSLPort:   cr.Spec.ForProvider.EnableNonSSLPort,
			RedisConfiguration: toCommonPropertiesRedisConfiguration(cr.Spec.ForProvider.RedisConfiguration),
			TenantSettings:     azure.ToStringPtrMap(cr.Spec.ForProvider.TenantSettings),
			ShardCount:         azure.ToInt32(cr.Spec.ForProvider.ShardCount),
			MinimumTLSVersion:  toTLSVersion(cr.Spec.ForProvider.MinimumTLSVersion),
		},
	}
}

// NewUpdateParameters returns a redis.UpdateParameters object only with changed
// fields.
// TODO(muvaf): Removal of an entry from the maps such as RedisConfiguration and
// TenantSettings is not properly supported. The user has to give empty string
// for deletion instead of just deleting the whole entry.
// NOTE(muvaf): This is barely a comparison function with almost identical if
// statements which increase the cyclomatic complexity even though it's actually
// easier to maintain all this in one function.
// nolint:gocyclo
func NewUpdateParameters(spec v1beta1.RedisParameters, state armredis.ResourceInfo) armredis.UpdateParameters {
	patch := armredis.UpdateParameters{
		Tags: azure.ToStringPtrMap(spec.Tags),
		Properties: &armredis.UpdateProperties{
			SKU:                NewSKU(spec.SKU),
			RedisConfiguration: toCommonPropertiesRedisConfiguration(spec.RedisConfiguration),
			EnableNonSSLPort:   spec.EnableNonSSLPort,
			ShardCount:         azure.ToInt32(spec.ShardCount),
			TenantSettings:     azure.ToStringPtrMap(spec.TenantSettings),
			MinimumTLSVersion:  toTLSVersion(spec.MinimumTLSVersion),
		},
	}
	// NOTE(muvaf): One could possibly generate UpdateParameters object from
	// ResourceType and extract a JSON patch. But since the number of fields
	// are not that many, I wanted to go with if statements. Hopefully, we'll
	// generate this code in the future.
	for k, v := range state.Tags {
		if patch.Tags[k] == v {
			delete(patch.Tags, k)
		}
	}
	if len(patch.Tags) == 0 {
		patch.Tags = nil
	}
	if state.Properties == nil {
		return patch
	}
	if reflect.DeepEqual(patch.Properties.SKU, state.Properties.SKU) {
		patch.Properties.SKU = nil
	}
	if reflect.DeepEqual(patch.Properties.RedisConfiguration, state.Properties.RedisConfiguration) {
		patch.Properties.RedisConfiguration = nil
	}
	if reflect.DeepEqual(patch.Properties.EnableNonSSLPort, state.Properties.EnableNonSSLPort) {
		patch.Properties.EnableNonSSLPort = nil
	}
	if reflect.DeepEqual(patch.Properties.ShardCount, state.Properties.ShardCount) {
		patch.Properties.ShardCount = nil
	}
	for k, v := range state.Properties.TenantSettings {
		if reflect.DeepEqual(patch.Properties.TenantSettings[k], v) {
			delete(patch.Properties.TenantSettings, k)
		}
	}
	if len(patch.Properties.TenantSettings) == 0 {
		patch.Properties.TenantSettings = nil
	}
	if reflect.DeepEqual(patch.Properties.MinimumTLSVersion, state.Properties.MinimumTLSVersion) {
		patch.Properties.MinimumTLSVersion = nil
	}
	return patch
}

// NewSKU returns a Redis resource SKU suitable for use with the Azure API.
func NewSKU(s v1beta1.SKU) *armredis.SKU {
	n := armredis.SKUName(s.Name)
	f := armredis.SKUFamily(s.Family)
	return &armredis.SKU{
		Name:     &n,
		Family:   &f,
		Capacity: azure.ToInt32Ptr(s.Capacity, azure.FieldRequired),
	}
}

// NeedsUpdate returns true if the supplied spec object differs from the
// supplied Azure resource. It considers only fields that can be modified in
// place without deleting and recreating the instance.
func NeedsUpdate(spec v1beta1.RedisParameters, az armredis.ResourceInfo) bool {
	if az.Properties == nil {
		return true
	}
	patch := NewUpdateParameters(spec, az)
	empty := redis.UpdateParameters{UpdateProperties: &redis.UpdateProperties{}}
	return !reflect.DeepEqual(empty, patch)
}

// GenerateObservation produces a RedisObservation object from the redis.ResourceType
// received from Azure.
func GenerateObservation(az armredis.ResourceInfo) v1beta1.RedisObservation {
	o := v1beta1.RedisObservation{
		ID:   azure.ToString(az.ID),
		Name: azure.ToString(az.Name),
	}
	if az.Properties == nil {
		return o
	}
	o.RedisVersion = azure.ToString(az.Properties.RedisVersion)
	if az.Properties.ProvisioningState != nil {
		o.ProvisioningState = string(*az.Properties.ProvisioningState)
	}
	o.HostName = azure.ToString(az.Properties.HostName)
	o.Port = azure.ToInt(az.Properties.Port)
	o.SSLPort = azure.ToInt(az.Properties.SSLPort)
	if az.Properties.LinkedServers != nil {
		o.LinkedServers = make([]string, len(az.Properties.LinkedServers))
		for i, val := range az.Properties.LinkedServers {
			o.LinkedServers[i] = azure.ToString(val.ID)
		}
	}
	return o
}

// LateInitialize fills the spec values that user did not fill with their
// corresponding value in the Azure, if there is any.
func LateInitialize(spec *v1beta1.RedisParameters, az armredis.ResourceInfo) {
	spec.Zones = azure.LateInitializeStringValArrFromPtrArr(spec.Zones, az.Zones)
	spec.Tags = azure.LateInitializeStringMap(spec.Tags, az.Tags)
	if az.Properties == nil {
		return
	}
	spec.SubnetID = azure.LateInitializeStringPtrFromPtr(spec.SubnetID, az.Properties.SubnetID)
	spec.StaticIP = azure.LateInitializeStringPtrFromPtr(spec.StaticIP, az.Properties.StaticIP)
	spec.RedisConfiguration = lateInitializeFromCommonPropertiesRedisConfiguration(spec.RedisConfiguration, az.Properties.RedisConfiguration)
	spec.EnableNonSSLPort = azure.LateInitializeBoolPtrFromPtr(spec.EnableNonSSLPort, az.Properties.EnableNonSSLPort)
	spec.TenantSettings = azure.LateInitializeStringMap(spec.TenantSettings, az.Properties.TenantSettings)
	spec.ShardCount = azure.LateInitializeIntPtrFromInt32Ptr(spec.ShardCount, az.Properties.ShardCount)
	var minTLS *string
	if az.Properties.MinimumTLSVersion != nil {
		s := string(*az.Properties.MinimumTLSVersion)
		minTLS = &s
	}
	spec.MinimumTLSVersion = azure.LateInitializeStringPtrFromPtr(spec.MinimumTLSVersion, minTLS)
}

// toCommonPropertiesRedisConfiguration converts a map[string]string to a
// armredis.CommonPropertiesRedisConfiguration by setting the corresponding
// fields from map values
func toCommonPropertiesRedisConfiguration(props map[string]string) *armredis.CommonPropertiesRedisConfiguration {
	c := &armredis.CommonPropertiesRedisConfiguration{}
	additionalProps := make(map[string]interface{}, len(props))
	for k, v := range props {
		v := v
		switch k {
		case "aof-storage-connection-string-0":
			c.AofStorageConnectionString0 = &v
		case "aof-storage-connection-string-1":
			c.AofStorageConnectionString1 = &v
		case "maxfragmentationmemory-reserved":
			c.MaxfragmentationmemoryReserved = &v
		case "maxmemory-delta":
			c.MaxmemoryDelta = &v
		case "maxmemory-policy":
			c.MaxmemoryPolicy = &v
		case "maxmemory-reserved":
			c.MaxmemoryReserved = &v
		case "rdb-backup-enabled":
			c.RdbBackupEnabled = &v
		case "rdb-backup-frequency":
			c.RdbBackupFrequency = &v
		case "rdb-backup-max-snapshot-count":
			c.RdbBackupMaxSnapshotCount = &v
		case "rdb-storage-connection-string":
			c.RdbStorageConnectionString = &v
		case "maxclients", "preferred-data-archive-auth-method", "preferred-data-persistence-auth-method":
			// read-only properties are ignored
		default: // if key is not found, put it into additional props
			additionalProps[k] = &v
		}
	}
	c.AdditionalProperties = additionalProps
	return c
}

func lateInitializeFromCommonPropertiesRedisConfiguration(p map[string]string, c *armredis.CommonPropertiesRedisConfiguration) map[string]string {
	if p != nil || c == nil {
		return p
	}
	p = make(map[string]string)
	for k, v := range c.AdditionalProperties {
		if s, ok := v.(string); ok {
			p[k] = s
			continue
		}
		if s, ok := v.(*string); ok {
			p[k] = *s
		}
	}

	if c.AofStorageConnectionString0 != nil {
		p["aof-storage-connection-string-0"] = *c.AofStorageConnectionString0
	}
	if c.AofStorageConnectionString1 != nil {
		p["aof-storage-connection-string-1"] = *c.AofStorageConnectionString1
	}
	if c.MaxfragmentationmemoryReserved != nil {
		p["maxfragmentationmemory-reserved"] = *c.MaxfragmentationmemoryReserved
	}
	if c.MaxmemoryDelta != nil {
		p["maxmemory-delta"] = *c.MaxmemoryDelta
	}
	if c.MaxmemoryPolicy != nil {
		p["maxmemory-policy"] = *c.MaxmemoryPolicy
	}
	if c.MaxmemoryReserved != nil {
		p["maxmemory-reserved"] = *c.MaxmemoryReserved
	}
	if c.RdbBackupEnabled != nil {
		p["rdb-backup-enabled"] = *c.RdbBackupEnabled
	}
	if c.RdbBackupFrequency != nil {
		p["rdb-backup-frequency"] = *c.RdbBackupFrequency
	}
	if c.RdbBackupMaxSnapshotCount != nil {
		p["rdb-backup-max-snapshot-count"] = *c.RdbBackupMaxSnapshotCount
	}
	if c.RdbStorageConnectionString != nil {
		p["rdb-storage-connection-string"] = *c.RdbStorageConnectionString
	}
	return p
}

func toTLSVersion(tlsVersion *string) *armredis.TLSVersion {
	v := armredis.TLSVersion(azure.ToString(tlsVersion))
	return &v
}
