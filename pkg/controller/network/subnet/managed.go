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

package subnet

import (
	"context"

	azurenetwork "github.com/Azure/azure-sdk-for-go/services/network/mgmt/2019-06-01/network"
	"github.com/Azure/azure-sdk-for-go/services/network/mgmt/2019-06-01/network/networkapi"
	"github.com/pkg/errors"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	xpv1 "github.com/crossplane/crossplane-runtime/apis/common/v1"
	"github.com/crossplane/crossplane-runtime/pkg/connection"
	"github.com/crossplane/crossplane-runtime/pkg/controller"
	"github.com/crossplane/crossplane-runtime/pkg/event"
	"github.com/crossplane/crossplane-runtime/pkg/meta"
	"github.com/crossplane/crossplane-runtime/pkg/reconciler/managed"
	"github.com/crossplane/crossplane-runtime/pkg/resource"

	"github.com/crossplane/provider-azure/apis/network/v1alpha3"
	"github.com/crossplane/provider-azure/apis/v1alpha1"
	azureclients "github.com/crossplane/provider-azure/pkg/clients"
	"github.com/crossplane/provider-azure/pkg/clients/network"
	"github.com/crossplane/provider-azure/pkg/features"
)

// Error strings.
const (
	errNotSubnet    = "managed resource is not an Subnet"
	errCreateSubnet = "cannot create Subnet"
	errUpdateSubnet = "cannot update Subnet"
	errGetSubnet    = "cannot get Subnet"
	errDeleteSubnet = "cannot delete Subnet"
)

// Setup adds a controller that reconciles Subnets.
func Setup(mgr ctrl.Manager, o controller.Options) error {
	name := managed.ControllerName(v1alpha3.SubnetGroupKind)

	cps := []managed.ConnectionPublisher{managed.NewAPISecretPublisher(mgr.GetClient(), mgr.GetScheme())}
	if o.Features.Enabled(features.EnableAlphaExternalSecretStores) {
		cps = append(cps, connection.NewDetailsManager(mgr.GetClient(), v1alpha1.StoreConfigGroupVersionKind))
	}

	return ctrl.NewControllerManagedBy(mgr).
		Named(name).
		WithOptions(o.ForControllerRuntime()).
		For(&v1alpha3.Subnet{}).
		Complete(managed.NewReconciler(mgr,
			resource.ManagedKind(v1alpha3.SubnetGroupVersionKind),
			managed.WithConnectionPublishers(),
			managed.WithExternalConnecter(&connecter{client: mgr.GetClient()}),
			managed.WithReferenceResolver(managed.NewAPISimpleReferenceResolver(mgr.GetClient())),
			managed.WithPollInterval(o.PollInterval),
			managed.WithLogger(o.Logger.WithValues("controller", name)),
			managed.WithRecorder(event.NewAPIRecorder(mgr.GetEventRecorderFor(name))),
			managed.WithConnectionPublishers(cps...)))
}

type connecter struct {
	client client.Client
}

func (c *connecter) Connect(ctx context.Context, mg resource.Managed) (managed.ExternalClient, error) {
	creds, auth, err := azureclients.GetAuthInfo(ctx, c.client, mg)
	if err != nil {
		return nil, err
	}
	cl := azurenetwork.NewSubnetsClient(creds[azureclients.CredentialsKeySubscriptionID])
	cl.Authorizer = auth
	return &external{client: cl}, nil
}

type external struct{ client networkapi.SubnetsClientAPI }

func (e *external) Observe(ctx context.Context, mg resource.Managed) (managed.ExternalObservation, error) {
	s, ok := mg.(*v1alpha3.Subnet)
	if !ok {
		return managed.ExternalObservation{}, errors.New(errNotSubnet)
	}

	az, err := e.client.Get(ctx, s.Spec.ResourceGroupName, s.Spec.VirtualNetworkName, meta.GetExternalName(s), "")
	if azureclients.IsNotFound(err) {
		return managed.ExternalObservation{ResourceExists: false}, nil
	}
	if err != nil {
		return managed.ExternalObservation{}, errors.Wrap(err, errGetSubnet)
	}

	network.UpdateSubnetStatusFromAzure(s, az)
	s.SetConditions(xpv1.Available())

	o := managed.ExternalObservation{
		ResourceExists:    true,
		ConnectionDetails: managed.ConnectionDetails{},
	}

	return o, nil
}

func (e *external) Create(ctx context.Context, mg resource.Managed) (managed.ExternalCreation, error) {
	s, ok := mg.(*v1alpha3.Subnet)
	if !ok {
		return managed.ExternalCreation{}, errors.New(errNotSubnet)
	}

	s.Status.SetConditions(xpv1.Creating())

	snet := network.NewSubnetParameters(s)
	if _, err := e.client.CreateOrUpdate(ctx, s.Spec.ResourceGroupName, s.Spec.VirtualNetworkName, meta.GetExternalName(s), snet); err != nil {
		return managed.ExternalCreation{}, errors.Wrap(err, errCreateSubnet)
	}

	return managed.ExternalCreation{}, nil
}

func (e *external) Update(ctx context.Context, mg resource.Managed) (managed.ExternalUpdate, error) {
	s, ok := mg.(*v1alpha3.Subnet)
	if !ok {
		return managed.ExternalUpdate{}, errors.New(errNotSubnet)
	}

	az, err := e.client.Get(ctx, s.Spec.ResourceGroupName, s.Spec.VirtualNetworkName, meta.GetExternalName(s), "")
	if err != nil {
		return managed.ExternalUpdate{}, errors.Wrap(err, errGetSubnet)
	}

	if network.SubnetNeedsUpdate(s, az) {
		snet := network.NewSubnetParameters(s)
		if _, err := e.client.CreateOrUpdate(ctx, s.Spec.ResourceGroupName, s.Spec.VirtualNetworkName, meta.GetExternalName(s), snet); err != nil {
			return managed.ExternalUpdate{}, errors.Wrap(err, errUpdateSubnet)
		}
	}
	return managed.ExternalUpdate{}, nil
}

func (e *external) Delete(ctx context.Context, mg resource.Managed) error {
	s, ok := mg.(*v1alpha3.Subnet)
	if !ok {
		return errors.New(errNotSubnet)
	}

	mg.SetConditions(xpv1.Deleting())

	_, err := e.client.Delete(ctx, s.Spec.ResourceGroupName, s.Spec.VirtualNetworkName, meta.GetExternalName(s))
	return errors.Wrap(resource.Ignore(azureclients.IsNotFound, err), errDeleteSubnet)
}
