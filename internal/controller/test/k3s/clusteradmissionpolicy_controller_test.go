/*
Copyright 2022.

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

//nolint:dupl
package k3s

import (
	"context"

	. "github.com/onsi/ginkgo/v2" //nolint:revive
	. "github.com/onsi/gomega"    //nolint:revive

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"

	policiesv1 "github.com/kubewarden/kubewarden-controller/api/policies/v1"
	"github.com/kubewarden/kubewarden-controller/internal/constants"
	. "github.com/kubewarden/kubewarden-controller/internal/controller/test"
)

var _ = Describe("ClusterAdmissionPolicy controller", func() {
	ctx := context.Background()

	When("creating a validating ClusterAdmissionPolicy", Ordered, func() {
		var policyServerName string
		var policyName string
		var policy *policiesv1.ClusterAdmissionPolicy

		BeforeAll(func() {
			policyServerName = NewName("policy-server")
			CreatePolicyServerAndWaitForItsService(k8sClient, PolicyServerFactory(policyServerName))

			policyName = NewName("validating-policy")
			policy = ClusterAdmissionPolicyFactory(policyName, policyServerName, false)
			Expect(k8sClient.Create(ctx, policy)).To(Succeed())
		})

		It("should set the ClusterAdmissionPolicy to active", func() {
			By("changing the policy status to pending")
			Eventually(func() (*policiesv1.ClusterAdmissionPolicy, error) {
				return GetTestClusterAdmissionPolicy(k8sClient, policyName)
			}, timeout, pollInterval).Should(
				HaveField("Status.PolicyStatus", Equal(policiesv1.PolicyStatusPending)),
			)

			By("changing the policy status to active")
			Eventually(func() (*policiesv1.ClusterAdmissionPolicy, error) {
				return GetTestClusterAdmissionPolicy(k8sClient, policyName)
			}, timeout, pollInterval).Should(
				HaveField("Status.PolicyStatus", Equal(policiesv1.PolicyStatusActive)),
			)
		})

		It("should create the ValidatingWebhookConfiguration", func() {
			Eventually(func() error {
				validatingWebhookConfiguration, err := GetTestValidatingWebhookConfiguration(k8sClient, policy.GetUniqueName())
				if err != nil {
					return err
				}

				Expect(validatingWebhookConfiguration.Labels["kubewarden"]).To(Equal("true"))
				Expect(validatingWebhookConfiguration.Labels[constants.WebhookConfigurationPolicyScopeLabelKey]).To(Equal("cluster"))
				Expect(validatingWebhookConfiguration.Annotations[constants.WebhookConfigurationPolicyNameAnnotationKey]).To(Equal(policyName))
				Expect(validatingWebhookConfiguration.Annotations[constants.WebhookConfigurationPolicyNamespaceAnnotationKey]).To(BeEmpty())
				Expect(validatingWebhookConfiguration.Webhooks).To(HaveLen(1))
				Expect(validatingWebhookConfiguration.Webhooks[0].ClientConfig.Service.Name).To(Equal("policy-server-" + policyServerName))

				caSecret, err := GetTestCASecret(k8sClient)
				Expect(err).ToNot(HaveOccurred())
				Expect(validatingWebhookConfiguration.Webhooks[0].ClientConfig.CABundle).To(Equal(caSecret.Data[constants.PolicyServerCARootPemName]))

				return nil
			}, timeout, pollInterval).Should(Succeed())
		})

		It("should be reconcile the ValidationWebhookConfiguration to the original state after some change", func() {
			By("changing the ValidatingWebhookConfiguration")
			var originalValidatingWebhookConfiguration *admissionregistrationv1.ValidatingWebhookConfiguration
			var validatingWebhookConfiguration *admissionregistrationv1.ValidatingWebhookConfiguration
			Eventually(func() error {
				var err error
				validatingWebhookConfiguration, err = GetTestValidatingWebhookConfiguration(k8sClient, policy.GetUniqueName())
				if err != nil {
					return err
				}
				originalValidatingWebhookConfiguration = validatingWebhookConfiguration.DeepCopy()
				return nil
			}, timeout, pollInterval).Should(Succeed())

			delete(validatingWebhookConfiguration.Labels, "kubewarden")
			validatingWebhookConfiguration.Labels[constants.WebhookConfigurationPolicyScopeLabelKey] = NewName("scope")
			delete(validatingWebhookConfiguration.Annotations, constants.WebhookConfigurationPolicyNameAnnotationKey)
			validatingWebhookConfiguration.Annotations[constants.WebhookConfigurationPolicyNamespaceAnnotationKey] = NewName("namespace")
			validatingWebhookConfiguration.Webhooks[0].ClientConfig.Service.Name = NewName("service")
			validatingWebhookConfiguration.Webhooks[0].ClientConfig.CABundle = []byte("invalid")
			Expect(
				k8sClient.Update(ctx, validatingWebhookConfiguration),
			).To(Succeed())

			By("reconciling the ValidatingWebhookConfiguration to its original state")
			Eventually(func() (*admissionregistrationv1.ValidatingWebhookConfiguration, error) {
				return GetTestValidatingWebhookConfiguration(k8sClient, policy.GetUniqueName())
			}, timeout, pollInterval).Should(
				And(
					HaveField("Labels", Equal(originalValidatingWebhookConfiguration.Labels)),
					HaveField("Annotations", Equal(originalValidatingWebhookConfiguration.Annotations)),
					HaveField("Webhooks", Equal(originalValidatingWebhookConfiguration.Webhooks)),
				),
			)
		})
	})

	When("creating a mutating ClusterAdmissionPolicy", Ordered, func() {
		var policyServerName string
		var policyName string
		var policy *policiesv1.ClusterAdmissionPolicy

		BeforeAll(func() {
			policyServerName = NewName("policy-server")
			CreatePolicyServerAndWaitForItsService(k8sClient, PolicyServerFactory(policyServerName))

			policyName = NewName("mutating-policy")
			policy = ClusterAdmissionPolicyFactory(policyName, policyServerName, true)
			Expect(k8sClient.Create(ctx, policy)).To(Succeed())
		})

		It("should set the AdmissionPolicy to active", func() {
			By("changing the policy status to pending")
			Eventually(func() (*policiesv1.ClusterAdmissionPolicy, error) {
				return GetTestClusterAdmissionPolicy(k8sClient, policyName)
			}, timeout, pollInterval).Should(
				HaveField("Status.PolicyStatus", Equal(policiesv1.PolicyStatusPending)),
			)

			By("changing the policy status to active")
			Eventually(func() (*policiesv1.ClusterAdmissionPolicy, error) {
				return GetTestClusterAdmissionPolicy(k8sClient, policyName)
			}, timeout, pollInterval).Should(
				HaveField("Status.PolicyStatus", Equal(policiesv1.PolicyStatusActive)),
			)
		})

		It("should create the MutatingWebhookConfiguration", func() {
			Eventually(func() error {
				mutatingWebhookConfiguration, err := GetTestMutatingWebhookConfiguration(k8sClient, policy.GetUniqueName())
				if err != nil {
					return err
				}
				Expect(mutatingWebhookConfiguration.Labels["kubewarden"]).To(Equal("true"))
				Expect(mutatingWebhookConfiguration.Labels[constants.WebhookConfigurationPolicyScopeLabelKey]).To(Equal("cluster"))
				Expect(mutatingWebhookConfiguration.Annotations[constants.WebhookConfigurationPolicyNameAnnotationKey]).To(Equal(policyName))
				Expect(mutatingWebhookConfiguration.Annotations[constants.WebhookConfigurationPolicyNamespaceAnnotationKey]).To(BeEmpty())
				Expect(mutatingWebhookConfiguration.Webhooks).To(HaveLen(1))
				Expect(mutatingWebhookConfiguration.Webhooks[0].ClientConfig.Service.Name).To(Equal("policy-server-" + policyServerName))

				caSecret, err := GetTestCASecret(k8sClient)
				Expect(err).ToNot(HaveOccurred())
				Expect(mutatingWebhookConfiguration.Webhooks[0].ClientConfig.CABundle).To(Equal(caSecret.Data[constants.PolicyServerCARootPemName]))

				return nil
			}, timeout, pollInterval).Should(Succeed())
		})

		It("should be reconcile the MutatingWebhookConfiguration to the original state after some change", func() {
			var originalMutatingWebhookConfiguration *admissionregistrationv1.MutatingWebhookConfiguration
			var mutatingWebhookConfiguration *admissionregistrationv1.MutatingWebhookConfiguration
			Eventually(func() error {
				var err error
				mutatingWebhookConfiguration, err = GetTestMutatingWebhookConfiguration(k8sClient, policy.GetUniqueName())
				if err != nil {
					return err
				}
				originalMutatingWebhookConfiguration = mutatingWebhookConfiguration.DeepCopy()
				return nil
			}, timeout, pollInterval).Should(Succeed())
			By("changing the MutatingWebhookConfiguration")

			delete(mutatingWebhookConfiguration.Labels, "kubewarden")
			mutatingWebhookConfiguration.Labels[constants.WebhookConfigurationPolicyScopeLabelKey] = NewName("scope")
			delete(mutatingWebhookConfiguration.Annotations, constants.WebhookConfigurationPolicyNameAnnotationKey)
			mutatingWebhookConfiguration.Annotations[constants.WebhookConfigurationPolicyNamespaceAnnotationKey] = NewName("namespace")
			mutatingWebhookConfiguration.Webhooks[0].ClientConfig.Service.Name = NewName("service")
			mutatingWebhookConfiguration.Webhooks[0].ClientConfig.CABundle = []byte("invalid")
			Expect(
				k8sClient.Update(ctx, mutatingWebhookConfiguration),
			).To(Succeed())

			By("reconciling the MutatingWebhookConfiguration to its original state")
			Eventually(func() (*admissionregistrationv1.MutatingWebhookConfiguration, error) {
				return GetTestMutatingWebhookConfiguration(k8sClient, "clusterwide-"+policyName)
			}, timeout, pollInterval).Should(
				And(
					HaveField("Labels", Equal(originalMutatingWebhookConfiguration.Labels)),
					HaveField("Annotations", Equal(originalMutatingWebhookConfiguration.Annotations)),
					HaveField("Webhooks", Equal(originalMutatingWebhookConfiguration.Webhooks)),
				),
			)
		})
	})

	It("should set policy status to unscheduled when creating an ClusterAdmissionPolicy without a PolicyServer assigned", func() {
		policyName := NewName("unscheduled-policy")
		Expect(
			k8sClient.Create(ctx, ClusterAdmissionPolicyFactory(policyName, "", false)),
		).To(HaveSucceededOrAlreadyExisted())

		Eventually(func() (*policiesv1.ClusterAdmissionPolicy, error) {
			return GetTestClusterAdmissionPolicy(k8sClient, policyName)
		}, timeout, pollInterval).Should(
			HaveField("Status.PolicyStatus", Equal(policiesv1.PolicyStatusUnscheduled)),
		)
	})

	When("creating a ClusterAdmissionPolicy with a PolicyServer assigned but not running yet", Ordered, func() {
		policyName := NewName("scheduled-policy")
		policyServerName := NewName("policy-server")

		BeforeAll(func() {
			Expect(
				k8sClient.Create(ctx, ClusterAdmissionPolicyFactory(policyName, policyServerName, false)),
			).To(HaveSucceededOrAlreadyExisted())
		})

		It("should set the policy status to scheduled", func() {
			Expect(
				k8sClient.Create(ctx, ClusterAdmissionPolicyFactory(policyName, policyServerName, false)),
			).To(HaveSucceededOrAlreadyExisted())

			Eventually(func() (*policiesv1.ClusterAdmissionPolicy, error) {
				return GetTestClusterAdmissionPolicy(k8sClient, policyName)
			}, timeout, pollInterval).Should(
				HaveField("Status.PolicyStatus", Equal(policiesv1.PolicyStatusScheduled)),
			)
		})

		It("should set the policy status to active when the PolicyServer is created", func() {
			By("creating the PolicyServer")
			Expect(
				k8sClient.Create(ctx, PolicyServerFactory(policyServerName)),
			).To(HaveSucceededOrAlreadyExisted())

			By("changing the policy status to pending")
			Eventually(func() (*policiesv1.ClusterAdmissionPolicy, error) {
				return GetTestClusterAdmissionPolicy(k8sClient, policyName)
			}, timeout, pollInterval).Should(
				HaveField("Status.PolicyStatus", Equal(policiesv1.PolicyStatusPending)),
			)

			By("changing the policy status to active")
			Eventually(func() (*policiesv1.ClusterAdmissionPolicy, error) {
				return GetTestClusterAdmissionPolicy(k8sClient, policyName)
			}, timeout, pollInterval).Should(
				HaveField("Status.PolicyStatus", Equal(policiesv1.PolicyStatusActive)),
			)
		})
	})
})
