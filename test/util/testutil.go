/*
Copyright 2021 The cert-manager Authors.

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

package util

import (
	"context"
	"fmt"
	"testing"
	"time"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	cmclient "github.com/cert-manager/cert-manager/pkg/client/clientset/versioned"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
)

func waitAndGetOneCertificateRequestInNamespace(ctx context.Context, client cmclient.Interface, ns string) (*cmapi.CertificateRequest, error) {
	var req *cmapi.CertificateRequest
	if err := wait.PollUntilWithContext(ctx, time.Millisecond*50, func(ctx context.Context) (done bool, err error) {
		reqs, err := client.CertmanagerV1().CertificateRequests(ns).List(ctx, metav1.ListOptions{})
		if err != nil {
			return false, err
		}
		if len(reqs.Items) == 0 {
			return false, nil
		}
		if len(reqs.Items) > 1 {
			return false, fmt.Errorf("more than one CertificateRequest created")
		}

		req = &reqs.Items[0]
		return true, nil
	}); err != nil {
		return nil, err
	}
	return req, nil
}

func IssueOneRequest(t *testing.T, client cmclient.Interface, namespace string, stopCh <-chan struct{}, cert, ca []byte) {
	if err := wait.PollUntil(time.Millisecond*50, func() (done bool, err error) {
		req, err := waitAndGetOneCertificateRequestInNamespace(context.TODO(), client, namespace)
		if err != nil {
			return false, err
		}

		csr := req.DeepCopy()
		csr.Status.Conditions = append(req.Status.Conditions, cmapi.CertificateRequestCondition{
			Type:    cmapi.CertificateRequestConditionReady,
			Status:  cmmeta.ConditionTrue,
			Reason:  cmapi.CertificateRequestReasonIssued,
			Message: "Issued by test",
		})
		csr.Status.Certificate = cert
		csr.Status.CA = ca
		_, err = client.CertmanagerV1().CertificateRequests(namespace).UpdateStatus(context.TODO(), csr, metav1.UpdateOptions{})
		if err != nil {
			return false, fmt.Errorf("error updating certificaterequest status: %v", err)
		}
		return true, nil
	}, stopCh); err != nil {
		t.Errorf("error automatically issuing certificaterequest: %v", err)
	}
}

func SetCertificateRequestConditions(ctx context.Context, t *testing.T, client cmclient.Interface, namespace string, conditions ...cmapi.CertificateRequestCondition) {
	if err := wait.PollUntilWithContext(ctx, time.Millisecond*50, func(ctx context.Context) (done bool, err error) {
		req, err := waitAndGetOneCertificateRequestInNamespace(context.TODO(), client, namespace)
		if err != nil {
			return false, err
		}

		reqCopy := req.DeepCopy()
		for _, cond := range conditions {
			setCertificateRequestCondition(reqCopy, cond)
		}

		req, err = client.CertmanagerV1().CertificateRequests(namespace).UpdateStatus(ctx, reqCopy, metav1.UpdateOptions{})
		if err != nil {
			return false, err
		}

		return true, nil
	}); err != nil {
		t.Errorf("error automatically setting certificaterequest condition")
	}
}

func SetOneCertificateRequestCondition(ctx context.Context, t *testing.T, client cmclient.Interface, namespace string, condition cmapi.CertificateRequestCondition) {
	SetCertificateRequestConditions(ctx, t, client, namespace, condition)
}

func setCertificateRequestCondition(req *cmapi.CertificateRequest, newCondition cmapi.CertificateRequestCondition) {
	for i, cond := range req.Status.Conditions {
		if cond.Type == newCondition.Type {
			req.Status.Conditions[i] = newCondition
			return
		}
	}
	req.Status.Conditions = append(req.Status.Conditions, newCondition)
}

func IssueAllRequests(t *testing.T, client cmclient.Interface, namespace string, stopCh <-chan struct{}, cert, ca []byte) {
	wait.Until(func() {
		reqs, err := client.CertmanagerV1().CertificateRequests(namespace).List(context.TODO(), metav1.ListOptions{})
		if err != nil {
			t.Fatal(err)
		}

		for _, req := range reqs.Items {
			if len(req.Status.Certificate) != 0 {
				continue
			}

			csr := req.DeepCopy()
			csr.Status.Conditions = append(req.Status.Conditions, cmapi.CertificateRequestCondition{
				Type:    cmapi.CertificateRequestConditionReady,
				Status:  cmmeta.ConditionTrue,
				Reason:  cmapi.CertificateRequestReasonIssued,
				Message: "Issued by test",
			})

			csr.Status.Certificate = cert
			csr.Status.CA = ca
			_, err = client.CertmanagerV1().CertificateRequests(namespace).UpdateStatus(context.TODO(), csr, metav1.UpdateOptions{})
			if err != nil {
				t.Fatal(err)
			}
		}

	}, time.Millisecond*50, stopCh)
}
