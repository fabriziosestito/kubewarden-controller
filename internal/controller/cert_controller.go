package controller

import (
	"context"
	"fmt"
	"time"

	"github.com/go-logr/logr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type CertController struct {
	client.Client
	Log logr.Logger
}

// Start begins the periodic reconciler
func (r *CertController) Start(ctx context.Context) error {
	r.Log.Info("Starting CertController ticker")

	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			r.Log.Info("Stopping periodic reconciler")
			return nil
		case <-ticker.C:
			if err := r.reconcile(ctx); err != nil {
				r.Log.Error(err, "Failed to reconcile")
			}
		}
	}
}

func (r *CertController) NeedLeaderElection() bool {
	return true
}

func (r *CertController) SetupWithManager(mgr ctrl.Manager) error {
	if err := mgr.Add(r); err != nil {
		return fmt.Errorf("failed enrolling controller with manager: %w", err)
	}

	return nil
}

// reconcile performs the periodic reconciliation logic
func (r *CertController) reconcile(_ context.Context) error {
	// Add your reconciliation logic here

	return nil
}
