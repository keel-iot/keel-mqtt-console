package main

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/keel-iot/keel-mqtt-console/internal/auth"
	"github.com/keel-iot/keel-mqtt-console/internal/broker"
	"github.com/keel-iot/keel-mqtt-console/internal/config"
	"github.com/keel-iot/keel-mqtt-console/internal/httpapi"
	"github.com/keel-iot/keel-mqtt-console/internal/store"
)

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	slog.SetDefault(log)
	cfg, err := config.Load()
	if err != nil {
		log.Error("invalid configuration", "error", err)
		os.Exit(1)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	db, err := store.Open(ctx, cfg.DatabaseURL)
	if err != nil {
		log.Error("open console database", "error", err)
		os.Exit(1)
	}
	defer db.Pool.Close()
	a, err := auth.New(ctx, cfg, db)
	if err != nil {
		log.Error("initialize authentication", "error", err)
		os.Exit(1)
	}
	if err := a.BootstrapLocal(ctx); err != nil {
		log.Error("initialize local authentication", "error", err)
		os.Exit(1)
	}
	b := broker.New(cfg.BrokerManagementURL)
	app := httpapi.New(cfg, a, b, db)
	srv := &http.Server{Addr: cfg.Addr, Handler: app.Handler(), ReadTimeout: 10 * time.Second, WriteTimeout: 15 * time.Second, IdleTimeout: 60 * time.Second}
	go func() {
		log.Info("console listening", "addr", cfg.Addr, "auth_mode", cfg.AuthMode)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Error("console server failed", "error", err)
			stop()
		}
	}()
	<-ctx.Done()
	shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = srv.Shutdown(shutdown)
}
