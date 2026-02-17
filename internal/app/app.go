package app

import (
	"log/slog"
	grpcapp "sso/internal/app/grpc"
	"time"
)

type App struct {
	GRPCSer *grpcapp.App
}

func New(log slog.Logger,
	grpcPort int,
	storagePath string,
	tokenTTL time.Duration,
) *App {
	// TODO: init storage

	// TODO: init auth servise (auth)
	grpcApp := grpcapp.New(log, grpcPort)

	return &App{
		GRPCSer: grpcApp,
	}
}
