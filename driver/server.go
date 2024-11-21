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

package driver

import (
	"context"
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/container-storage-interface/spec/lib/go/csi"
	"github.com/go-logr/logr"
	"github.com/kubernetes-csi/csi-lib-utils/protosanitizer"
	"google.golang.org/grpc"
)

type GRPCServer struct {
	server *grpc.Server
	lis    net.Listener
}

func NewGRPCServer(endpoint string, log logr.Logger, ids csi.IdentityServer, cs csi.ControllerServer, ns csi.NodeServer) (*GRPCServer, error) {
	proto, addr, err := parseEndpoint(endpoint)
	if err != nil {
		return nil, err
	}

	if proto == "unix" {
		addr = "/" + addr
		if err := os.Remove(addr); err != nil && !os.IsNotExist(err) {
			return nil, fmt.Errorf("failed to remove %q: %w", addr, err)
		}
	}

	listener, err := net.Listen(proto, addr)
	if err != nil {
		return nil, err
	}

	return NewGRPCServerWithListener(listener, log, ids, cs, ns), nil
}

func NewGRPCServerWithListener(lis net.Listener, log logr.Logger, ids csi.IdentityServer, cs csi.ControllerServer, ns csi.NodeServer) *GRPCServer {
	opts := []grpc.ServerOption{
		grpc.UnaryInterceptor(loggingInterceptor(log)),
	}
	server := grpc.NewServer(opts...)

	if ids != nil {
		csi.RegisterIdentityServer(server, ids)
	}
	if cs != nil {
		csi.RegisterControllerServer(server, cs)
	}
	if ns != nil {
		csi.RegisterNodeServer(server, ns)
	}

	return &GRPCServer{
		server: server,
		lis:    lis,
	}
}

func (g *GRPCServer) Run() error {
	return g.server.Serve(g.lis)
}

func (s *GRPCServer) Stop() {
	s.server.GracefulStop()
}

func (s *GRPCServer) ForceStop() {
	s.server.Stop()
}

func parseEndpoint(ep string) (string, string, error) {
	if strings.HasPrefix(strings.ToLower(ep), "unix://") || strings.HasPrefix(strings.ToLower(ep), "tcp://") {
		s := strings.SplitN(ep, "://", 2)
		if s[1] != "" {
			return s[0], s[1], nil
		}
	}
	return "", "", fmt.Errorf("invalid endpoint: %v", ep)
}

func loggingInterceptor(log logr.Logger) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		log := log.WithValues("rpc_method", info.FullMethod, "request", protosanitizer.StripSecrets(req))
		log.V(3).Info("handling request")
		resp, err := handler(ctx, req)
		if err != nil {
			log.Error(err, "failed processing request")
		} else {
			log.V(5).Info("request completed", "response", protosanitizer.StripSecrets(resp))
		}
		return resp, err
	}
}
