#!/bin/bash

# Configurar Docker de Minikube
eval $(minikube docker-env)

cd /home/hashdown/Api360-backend

case "$1" in
  auth)
    echo "🔨 Building auth-service..."
    docker build -t api360/auth-service:latest -f app/microservices/auth/Dockerfile .
    kubectl rollout restart deployment auth-service -n api360
    ;;
  gateway)
    echo "🔨 Building gateway..."
    docker build -t api360/gateway:latest -f gateway/Dockerfile .
    kubectl rollout restart deployment gateway -n api360
    ;;
  shared)
    echo "🔨 Shared updated - rebuilding all services..."
    docker build -t api360/auth-service:latest -f app/microservices/auth/Dockerfile .
    docker build -t api360/gateway:latest -f gateway/Dockerfile .
    kubectl rollout restart deployment auth-service -n api360
    kubectl rollout restart deployment gateway -n api360
    ;;
  all)
    echo "🔨 Building all services..."
    docker build -t api360/auth-service:latest -f app/microservices/auth/Dockerfile .
    docker build -t api360/gateway:latest -f gateway/Dockerfile .
    kubectl rollout restart deployment auth-service -n api360
    kubectl rollout restart deployment gateway -n api360
    ;;
  status)
    kubectl get pods -n api360
    ;;
  logs)
    kubectl logs -n api360 -l app=$2 -f --tail=100
    ;;
  *)
    echo "Uso: ./deploy.sh [auth|gateway|shared|all|status|logs <service>]"
    exit 1
    ;;
esac

echo "⏳ Waiting for pods..."
kubectl get pods -n api360 -w