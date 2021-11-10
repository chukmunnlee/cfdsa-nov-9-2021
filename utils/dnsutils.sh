#!/usr/bin/env bash
kubectl run dnsutils --image=gcr.io/kubernetes-e2e-test-images/dnsutils:1.3 --restart=Never --command sleep 10000000
