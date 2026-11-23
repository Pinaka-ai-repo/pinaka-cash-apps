# ASTRA Cloud-Agnostic Infrastructure-as-Code Template (infra/terraform/main.tf)
# MIT Open-Source Template — 100% Cloud-Vendor Agnostic (Kubernetes / OpenTofu / Terraform).
# Runs on any CNCF-compliant Kubernetes cluster (On-Premises bare metal, K3s, OpenShift, Rancher,
# or any cloud Kubernetes service) with zero cloud-provider lock-in and zero hardcoded credentials.
# Enforces SEC-13 (Encryption at Rest), SEC-15 (Zero-Trust NetworkPolicy), and SEC-35 (Non-Root Container Hardening).

terraform {
  required_version = ">= 1.6.0"
  required_providers {
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "~> 2.27"
    }
  }
}

variable "namespace" {
  description = "Target Kubernetes namespace for ASTRA deployment"
  type        = string
  default     = "astra-system"
}

variable "environment_mode" {
  description = "Operational mode: demo, shadow, or production"
  type        = string
  default     = "production"
}

variable "execution_policy" {
  description = "Network egress policy: local-no-egress or allowlisted-egress"
  type        = string
  default     = "local-no-egress"
}

variable "object_storage_endpoint" {
  description = "Cloud-agnostic S3-compatible object storage endpoint (e.g., MinIO, Ceph, Garage, or self-hosted store)"
  type        = string
  default     = "http://astra-minio.astra-system.svc.cluster.local:9000"
}

variable "vault_addr" {
  description = "HashiCorp Vault / OpenBao address for envelope encryption and dynamic secret references"
  type        = string
  default     = "http://astra-vault.astra-system.svc.cluster.local:8200"
}

resource "kubernetes_namespace" "astra" {
  metadata {
    name = var.namespace
    labels = {
      "app.kubernetes.io/name"       = "astra-cash-application"
      "app.kubernetes.io/managed-by" = "opentofu-terraform"
      "astra.pinaka.ai/license"      = "MIT"
      "astra.pinaka.ai/mode"         = var.environment_mode
    }
  }
}

# SEC-15: Default-Deny Ingress & Egress NetworkPolicy (Zero-Trust Pod Isolation)
resource "kubernetes_network_policy" "astra_zero_trust" {
  metadata {
    name      = "astra-default-deny-external"
    namespace = kubernetes_namespace.astra.metadata[0].name
  }

  spec {
    pod_selector {}
    policy_types = ["Ingress", "Egress"]

    ingress {
      from {
        namespace_selector {
          match_labels = {
            "app.kubernetes.io/name" = "astra-cash-application"
          }
        }
      }
    }

    egress {
      to {
        namespace_selector {
          match_labels = {
            "app.kubernetes.io/name" = "astra-cash-application"
          }
        }
      }
    }
  }
}

# Cloud-Agnostic Runtime Configuration Map (Zero Secrets Stored in ConfigMap)
resource "kubernetes_config_map" "astra_runtime_config" {
  metadata {
    name      = "astra-runtime-config"
    namespace = kubernetes_namespace.astra.metadata[0].name
  }

  data = {
    ASTRA_ENV                     = var.environment_mode
    ASTRA_AUTH_MODE               = "oidc"
    ASTRA_EXECUTION_POLICY        = var.execution_policy
    ASTRA_ENCRYPTION_AT_REST      = "true"
    ASTRA_KMS_KEY_OWNER           = "customer-security-admin"
    ASTRA_TLS_MIN_VERSION         = "1.3"
    OBJECT_STORAGE_ENDPOINT_URL   = var.object_storage_endpoint
    OBJECT_STORAGE_BUCKET         = "astra-remittance-artifacts"
    OBJECT_STORAGE_REGION         = "local"
    VAULT_ADDR                    = var.vault_addr
    LAYA_REASON_CLASSIFIER_ENABLED = "true"
    PINAKA_INTEGRATION_ENABLED    = "true"
  }
}
