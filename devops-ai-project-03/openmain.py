import os
from typing import Any, Dict, List
import requests
from fastapi import FastAPI, HTTPException
from kubernetes import client, config
from openai import OpenAI  # Added OpenAI client library

APP_VERSION = "1.0"

# Swapped Ollama variables for OpenAI configurations
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
OPENAI_MODEL = os.getenv("OPENAI_MODEL", "gpt-5.6-sol")
AI_TIMEOUT = int(os.getenv("AI_TIMEOUT", "240"))

# Initialize the OpenAI client
# It automatically picks up the OPENAI_API_KEY environment variable if not explicitly passed
#client_openai = OpenAI(api_key=OPENAI_API_KEY)

app = FastAPI(title="AI Kubernetes Security Analyzer", version=APP_VERSION)

try: 
    config.load_incluster_config()
except Exception:
    try: 
        config.load_kube_config()
    except Exception: 
        pass

core = client.CoreV1Api()
apps = client.AppsV1Api()
rbac = client.RbacAuthorizationV1Api()
net = client.NetworkingV1Api()

RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}

def f(sev, cat, res, title, evidence, reco): 
    return {"severity": sev, "category": cat, "resource": res, "title": title, "evidence": evidence, "recommendation": reco}

def scan_podspec(ns, kind, name, s):
    out = []
    res = f"{ns}/{kind}/{name}"
    if s.host_network: out.append(f("HIGH", "Pod Security", res, "Host network enabled", "spec.hostNetwork=true", "Disable hostNetwork unless required."))
    if s.host_pid: out.append(f("HIGH", "Pod Security", res, "Host PID namespace enabled", "spec.hostPID=true", "Disable hostPID unless required."))
    if s.host_ipc: out.append(f("HIGH", "Pod Security", res, "Host IPC namespace enabled", "spec.hostIPC=true", "Disable hostIPC unless required."))
    for v in s.volumes or []:
        if v.host_path: out.append(f("HIGH", "Pod Security", res, "hostPath volume used", f"{v.name}: {v.host_path.path}", "Replace hostPath with a safer volume type where possible."))
    psc = s.security_context
    if psc and psc.run_as_user == 0: out.append(f("HIGH", "Container Security", res, "Runs as root", "runAsUser=0", "Run as a non-root UID."))
    if not psc or not psc.seccomp_profile: out.append(f("MEDIUM", "Container Security", res, "Seccomp not explicitly configured", "No seccompProfile found", "Use RuntimeDefault or an appropriate Localhost profile."))
    for c in list(s.containers or []) + list(s.init_containers or []):
        r = f"{res}/{c.name}"
        sc = c.security_context
        image = c.image or ""
        if image.endswith(":latest") or ":" not in image.split("/")[-1]: out.append(f("MEDIUM", "Image Security", r, "Mutable/unpinned image tag", image, "Pin to an immutable version or digest."))
        if sc and sc.privileged: out.append(f("CRITICAL", "Container Security", r, "Privileged container", "securityContext.privileged=true", "Remove privileged mode unless strictly required."))
        if sc and sc.allow_privilege_escalation: out.append(f("HIGH", "Container Security", r, "Privilege escalation allowed", "allowPrivilegeEscalation=true", "Set allowPrivilegeEscalation=false where compatible."))
        if not sc or sc.run_as_non_root is not True: out.append(f("MEDIUM", "Container Security", r, "Non-root execution not enforced", "runAsNonRoot is not true at container/pod level", "Set runAsNonRoot=true."))
        if sc and sc.capabilities and sc.capabilities.add: out.append(f("MEDIUM", "Linux Capabilities", r, "Additional capabilities added", str(sc.capabilities.add), "Drop unnecessary capabilities."))
        if not c.resources or not c.resources.limits: out.append(f("LOW", "Workload Hardening", r, "No resource limits", "resources.limits absent", "Set CPU and memory limits based on measured usage."))
    sa = s.service_account_name or "default"
    if sa == "default": out.append(f("MEDIUM", "ServiceAccount", res, "Default ServiceAccount used", "serviceAccountName=default", "Use a dedicated ServiceAccount."))
    if s.automount_service_account_token is not False: out.append(f("MEDIUM", "ServiceAccount", res, "ServiceAccount token may be mounted", "automountServiceAccountToken is not false", "Set false unless API access is required."))
    return out

def scan_rbac():
    out = []
    for role in rbac.list_cluster_role().items:
        for rule in role.rules or []:
            resources = set(rule.resources or [])
            verbs = set(rule.verbs or [])
            if "*" in resources or "*" in verbs: out.append(f("HIGH", "RBAC", f"ClusterRole/{role.metadata.name}", "Wildcard RBAC permission", f"resources={sorted(resources)}, verbs={sorted(verbs)}", "Replace wildcards with least-privilege permissions."))
            if (verbs & {"create", "update", "patch", "delete"}) and ({"roles", "rolebindings", "*"} & resources): out.append(f("HIGH", "RBAC", f"ClusterRole/{role.metadata.name}", "Role-management permission", "Role/RoleBinding write permission detected", "Review for privilege escalation risk."))
    for b in rbac.list_cluster_role_binding().items:
        if b.role_ref and b.role_ref.name == "cluster-admin":
            for s in b.subjects or []: out.append(f("CRITICAL", "RBAC", f"ClusterRoleBinding/{b.metadata.name}", "cluster-admin binding", f"{s.kind}:{s.namespace or ''}/{s.name}", "Review whether full cluster-admin is necessary."))
    return out

def scan_ns(ns):
    out = []
    for o in apps.list_namespaced_deployment(ns).items: out += scan_podspec(ns, "Deployment", o.metadata.name, o.spec.template.spec)
    for o in apps.list_namespaced_stateful_set(ns).items: out += scan_podspec(ns, "StatefulSet", o.metadata.name, o.spec.template.spec)
    for o in apps.list_namespaced_daemon_set(ns).items: out += scan_podspec(ns, "DaemonSet", o.metadata.name, o.spec.template.spec)
    for o in core.list_namespaced_pod(ns).items:
        if not (o.metadata.owner_references or []): out += scan_podspec(ns, "Pod", o.metadata.name, o.spec)
    pods = core.list_namespaced_pod(ns).items
    policies = net.list_namespaced_network_policy(ns).items
    if pods and not policies: out.append(f("LOW", "Network Security", ns, "No NetworkPolicy found", "Workloads exist but no NetworkPolicy objects exist", "Define expected ingress and egress policies."))
    out += scan_rbac()
    out.sort(key=lambda x: RANK[x["severity"]], reverse=True)
    summary = {x: sum(i["severity"] == x for i in out) for x in RANK}
    return {"namespace": ns, "summary": summary, "finding_count": len(out), "findings": out}

# Updated to use the official OpenAI Client library structure
def ai(scan):
    if not OPENAI_API_KEY:
        return "AI explanation unavailable: OPENAI_API_KEY environment variable is missing."
        
    prompt = f'''You are a Kubernetes security reviewer. Python findings and severity are authoritative; do not invent vulnerabilities or change severity. Never expose secret values. A missing NetworkPolicy is a hardening gap, not automatically critical. Do not claim CVEs because this scanner does not scan images. Explain: security posture, top findings, remediation order, safe YAML examples, human-review items.\n\nSCAN:\n{scan}'''
    try:
        response = client_openai.chat.completions.create(
            model=OPENAI_MODEL,
            messages=[
                {"role": "user", "content": prompt}
            ],
            timeout=AI_TIMEOUT
        )
        return response.choices[0].message.content
    except Exception as e: 
        return f"AI explanation unavailable: {e}"

@app.get("/health")
def health(): 
    return {"status": "healthy", "service": "ai-k8s-security-analyzer", "version": APP_VERSION, "model": OPENAI_MODEL}

@app.get("/scan/namespace/{namespace}")
def namespace(namespace: str):
    try: 
        x = scan_ns(namespace)
    except Exception as e: 
        raise HTTPException(500, str(e))
    x["ai_explanation"] = ai(x)
    x["model"] = OPENAI_MODEL
    return x

@app.get("/scan/cluster")
def cluster():
    try: 
        results = [scan_ns(n.metadata.name) for n in core.list_namespace().items]
    except Exception as e: 
        raise HTTPException(500, str(e))
    summary = {x: sum(r["summary"][x] for r in results) for x in RANK}
    
    cluster_payload = {
        "scope": "cluster",
        "summary": summary,
        "top_findings": [r["findings"][:10] for r in results]
    }
    
    return {
        "scope": "cluster",
        "summary": summary,
        "namespaces_results": results,
        "model": OPENAI_MODEL,
        "ai_explanation": ai(cluster_payload)
    }
