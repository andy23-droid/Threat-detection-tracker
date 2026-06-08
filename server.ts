import express from 'express';
import path from 'path';
import { fileURLToPath } from 'url';
import { createServer as createViteServer } from 'vite';
import { GoogleGenAI, Type } from '@google/genai';
import dotenv from 'dotenv';

// Load environment variables
dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Import types inline or represent directly in memory
interface Vulnerability {
  id: string;
  cveId: string;
  title: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  cvss: number;
  system: string;
  status: 'OPEN' | 'INVESTIGATING' | 'PATCHED' | 'IGNORED';
  detectedAt: string;
  description: string;
  mitigation: string;
  remediationPlaybook?: string;
}

interface AlertRule {
  id: string;
  name: string;
  severityThreshold: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  systemPattern: string; // Match system name (or "*" for all)
  isActive: boolean;
  muteNotification: boolean;
}

interface AlertLog {
  id: string;
  vulnerabilityId: string;
  cveId: string;
  title: string;
  message: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  timestamp: string;
  isAcknowledged: boolean;
}

// Global In-Memory Cybersecurity Vulnerability database
let vulnerabilities: Vulnerability[] = [
  {
    id: "v-1",
    cveId: "CVE-2026-0248",
    title: "SSH Authorized Keys Arbitrary Command Injection Bypass",
    severity: "CRITICAL",
    cvss: 9.8,
    system: "SSH-Gateway-Prod",
    status: "OPEN",
    detectedAt: "2026-06-08T08:15:00Z",
    description: "A logic error in user credentials parsing routines in SSH-Gateway-Prod allows an authenticated SSH client to inject arbitrary shell script commands, bypassing force-command configs.",
    mitigation: "Upgrade login shell wrappers, ensure strict SSH limits are compiled, or restrict key credentials immediately."
  },
  {
    id: "v-2",
    cveId: "CVE-2025-4652",
    title: "Log4j RCE via Legacy JNDI Lookup Execution",
    severity: "HIGH",
    cvss: 8.8,
    system: "Legacy-Reporting-App",
    status: "INVESTIGATING",
    detectedAt: "2026-06-07T14:22:11Z",
    description: "An unauthenticated remote code execution vulnerability can be triggered in the Legacy Reporting App when enterprise payload headers are processed with active JNDI schemas.",
    mitigation: "Apply JVM startup flag -Dlog4j2.formatMsgNoLookups=true to legacy server container environments immediately."
  },
  {
    id: "v-3",
    cveId: "CVE-2025-5643",
    title: "Nginx Client IP Directory Traversal Overlay Bypass",
    severity: "MEDIUM",
    cvss: 6.5,
    system: "CDN-Proxy-LoadBalancer",
    status: "PATCHED",
    detectedAt: "2026-06-06T10:00:00Z",
    description: "Nginx cache routers are vulnerable to a path sanitization offset when serving web requests with corrupted virtual-directory segments, exposing layout structures.",
    mitigation: "Update cluster load balancers to stable Mainline releases and restart proxy containers."
  },
  {
    id: "v-4",
    cveId: "CVE-2026-1188",
    title: "Spring Boot Actuator Information Disclosure Leak",
    severity: "LOW",
    cvss: 4.3,
    system: "Developer-Sandbox-Portal",
    status: "OPEN",
    detectedAt: "2026-06-08T01:30:20Z",
    description: "Exposure of system properties, local configurations, and sensitive developer profile keys via public endpoint availability at /actuator/env.",
    mitigation: "Disable Actuator web interface exposure or explicitly set management.endpoints.web.exposure.exclude=env properties."
  }
];

let alertRules: AlertRule[] = [
  {
    id: "r-1",
    name: "Critical Zero-Day Alarm",
    severityThreshold: "CRITICAL",
    systemPattern: "*",
    isActive: true,
    muteNotification: false
  },
  {
    id: "r-2",
    name: "Production Environment Watcher",
    severityThreshold: "HIGH",
    systemPattern: "Prod",
    isActive: true,
    muteNotification: false
  }
];

let alertLogs: AlertLog[] = [
  {
    id: "a-1",
    vulnerabilityId: "v-1",
    cveId: "CVE-2026-0248",
    title: "CRITICAL Incident Triggered",
    message: "Critical severity vulnerability CVE-2026-0248 was detected on SSH-Gateway-Prod.",
    severity: "CRITICAL",
    timestamp: "2026-06-08T08:15:05Z",
    isAcknowledged: false
  }
];

// Re-seed utility
const seedVulnerabilities = JSON.parse(JSON.stringify(vulnerabilities));
const seedAlertRules = JSON.parse(JSON.stringify(alertRules));
const seedAlertLogs = JSON.parse(JSON.stringify(alertLogs));

// Templates for dynamic attack simulation
const attackTemplates = [
  {
    cveId: "CVE-2026-4412",
    title: "Kubernetes Kubelet API Privilege Escalation Exploit",
    severity: "CRITICAL" as const,
    cvss: 9.9,
    system: "K8s-Cluster-Prod",
    description: "An authorization bypass flaw in the Kubelet API allows local administrative takeover inside production orchestrator Nodes when specific volume mounts are configured.",
    mitigation: "Apply orchestrator update patches, enforce strict service account contexts, and restrict Node ports."
  },
  {
    cveId: "CVE-2026-7811",
    title: "OpenSSL Denial of Service in TLS Handshake",
    severity: "HIGH" as const,
    cvss: 7.5,
    system: "Web-Load-Balancer-Prod",
    description: "An infinite loop parser issue within TLS-1.3 session extensions can crash edge routing proxies upon receiving special handshake frames, causing a complete system down.",
    mitigation: "Deploy secure firewall packet rules or compile and run binaries using newer TLS releases."
  },
  {
    cveId: "CVE-2026-1033",
    title: "MySQL SQL Injection in Custom Audit Logging Module",
    severity: "HIGH" as const,
    cvss: 8.2,
    system: "Database-Cluster-Prod",
    description: "Unsanitized parameters log parsing functions in standard audit logs allow SQL statement splicing to read system credentials tables.",
    mitigation: "Turn off legacy custom module extensions or upgrade query parameters to prepared bindings immediately."
  },
  {
    cveId: "CVE-2026-0929",
    title: "Apache Kafka Unauthorized Consumer Group Hijacking",
    severity: "MEDIUM" as const,
    cvss: 6.5,
    system: "Event-Streaming-Staging",
    description: "Missing consumer authentication validation allows arbitrary clients to clear partitions or alter consumer indexes on unencrypted streams.",
    mitigation: "Configure Kafka server SASL/SSL credentials permissions and define strict consumer rules."
  }
];

// Lazy Gemini Client Initialization
let aiClient: GoogleGenAI | null = null;
function getGeminiClient(): { ai: GoogleGenAI | null; mode: 'LIVE' | 'DEMO' } {
  const key = process.env.GEMINI_API_KEY;
  if (!key || key === "MY_GEMINI_API_KEY" || key === "") {
    return { ai: null, mode: 'DEMO' };
  }
  if (!aiClient) {
    aiClient = new GoogleGenAI({
      apiKey: key,
      httpOptions: {
        headers: {
          'User-Agent': 'aistudio-build',
        }
      }
    });
  }
  return { ai: aiClient, mode: 'LIVE' };
}

// Function to check rules when a new vulnerability is registered
function checkAlertRulesForVulnerability(vuln: Vulnerability) {
  for (const rule of alertRules) {
    if (!rule.isActive) continue;

    // Check System Pattern match (standard lowercase inclusion or wildcard)
    const matchesSystem = 
      rule.systemPattern === "*" || 
      vuln.system.toLowerCase().includes(rule.systemPattern.toLowerCase());

    if (!matchesSystem) continue;

    // Check Severity Threshold match
    const severityHierarchy = { "CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1 };
    const ruleVal = severityHierarchy[rule.severityThreshold];
    const vulnVal = severityHierarchy[vuln.severity];

    if (vulnVal >= ruleVal) {
      // Create Alert
      const alertId = `a-gen-${Date.now()}-${Math.floor(Math.random() * 1000)}`;
      const newAlert: AlertLog = {
        id: alertId,
        vulnerabilityId: vuln.id,
        cveId: vuln.cveId,
        title: `${vuln.severity} Threat Triggered!`,
        message: `${vuln.severity} vulnerability "${vuln.title}" discovered on target [${vuln.system}] by real-time scanners.`,
        severity: vuln.severity,
        timestamp: new Date().toISOString(),
        isAcknowledged: false
      };
      alertLogs.unshift(newAlert);
      console.log(`Alert triggered for ${vuln.cveId}:`, newAlert.message);
    }
  }
}

async function startServer() {
  const app = express();
  const PORT = 3000;

  app.use(express.json());

  // API Route - Get all vulnerabilities
  app.get('/api/vulnerabilities', (req, res) => {
    res.json(vulnerabilities);
  });

  // API Route - Add arbitrary vulnerability
  app.post('/api/vulnerabilities', (req, res) => {
    const { cveId, title, severity, cvss, system, description, mitigation } = req.body;
    if (!cveId || !title || !severity || !cvss || !system || !description || !mitigation) {
      return res.status(400).json({ error: "Missing required vulnerability properties" });
    }

    const newVuln: Vulnerability = {
      id: `v-custom-${Date.now()}`,
      cveId,
      title,
      severity,
      cvss: Number(cvss),
      system,
      status: 'OPEN',
      detectedAt: new Date().toISOString(),
      description,
      mitigation
    };

    vulnerabilities.unshift(newVuln);
    checkAlertRulesForVulnerability(newVuln);
    res.status(201).json(newVuln);
  });

  // API Route - Patch vulnerability status or fields
  app.patch('/api/vulnerabilities/:id', (req, res) => {
    const { id } = req.params;
    const vulnIndex = vulnerabilities.findIndex(v => v.id === id);
    if (vulnIndex === -1) {
      return res.status(404).json({ error: "Vulnerability not found" });
    }

    const updated = { ...vulnerabilities[vulnIndex], ...req.body };
    vulnerabilities[vulnIndex] = updated;
    res.json(updated);
  });

  // API Route - Delete vulnerability
  app.delete('/api/vulnerabilities/:id', (req, res) => {
    const { id } = req.params;
    vulnerabilities = vulnerabilities.filter(v => v.id !== id);
    res.json({ success: true, id });
  });

  // API Route - Trigger Mock Sploit Intrusion
  app.post('/api/vulnerabilities/simulate', (req, res) => {
    // Select one randomized entry
    const template = attackTemplates[Math.floor(Math.random() * attackTemplates.length)];
    const uniqueId = `v-sim-${Date.now()}`;
    const newSim: Vulnerability = {
      ...template,
      id: uniqueId,
      detectedAt: new Date().toISOString(),
      status: 'OPEN'
    };

    vulnerabilities.unshift(newSim);
    checkAlertRulesForVulnerability(newSim);
    res.status(201).json({ vulnerability: newSim, alertsTriggeredCount: alertLogs.filter(a => a.vulnerabilityId === uniqueId).length });
  });

  // API Route - Reset DB
  app.post('/api/vulnerabilities/reset', (req, res) => {
    vulnerabilities = JSON.parse(JSON.stringify(seedVulnerabilities));
    alertRules = JSON.parse(JSON.stringify(seedAlertRules));
    alertLogs = JSON.parse(JSON.stringify(seedAlertLogs));
    res.json({ success: true, message: "Vulnerability tracker and alerts reset to default seed state." });
  });

  // API Route - Get alert rules
  app.get('/api/alert-rules', (req, res) => {
    res.json(alertRules);
  });

  // API Route - Set or change alert rule
  app.post('/api/alert-rules', (req, res) => {
    const { name, severityThreshold, systemPattern, isActive, muteNotification } = req.body;
    if (!name || !severityThreshold || !systemPattern) {
      return res.status(400).json({ error: "Missing required rule parameters" });
    }

    const newRule: AlertRule = {
      id: `r-rule-${Date.now()}`,
      name,
      severityThreshold,
      systemPattern,
      isActive: isActive !== undefined ? isActive : true,
      muteNotification: muteNotification !== undefined ? muteNotification : false
    };

    alertRules.push(newRule);
    res.status(201).json(newRule);
  });

  // API Route - Toggle or update alert rule
  app.patch('/api/alert-rules/:id', (req, res) => {
    const { id } = req.params;
    const ruleIdx = alertRules.findIndex(r => r.id === id);
    if (ruleIdx === -1) {
      return res.status(404).json({ error: "Rule not found" });
    }
    alertRules[ruleIdx] = { ...alertRules[ruleIdx], ...req.body };
    res.json(alertRules[ruleIdx]);
  });

  // API Route - Delete alert rule
  app.delete('/api/alert-rules/:id', (req, res) => {
    const { id } = req.params;
    alertRules = alertRules.filter(r => r.id !== id);
    res.json({ success: true, id });
  });

  // API Route - Get alert logs
  app.get('/api/alerts', (req, res) => {
    res.json(alertLogs);
  });

  // API Route - Acknowledge alert
  app.post('/api/alerts/:id/acknowledge', (req, res) => {
    const { id } = req.params;
    const alert = alertLogs.find(a => a.id === id);
    if (!alert) {
      return res.status(404).json({ error: "Alert log not found" });
    }
    alert.isAcknowledged = true;
    res.json(alert);
  });

  // API Route - Acknowledge ALL alerts
  app.post('/api/alerts/acknowledge-all', (req, res) => {
    alertLogs.forEach(a => a.isAcknowledged = true);
    res.json({ success: true, count: alertLogs.length });
  });

  // API Route - Gemini-powered Vulnerability Scanning & Risk Assessment
  app.post('/api/scan-stack', async (req, res) => {
    const { stackDescription, targetSystemName } = req.body;
    const systemName = targetSystemName || "Custom-Infrastructure-Node";

    if (!stackDescription || stackDescription.trim() === '') {
      return res.status(400).json({ error: "Please enter a valid stack configuration to audit." });
    }

    const { ai, mode } = getGeminiClient();

    if (mode === 'DEMO' || !ai) {
      // Safe sandbox fallback
      console.log("Using demo sandbox generator for stack auditing...");
      const mockResult: Vulnerability[] = [
        {
          id: `v-gem-demo-${Date.now()}-1`,
          cveId: "CVE-2025-0158",
          title: `Insecure Library Dependency in ${systemName}`,
          severity: "HIGH",
          cvss: 8.4,
          system: systemName,
          status: "OPEN",
          detectedAt: new Date().toISOString(),
          description: `Simulated result for audit query: "${stackDescription}". A high-severity authentication bypass library routine exists in parsing logic, matching key infrastructure nodes.`,
          mitigation: "Upgrade standard application dependencies blocklists and recompile assets to stable versions.",
        },
        {
          id: `v-gem-demo-${Date.now()}-2`,
          cveId: "CVE-2025-9922",
          title: `Privileged Database Access configuration in ${systemName}`,
          severity: "MEDIUM",
          cvss: 6.9,
          system: systemName,
          status: "OPEN",
          detectedAt: new Date().toISOString(),
          description: `Simulated result for audit query: "${stackDescription}". Loose trust configuration parameters lead to potential SQL auditing overrides in local session caching systems.`,
          mitigation: "Restrict connection permission parameters in properties resources."
        }
      ];

      // Add to main vulnerability register
      mockResult.forEach(v => {
        vulnerabilities.unshift(v);
        checkAlertRulesForVulnerability(v);
      });

      return res.json({ 
        vulnerabilities: mockResult, 
        mode: 'DEMO', 
        message: "Audited using sandbox mode fallback. Connect GEMINI_API_KEY for dynamic scanning." 
      });
    }

    try {
      console.log(`Analyzing stack "${stackDescription}" via live Gemini AI model...`);
      const response = await ai.models.generateContent({
        model: "gemini-3.5-flash",
        contents: `You are an elite automated DevSecOps Auditing machine. An administrator wants you to parse the following description of their technology stack/components:
        ---
        "${stackDescription}"
        ---
        And identify valid potential vulnerabilities (CVEs) or severe misconfigurations applicable to this stack for system [${systemName}].

        Respond STRICTLY with a JSON array that maps to this schema structure:
        [
          {
            "cveId": "CVE-XXXX-XXXX identifier or Zero-Day-XXXX",
            "title": "A short descriptive title naming the affected library/protocol",
            "severity": "CRITICAL", "HIGH", "MEDIUM", or "LOW",
            "cvss": 7.8,
            "description": "Professional technical description detailing how this component exposes the system to exploits",
            "mitigation": "Immediate actionable fix or command sequence to remediate this vulnerability"
          }
        ]
        Limit yourself to generating 1 to 3 highly realistic or actual vulnerabilities. Ensure CVSS is a number between 1.0 and 10.0. Keep the description technical and concise.`,
        config: {
          responseMimeType: "application/json",
          responseSchema: {
            type: Type.ARRAY,
            items: {
              type: Type.OBJECT,
              properties: {
                cveId: { type: Type.STRING, description: "CVE identifier or unique signature" },
                title: { type: Type.STRING, description: "Name/title of vulnerability" },
                severity: { type: Type.STRING, description: "CRITICAL, HIGH, MEDIUM, or LOW" },
                cvss: { type: Type.NUMBER, description: "CVSS value from 1.0 to 10.0" },
                description: { type: Type.STRING, description: "Detailed exposure scenario" },
                mitigation: { type: Type.STRING, description: "Technical mitigation steps" }
              },
              required: ["cveId", "title", "severity", "cvss", "description", "mitigation"]
            }
          }
        }
      });

      const text = response.text || "[]";
      console.log("Raw Gemini JSON scan response:", text);
      const parsedItems = JSON.parse(text);

      const createdVulns: Vulnerability[] = parsedItems.map((item: any, idx: number) => {
        let cleanSeverity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' = 'MEDIUM';
        const sevStr = String(item.severity).toUpperCase();
        if (['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].includes(sevStr)) {
          cleanSeverity = sevStr as any;
        }

        return {
          id: `v-gem-live-${Date.now()}-${idx}`,
          cveId: item.cveId || `Zero-Day-${Date.now()}`,
          title: item.title || "Custom Security Misconfiguration",
          severity: cleanSeverity,
          cvss: Number(item.cvss) || 5.0,
          system: systemName,
          status: 'OPEN',
          detectedAt: new Date().toISOString(),
          description: item.description || "Identified security threat via automatic audits.",
          mitigation: item.mitigation || "Upgrade underlying packages to latest stable release and conduct code audit."
        };
      });

      // Inject into main register
      createdVulns.forEach(v => {
        vulnerabilities.unshift(v);
        checkAlertRulesForVulnerability(v);
      });

      res.json({ vulnerabilities: createdVulns, mode: 'LIVE' });
    } catch (err: any) {
      console.error("Gemini stack audit error:", err);
      res.status(500).json({ error: "Gemini analysis failed. Using fallback simulation.", details: err.message });
    }
  });

  // API Route - Gemini-powered Playbook Generator
  app.post('/api/vulnerabilities/:id/remediate', async (req, res) => {
    const { id } = req.params;
    const vuln = vulnerabilities.find(v => v.id === id);
    if (!vuln) {
      return res.status(404).json({ error: "Vulnerability not found" });
    }

    const { ai, mode } = getGeminiClient();

    if (mode === 'DEMO' || !ai) {
      // Safe high-fidelity sandbox fallback
      console.log(`Generating fallback mitigation playbook for ${vuln.cveId}...`);
      const fallbackPlaybook = `
# ⚠️ DEVSEC-OPS RECOVERY PLAYBOOK (DEMO MODE)
**Vulnerability Ref**: ${vuln.cveId}
**Target Node**: \`${vuln.system}\`
**Severity Rating**: \`${vuln.severity}\` (CVSS ${vuln.cvss})

---

### Executing Rapid Shield Sandbox Patch

Below is a generated runbook targeting [${vuln.system}]. To deploy live Gemini analysis pipelines, make sure to add your \`GEMINI_API_KEY\` underneath the **Settings > Secrets** panel in the AI Studio workspace.

### 1. Verification of Threat Vulnerability
Run the following script command sequence inside the admin terminal interface of **${vuln.system}** to assert audit statuses:
\`\`\`bash
# Look up operational logs and network connections targeting known exploits:
netstat -tulpn | grep -E "22|80|443"
cat /var/log/audit/audit.log | grep -i "${vuln.cveId}" || echo "No active exploitation log signature found."
\`\`/

### 2. Immediate Quarantine & Isolation
Restrict internet protocol packet routing for this system block while remediation efforts proceed:
\`\`\`bash
# Create immediate local firewall rules boundaries:
sudo iptables -A INPUT -p tcp --dport 22 -m limit --limit 3/min -j ACCEPT
sudo iptables -A OUTPUT -p tcp -d 10.0.0.0/8 -j ACCEPT
\`\`\`

### 3. Rapid Code Remediation & Upgrades
Apply standard dependency packages patching overrides:
\`\`\`bash
# Update local packages database and execute forced upgrades:
sudo apt-get update && sudo apt-get install --only-upgrade openspawn-core ssh-daemon-utils -y
\`\`\`

**Config Adjustment**: Make sure current parameters do not leak resources. Verify config files include correct headers.

### 4. System Integrity Assertions
Run verification tests to confirm the exploit is patched:
\`\`\`bash
# Validate service configurations:
systemctl status sshd
sysctl -p /etc/sysctl.conf
echo "Verification complete. Patch successfully loaded."
\`\`\`
`;
      vuln.remediationPlaybook = fallbackPlaybook;
      return res.json({ playbook: fallbackPlaybook, mode: 'DEMO' });
    }

    try {
      console.log(`Generating live Gemini DevSecOps playbook for ${vuln.cveId}...`);
      const prompt = `You are a Principal Security Architect and DevSecOps Coordinator.
      Write an ultra-detailed, actionable, production-ready Security Patching and Remediation Playbook for:
      
      Vulnerability ID: ${vuln.cveId}
      System Impact Category: ${vuln.system}
      Risk Class: ${vuln.severity} (CVSS: ${vuln.cvss})
      Vulnerability Title: ${vuln.title}
      Vulnerability Summary of Threat: ${vuln.description}
      Suggested Core Action: ${vuln.mitigation}

      Structure the response elegantly in high-contrast clean Markdown.
      Provide:
      1. INTRUSION SURFACE EXPLORATION: Explain the vulnerability clearly under a header. Explain the threat attack path.
      2. CONTAINMENT COMMANDS: Provide actual shell commands or system config files block sequences to contain the server system location.
      3. PATCH SEQUENCE: Actionable coding patterns or packages commands.
      4. SANITY VERIFICATION: Commands to run to check that the exploit is mitigated and the target system is fully stable.
      
      Keep explanations strictly focused on DevSecOps engineering efficiency, with no lengthy intros or conversational filler.`;

      const response = await ai.models.generateContent({
        model: "gemini-3.5-flash",
        contents: prompt
      });

      const playbookText = response.text || "Failed to generate playbook output content.";
      vuln.remediationPlaybook = playbookText;
      res.json({ playbook: playbookText, mode: 'LIVE' });
    } catch (err: any) {
      console.error("Gemini playbook generator error:", err);
      res.status(500).json({ error: "Gemini Playbook Generation failed.", details: err.message });
    }
  });

  // Serve static assets in production, or mount Vite middleware in development
  if (process.env.NODE_ENV !== "production") {
    console.log("Configuring server with dynamic Vite-middleware proxies...");
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: "spa"
    });
    app.use(vite.middlewares);
  } else {
    console.log("Serving build outputs out of /dist...");
    const distPath = path.join(process.cwd(), 'dist');
    app.use(express.static(distPath));
    app.get('*', (req, res) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  }

  app.listen(PORT, "0.0.0.0", () => {
    console.log(`Vulnerability System server listening on host 0.0.0.0, port ${PORT}`);
  });
}

startServer();
