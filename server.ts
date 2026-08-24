import express from 'express';
import path from 'path';
import { GoogleGenAI } from '@google/genai';
import { createServer as createViteServer } from 'vite';
import { performSecurityAssessment, generateSyntheticTrace, PRESET_SCENARIOS, DH_GROUPS } from './src/utils/ipsecData';
import { extractFlowFeatures, predictWithXGBoost, XGBOOST_MODEL_METRICS } from './src/utils/xgboostEngine';
import { TestbedConfig } from './src/types/ipsec';

const app = express();
const PORT = 3000;

app.use(express.json({ limit: '10mb' }));

// Lazy Gemini AI Client initialization
function getGeminiClient(): GoogleGenAI | null {
  const apiKey = process.env.GEMINI_API_KEY;
  if (!apiKey) {
    return null;
  }
  return new GoogleGenAI({
    apiKey,
    httpOptions: {
      headers: {
        'User-Agent': 'aistudio-build'
      }
    }
  });
}

// 1. API: Scenarios List
app.get('/api/scenarios', (req, res) => {
  res.json({ scenarios: PRESET_SCENARIOS });
});

// 2. API: Generate Testbed and Simulate Traffic
app.post('/api/generate-testbed', (req, res) => {
  try {
    const config: TestbedConfig = req.body;
    if (!config || !config.vpnMode) {
      return res.status(400).json({ error: 'Invalid testbed configuration provided.' });
    }

    const packets = generateSyntheticTrace(config);
    const flowFeatures = extractFlowFeatures(packets);
    const xgboostPrediction = predictWithXGBoost(flowFeatures);
    const securityAssessment = performSecurityAssessment(config);

    // Generate StrongSwan & Cisco Configurations
    const strongswanConfig = generateStrongswanConfig(config);
    const ciscoConfig = generateCiscoConfig(config);

    res.json({
      success: true,
      config,
      packets,
      flowFeatures,
      xgboostPrediction,
      securityAssessment,
      strongswanConfig,
      ciscoConfig
    });
  } catch (err: any) {
    console.error('Error generating testbed:', err);
    res.status(500).json({ error: err.message || 'Failed to generate testbed trace' });
  }
});

// 3. API: Analyze Custom Packet Trace / Hex Stream
app.post('/api/analyze-trace', (req, res) => {
  try {
    const { packets, rawHexText, customConfig } = req.body;

    let targetPackets = packets;
    if (!targetPackets || targetPackets.length === 0) {
      // Fallback to default preset if none passed
      targetPackets = generateSyntheticTrace(PRESET_SCENARIOS[0]);
    }

    const flowFeatures = extractFlowFeatures(targetPackets);
    const xgboostPrediction = predictWithXGBoost(flowFeatures);
    const activeConfig: TestbedConfig = customConfig || PRESET_SCENARIOS[0];
    const securityAssessment = performSecurityAssessment(activeConfig);

    res.json({
      success: true,
      packets: targetPackets,
      flowFeatures,
      xgboostPrediction,
      securityAssessment
    });
  } catch (err: any) {
    console.error('Error analyzing trace:', err);
    res.status(500).json({ error: err.message || 'Trace analysis failed' });
  }
});

// 4. API: XGBoost Model Metrics & Metadata
app.get('/api/xgboost/metrics', (req, res) => {
  res.json({
    metrics: XGBOOST_MODEL_METRICS
  });
});

// 5. API: Gemini AI-Powered Deep Security Assessment & CISO Report
app.post('/api/gemini/security-audit', async (req, res) => {
  try {
    const { config, securityAssessment, flowFeatures, xgboostPrediction } = req.body;
    const ai = getGeminiClient();

    if (!ai) {
      // Fallback deterministic intelligent narrative if API key is not configured
      return res.json({
        executiveSummary: `Automated Security Audit Report for ${config?.name || 'IPsec VPN'}:
The assessed IPsec deployment scored ${securityAssessment?.overallScore || 45}/100 and has been rated as ${securityAssessment?.riskLevel || 'HIGH RISK'}.
Key vulnerabilities include ${securityAssessment?.findings?.map((f: any) => f.title).join(', ') || 'cryptographic deprecation and missing PFS'}.
XGBoost classified the inner encrypted flow as "${xgboostPrediction?.predictedClass || 'Unknown'}" with ${(xgboostPrediction?.confidence * 100).toFixed(1)}% confidence based on packet size distribution and IAT jitter.`,
        threatAnalysis: 'High exposure to offline PSK dictionary attacks, discrete logarithm precomputation (Logjam), and 64-bit collision attacks (Sweet32).',
        rfcCompliance: 'Violates RFC 8221 and NIST SP 800-77 Rev 1 guidelines. Transition to IKEv2 with AES-256-GCM and DH Group 19 (ECP-256) is mandated.',
        remediationRoadmap: [
          'Step 1: Replace IKEv1 daemon with strongSwan IKEv2.',
          'Step 2: Enforce AEAD ciphers (aes256gcm16) and disable 3DES/CBC.',
          'Step 3: Enable Perfect Forward Secrecy (PFS) on all Child SAs.',
          'Step 4: Configure Anti-Replay window of 64 packets.'
        ]
      });
    }

    const prompt = `You are a Principal Cryptographer and Network Security Architect specialized in IPsec VPN protocol analysis (RFC 7296, RFC 8221, NIST SP 800-77 Rev 1, ANSSI, BSI).
Analyze the following IPsec VPN security posture and generate a structured executive and technical assessment report:

Deployment Metadata:
- Mode: ${config?.vpnMode} Mode
- IKE Version: ${config?.ikeVersion} (${config?.ikeMode})
- Encryption Cipher: ${config?.encryptionAlgo}
- Authentication Hash: ${config?.authAlgo}
- Diffie-Hellman Group: Group ${config?.dhGroupId}
- Perfect Forward Secrecy: ${config?.pfsEnabled ? 'Enabled' : 'DISABLED'}
- IP Version: ${config?.ipVersion}
- Overall Security Score: ${securityAssessment?.overallScore}/100 (${securityAssessment?.riskLevel})
- Inferred Inner Traffic: ${xgboostPrediction?.predictedClass} (XGBoost Confidence: ${(xgboostPrediction?.confidence * 100).toFixed(1)}%)
- Flow Characteristics: Mean Packet Size=${flowFeatures?.meanPacketSize}B, Mean IAT=${flowFeatures?.meanInterArrivalTimeMs}ms, Entropy=${flowFeatures?.payloadEntropy}

Identified Findings:
${JSON.stringify(securityAssessment?.findings, null, 2)}

Provide your response in clear, authoritative technical Markdown addressing:
1. Executive Summary (CISO/SecOps overview, overall risk posture, business impact)
2. In-Depth Cryptographic Vulnerability Analysis (detailed explanation of why current ciphers/DH/IKE mode are vulnerable to attacks like Logjam, Sweet32, Offline Dictionary cracking, or Padding Oracle)
3. Inner Traffic Fingerprinting Risk (how adversaries or nation-state monitors use statistical ML/XGBoost to classify encrypted ESP traffic)
4. Step-by-Step Remediation Guide (exact config directives for strongSwan / Cisco IOS).`;

    const response = await ai.models.generateContent({
      model: 'gemini-3.7-flash',
      contents: prompt
    });

    res.json({
      analysisMarkdown: response.text
    });
  } catch (err: any) {
    console.error('Gemini Audit API error:', err);
    res.status(500).json({ error: err.message || 'AI assessment failed' });
  }
});

// 6. API: Gemini Interactive Cybersecurity Advisor Chat
app.post('/api/gemini/chat', async (req, res) => {
  try {
    const { message, context } = req.body;
    const ai = getGeminiClient();

    if (!ai) {
      return res.json({
        reply: `I am your AI IPsec Protocol & Security Assistant. Currently analyzing configuration: ${context?.config?.name || 'IPsec VPN'}. ${message.toLowerCase().includes('recommend') || message.toLowerCase().includes('fix') ? 'To harden this tunnel, we recommend upgrading to IKEv2 with AES-256-GCM and DH Group 19.' : 'Ask me anything about packet dissection, IKEv1 vs IKEv2 handshakes, Sweet32 attacks, Diffie-Hellman discrete log precomputations, or strongSwan configuration syntax.'}`
      });
    }

    const systemInstruction = `You are "IPsec Shield AI", an expert network security auditor and cryptographer specializing in IPsec VPNs, IKEv1/IKEv2 protocol dissection, cryptographic suite evaluation, RFC standards (RFC 4301, 7296, 8221, 7321), and machine learning traffic fingerprinting (XGBoost).
Context of current inspected VPN:
- Scenario: ${context?.config?.name}
- Mode: ${context?.config?.vpnMode}
- Protocol: ${context?.config?.ikeVersion} (${context?.config?.encryptionAlgo} / ${context?.config?.authAlgo} / DH ${context?.config?.dhGroupId})
- PFS: ${context?.config?.pfsEnabled ? 'Enabled' : 'Disabled'}
- Current Risk Score: ${context?.securityAssessment?.overallScore}/100
- XGBoost Traffic Prediction: ${context?.xgboostPrediction?.predictedClass}

Answer the user's questions clearly, concisely, and with precise cryptographic accuracy and actionable code/config snippets when appropriate.`;

    const response = await ai.models.generateContent({
      model: 'gemini-3.7-flash',
      contents: message,
      config: {
        systemInstruction
      }
    });

    res.json({
      reply: response.text
    });
  } catch (err: any) {
    console.error('Gemini Chat API error:', err);
    res.status(500).json({ error: err.message || 'AI chat failed' });
  }
});

function generateStrongswanConfig(config: TestbedConfig): string {
  const dh = DH_GROUPS[config.dhGroupId] || DH_GROUPS[14];
  const isIkev2 = config.ikeVersion === 'IKEv2';
  const isAead = config.encryptionAlgo.includes('GCM') || config.encryptionAlgo.includes('ChaCha');

  let ikeProposal = '';
  let espProposal = '';

  if (isAead) {
    const encr = config.encryptionAlgo.toLowerCase().replace('-', '');
    ikeProposal = `${encr}-prfsha384-${dh.type.toLowerCase()}${dh.bitLength > 500 ? '521' : dh.bitLength}`;
    espProposal = `${encr}${config.pfsEnabled ? `-${dh.type.toLowerCase()}${dh.bitLength > 500 ? '521' : dh.bitLength}` : ''}`;
  } else {
    const encr = config.encryptionAlgo.toLowerCase().replace('-cbc', '');
    const auth = config.authAlgo.toLowerCase().replace('hmac-', '');
    ikeProposal = `${encr}-${auth}-${dh.name.toLowerCase().includes('modp') ? `modp${dh.bitLength}` : `ecp${dh.bitLength}`}`;
    espProposal = `${encr}-${auth}${config.pfsEnabled ? `-${dh.name.toLowerCase().includes('modp') ? `modp${dh.bitLength}` : `ecp${dh.bitLength}`}` : ''}`;
  }

  return `# /etc/ipsec.conf - StrongSwan IPsec Configuration
config setup
    charondebug="ike 2, knl 2, cfg 2, esp 2"
    uniqueids=yes

conn ipsec-tunnel-${config.id}
    type=${config.vpnMode.toLowerCase()}
    keyexchange=${isIkev2 ? 'ikev2' : 'ikev1'}
    ike=${ikeProposal}!
    esp=${espProposal}!
    ikelifetime=${config.keyLifetimeHours}h
    lifetime=${Math.max(1, Math.floor(config.keyLifetimeHours / 3))}h
    rekeymargin=3m
    keyingtries=3
    authby=secret
    left=${config.ipVersion === 'IPv6' ? '2001:db8:85a3::8a2e:370:7334' : '198.51.100.10'}
    leftsubnet=${config.ipVersion === 'IPv6' ? '2001:db8:1::/64' : '10.0.1.0/24'}
    right=${config.ipVersion === 'IPv6' ? '2001:db8:85a3::8a2e:370:8888' : '203.0.113.50'}
    rightsubnet=${config.ipVersion === 'IPv6' ? '2001:db8:2::/64' : '10.0.2.0/24'}
    auto=start
    replay_window=${config.replayProtection ? '64' : '0'}`;
}

function generateCiscoConfig(config: TestbedConfig): string {
  const isIkev2 = config.ikeVersion === 'IKEv2';
  return `! Cisco IOS XE / ASA IPsec Configuration
crypto ikev2 proposal IKE2_PROP_${config.id.toUpperCase().replace(/-/g, '_')}
 encryption ${config.encryptionAlgo.toLowerCase().includes('gcm') ? 'aes-gcm-256' : 'aes-cbc-256'}
 prf ${config.authAlgo.toLowerCase().includes('sha512') ? 'sha512' : 'sha384'}
 group ${config.dhGroupId}
!
crypto ikev2 policy IKE2_POL
 proposal IKE2_PROP_${config.id.toUpperCase().replace(/-/g, '_')}
!
crypto transform-set ESP_TRANSFORM esp-${config.encryptionAlgo.toLowerCase().includes('gcm') ? 'gcm 256' : 'aes 256 esp-sha256-hmac'}
 mode ${config.vpnMode.toLowerCase()}
!
crypto map IPSEC_MAP 10 ipsec-isakmp
 set peer 203.0.113.50
 set transform-set ESP_TRANSFORM
 ${config.pfsEnabled ? `set pfs group${config.dhGroupId}` : '! PFS Disabled'}
 set security-association lifetime seconds ${config.keyLifetimeHours * 3600}
 match address VPN_ACL`;
}

// Vite middleware setup
async function startServer() {
  if (process.env.NODE_ENV !== 'production') {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa'
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), 'dist');
    app.use(express.static(distPath));
    app.get('*', (req, res) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`IPsec Shield AI Server running on http://localhost:${PORT}`);
  });
}

startServer();
