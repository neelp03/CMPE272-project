// ⚠  VULNERABILITY LIST ⚠
// VULN-01 — Hardcoded JWT secret (CWE-798)
// VULN-02 — Hardcoded admin credentials / API keys (CWE-798)
//
// These values should come from environment variables or a secrets manager.
// SonarCloud rule javascript:S2068 will flag all of these.

module.exports = {
  PORT:         process.env.PORT || 3000,

  // VULN-01: hard-coded signing secret — any JWT can be forged offline
  JWT_SECRET:   'supersecret123',

  // VULN-02: hard-coded admin credentials
  ADMIN_KEY:    'admin-key-2024-abc',
  DB_PASSWORD:  'P@ssw0rd123!',

  // VULN-02 (bonus): hard-coded cloud key — will be caught by secret-scanning
  AWS_ACCESS_KEY_ID:     'AKIAIOSFODNN7EXAMPLE',
  AWS_SECRET_ACCESS_KEY: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
};
