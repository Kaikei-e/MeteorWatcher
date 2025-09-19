-- Initial schema for Meteor Watcher datastore
-- This runs only on first container initialization.

CREATE SCHEMA IF NOT EXISTS vulnerability;

-- Store vulnerabilities
CREATE TABLE IF NOT EXISTS osv_vulnerabilities (
  id              bigserial PRIMARY KEY,
  osv_vuln_id         text NOT NULL,
  ecosystem       text NOT NULL,
  name            text NOT NULL,
  affected_package text NOT NULL,
  affected_versions text NOT NULL,
  affected_ranges text NOT NULL,
  references text NOT NULL,
  events text NOT NULL,
  created_at      timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_osv_vulnerabilities_ecosystem ON osv_vulnerabilities (ecosystem);
CREATE INDEX IF NOT EXISTS idx_osv_vulnerabilities_name ON osv_vulnerabilities (name);
CREATE INDEX IF NOT EXISTS idx_osv_vulnerabilities_osv_vuln_id ON osv_vulnerabilities (osv_vuln_id);

-- Store normalized detailed vulnerabilities
CREATE TABLE IF NOT EXISTS normalized_vulnerabilities (
  id              uuid PRIMARY KEY,
  ecosystem       text NOT NULL,
  cve_id          text NOT NULL,
  osv_vuln_id     bigint REFERENCES osv_vulnerabilities(id) ON DELETE CASCADE,
  severity        text NOT NULL,
);

CREATE INDEX IF NOT EXISTS idx_normalized_vulnerabilities_ecosystem ON normalized_vulnerabilities (ecosystem);
CREATE INDEX IF NOT EXISTS idx_normalized_vulnerabilities_cve_id ON normalized_vulnerabilities (cve_id);
CREATE INDEX IF NOT EXISTS idx_normalized_vulnerabilities_osv_vuln_id ON normalized_vulnerabilities (osv_vuln_id);