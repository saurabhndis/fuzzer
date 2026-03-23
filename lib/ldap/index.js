// LDAP Protocol Fuzzer — re-exports for clean imports
// Usage: const ldap = require('./lib/ldap');

const constants = require('./constants');
const packet = require('./packet');
const {
  LDAP_SCENARIOS,
  LDAP_CATEGORIES,
  LDAP_CATEGORY_SEVERITY,
  LDAP_CATEGORY_DEFAULT_DISABLED,
  getLdapScenario,
  getLdapScenariosByCategory,
  listLdapScenarios,
  listLdapClientScenarios,
  listLdapServerScenarios,
} = require('./scenarios');
const { LdapFuzzerClient } = require('./fuzzer-client');
const { LdapFuzzerServer } = require('./fuzzer-server');


module.exports = {
  // Constants
  ...constants,

  // Packet builder
  ...packet,

  // Scenarios
  LDAP_SCENARIOS,
  LDAP_CATEGORIES,
  LDAP_CATEGORY_SEVERITY,
  LDAP_CATEGORY_DEFAULT_DISABLED,
  getLdapScenario,
  getLdapScenariosByCategory,
  listLdapScenarios,
  listLdapClientScenarios,
  listLdapServerScenarios,

  // Engines
  LdapFuzzerClient,
  LdapFuzzerServer,
};
