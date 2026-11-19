//! Group-to-VPN-server authorization.
//!
//! The single authoritative rule: a mapping grants a server when the mapping's
//! `idp_group` appears in the user's groups and its `vpn_server` matches the
//! requested server. Comparison is exact and case-sensitive.

use crate::config::Mapping;

/// Whether any of `groups` is the mapping's IdP group.
fn grants(groups: &[String], mapping: &Mapping) -> bool {
    groups.iter().any(|group| group == &mapping.idp_group)
}

/// Returns the first mapping granting access to `server` for `groups`.
///
/// The comparison is case-sensitive and exact. Startup validation already
/// forbids duplicate `vpn_server` values, so at most one mapping can match.
// Consumed by the server-download handler; the whoami handler drives the
// portal list through `authorized_servers`.
pub fn authorized<'a>(
    groups: &[String],
    server: &str,
    mappings: &'a [Mapping],
) -> Option<&'a Mapping> {
    mappings
        .iter()
        .find(|mapping| mapping.vpn_server == server && grants(groups, mapping))
}

/// Returns the VPN servers the user's groups grant access to, in mapping order.
pub fn authorized_servers(groups: &[String], mappings: &[Mapping]) -> Vec<String> {
    mappings
        .iter()
        .filter(|mapping| grants(groups, mapping))
        .map(|mapping| mapping.vpn_server.clone())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Mapping;

    fn mapping(vpn_server: &str, idp_group: &str) -> Mapping {
        Mapping {
            vpn_server: vpn_server.to_owned(),
            idp_group: idp_group.to_owned(),
            vault_metadata_mountpoint: "vpnmeta".to_owned(),
            vault_metadata_path: "develmeta".to_owned(),
            vault_pki_mountpoint: "vpn/devel".to_owned(),
            vault_jwt_role: "test-role".to_owned(),
            vault_jwt_path: "jwt".to_owned(),
        }
    }

    fn group(name: &str) -> String {
        name.to_owned()
    }

    #[test]
    fn exact_case_sensitive_match() {
        let mappings = vec![mapping("myserver", "/example")];

        assert!(
            authorized(&[group("/example")], "myserver", &mappings).is_some(),
            "/example must grant myserver"
        );
        assert!(
            authorized(&[group("/Example")], "myserver", &mappings).is_none(),
            "group comparison must be case-sensitive"
        );
        assert!(
            authorized(&[group("/other")], "myserver", &mappings).is_none(),
            "unknown group must not grant myserver"
        );
    }

    #[test]
    fn any_mapping_grants() {
        let mappings = vec![
            mapping("myserver", "/example"),
            mapping("myserver2", "/other"),
        ];

        assert!(
            authorized(&[group("/other")], "myserver2", &mappings).is_some(),
            "any single matching mapping grants the server"
        );
        assert!(
            authorized(&[group("/example")], "myserver", &mappings).is_some(),
            "any single matching mapping grants the server"
        );
    }

    #[test]
    fn authorized_servers_preserves_mapping_order() {
        let mappings = vec![
            mapping("myserver", "/example"),
            mapping("myserver2", "/example"),
            mapping("myserver3", "/example"),
            mapping("myserver4", "/example2"),
        ];

        assert_eq!(
            authorized_servers(&[group("/example")], &mappings),
            vec!["myserver", "myserver2", "myserver3"]
        );
    }
}
