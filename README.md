# Ansible Collection: trippsc2.hpe

This collection contains plugins and/or roles for configuring HPE servers.

## Content

### Module plugins

- [ilo_account_settings](plugins/modules/ilo_account_settings.py) - Configure iLO account settings
- [ilo_domain_name](plugins/modules/ilo_domain_name.py) - Configures iLO domain name
- [ilo_hostname](plugins/modules/ilo_hostname.py) - Configures iLO hostname
- [ilo_https_certificate](plugins/modules/ilo_https_certificate.py) - Configures iLO HTTPS certificate
- [ilo_https_certificate_info](plugins/modules/ilo_https_certificate_info.py) - Retrieves iLO HTTPS certificate information
- [ilo_https_csr](plugins/modules/ilo_https_csr.py) - Generates an iLO HTTPS certificate signing request (CSR)
- [ilo_https_security_settings](plugins/modules/ilo_https_security_settings.py) - Configures iLO HTTPS security settings
- [ilo_ipv4_dns_servers](plugins/modules/ilo_ipv4_dns_servers.py) - Configures iLO IPv4 DNS servers
- [ilo_ipv6_dns_servers](plugins/modules/ilo_ipv6_dns_servers.py) - Configures iLO IPv6 DNS servers
- [ilo_ldap_remote_role_mapping](plugins/modules/ilo_ldap_remote_role_mapping.py) - Configures iLO LDAP remote role mapping
- [ilo_ldap_settings](plugins/modules/ilo_ldap_settings.py) - Configure iLO LDAP settings
- [ilo_ntp_servers](plugins/modules/ilo_ntp_servers.py) - Configures iLO NTP servers
- [ilo_snmp_community](plugins/modules/ilo_snmp_community.py) - Configures iLO SNMP community strings
- [ilo_snmp_config](plugins/modules/ilo_snmp_config.py) - Configures iLO SNMP settings
- [ilo_snmp_user](plugins/modules/ilo_snmp_user.py) - Configures iLO SNMP user settings
- [ilo_time_zone](plugins/modules/ilo_time_zone.py) - Configures iLO time zone

### Roles

- [ilo_https_certificate](roles/ilo_https_certificate/README.md) - This role configures the iLO HTTPS certificate.
