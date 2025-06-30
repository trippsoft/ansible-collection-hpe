<!-- BEGIN_ANSIBLE_DOCS -->

# Ansible Role: trippsc2.hpe.ilo_https_certificate
Version: 1.0.1

This role generates a new HTTPS Certificate for an HPE iLO, if an existing certificate doesn't exist or needs renewal.

This role will use another role to generate the private key, CSR, and certificate.

The role can be supplied by setting the `ilo_certificate_type` to an existing type or setting it to `custom` and supplying a role name through the `ilo_certificate_role` variable.

The role referenced must output an unencrypted private key in the `cert_private_key_content` variable and the certificate in the `cert_certificate_content` variable.


## Requirements


## Dependencies

| Collection |
| ---------- |
| ansible.utils |
| netscaler.adc |
| trippsc2.adcs |
| trippsc2.general |
| trippsc2.hashi_vault |

## Role Arguments
|Option|Description|Type|Required|Choices|Default|
|---|---|---|---|---|---|
| ilo_base_url | <p>The base URL of the HPE iLO.</p> | str | yes |  |  |
| ilo_username | <p>The username to use when connecting to the HPE iLO.</p> | str | yes |  |  |
| ilo_password | <p>The password to use when connecting to the HPE iLO.</p> | str | yes |  |  |
| ilo_certificate_regenerate_days | <p>The number of days before the certificate expiration to regenerate the CSR.</p> | int | no |  | 30 |
| ilo_certificate_type | <p>The type of certificate to generate.</p><p>If set to `self_signed`, the role will use the **trippsc2.general.self_signed_certificate** role.</p><p>If set to `adcs_signed`, the role will use the **trippsc2.adcs.signed_certificate** role.</p><p>If set to `vault_signed`, the role will use the **trippsc2.hashi_vault.signed_certificate** role.</p><p>If set to `acme_dns_signed`, the role will use the **trippsc2.general.acme_dns_certificate** role.</p><p>If set to `custom`, the role will use the role supplied in the `ilo_certificate_role` variable.</p> | str | yes | <ul><li>self_signed</li><li>adcs_signed</li><li>vault_signed</li><li>acme_dns_signed</li><li>custom</li></ul> |  |
| ilo_certificate_role | <p>The role to use to generate the private key, CSR, and certificate.</p><p>This is required if *ilo_certificate_type* is set to `custom`. Otherwise, it is not used.</p> | str | no |  |  |


## License
MIT

## Author and Project Information
Jim Tarpley (@trippsc2)
<!-- END_ANSIBLE_DOCS -->
