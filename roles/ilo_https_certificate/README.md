<!-- BEGIN_ANSIBLE_DOCS -->

# Ansible Role: trippsc2.netscaler.server_certificate
Version: 1.0.5

This role generates a new Server Certificate for a NetScaler load balancer, if an existing certificate doesn't exist or needs renewal.

This role will use another role to generate the private key, CSR, and certificate.

The role can be supplied by setting the `netscaler_certificate_type` to an existing type or setting it to `custom` and supplying a role name through the `netscaler_certificate_role` variable.

The role referenced must output an encrypted private key in the `cert_private_key_content` variable and the certificate in the `cert_certificate_content` variable.

At this time, this role does not support using ADM as a proxy for a NetScaler load balancer.


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
| netscaler_nsip | <p>The NSIP address of the NetScaler load balancer.</p> | str | yes |  |  |
| netscaler_protocol | <p>The protocol to use when connecting to the NetScaler load balancer.</p><p>If not provided, the role will default to `https`.</p> | str | no | <ul><li>http</li><li>https</li></ul> |  |
| netscaler_port | <p>The port to use when connecting to the NetScaler load balancer.</p><p>If not provided and *netscaler_protocol* is set to `https`, the role will default to `443`.</p><p>If not provided and *netscaler_protocol* is set to `http`, the role will default to `80`.</p> | int | no |  |  |
| netscaler_validate_certs | <p>Whether to validate SSL certificates when connecting to the NetScaler load balancer.</p><p>If not provided, the role will default to `true`.</p> | bool | no |  |  |
| netscaler_api_path | <p>The path to the NetScaler Nitro API.</p><p>If not provided, the role will default to `nitro/v1/config`.</p> | str | no |  |  |
| netscaler_user | <p>The username to use when connecting to the NetScaler load balancer.</p><p>This is mutually exclusive with *netscaler_token*.  One or the other is required.</p> | str | no |  |  |
| netscaler_pass | <p>The password to use when connecting to the NetScaler load balancer.</p><p>This is mutually exclusive with *netscaler_token*.  One or the other is required.</p> | str | no |  |  |
| netscaler_token | <p>The token to use when connecting to the NetScaler load balancer.</p><p>This is mutually exclusive with *netscaler_user* and *netscaler_pass*.  One or the other is required.</p> | str | no |  |  |
| netscaler_certificate_name | <p>The name of the certificate to create or renew.</p> | str | yes |  |  |
| netscaler_certificate_regenerate_days | <p>The number of days before the certificate expiration to regenerate the CSR.</p> | int | no |  | 30 |
| netscaler_certificate_type | <p>The type of certificate to generate.</p><p>If set to `self_signed`, the role will use the **trippsc2.general.self_signed_certificate** role.</p><p>If set to `adcs_signed`, the role will use the **trippsc2.adcs.signed_certificate** role.</p><p>If set to `vault_signed`, the role will use the **trippsc2.hashi_vault.signed_certificate** role.</p><p>If set to `acme_dns_signed`, the role will use the **trippsc2.general.acme_dns_certificate** role.</p><p>If set to `custom`, the role will use the role supplied in the `netscaler_certificate_role` variable.</p> | str | yes | <ul><li>self_signed</li><li>adcs_signed</li><li>vault_signed</li><li>acme_dns_signed</li><li>custom</li></ul> |  |
| netscaler_certificate_role | <p>The role to use to generate the private key, CSR, and certificate.</p><p>This is required if *netscaler_certificate_type* is set to `custom`. Otherwise, it is not used.</p> | str | no |  |  |
| netscaler_private_key_passphrase | <p>The passphrase to use when decrypting the private key.</p> | str | yes |  |  |
| netscaler_private_key_filename | <p>The filename of the private key to use when generating the CSR.</p> | str | yes |  |  |
| netscaler_intermediate_certificate_filename | <p>The filename of the intermediate CA certificate.</p><p>If *netscaler_certificate_type* is set to `acme_dns_signed`, this is required.</p><p>This should not be depended on by other certificates, as it will be replaced if the CA chain changes.</p> | str | no |  |  |
| netscaler_intermediate_certificate_name | <p>The name of the intermediate CA certificate.</p><p>If *netscaler_certificate_type* is set to `acme_dns_signed`, this is required.</p><p>This should not be depended on by other certificates, as it will be replaced if the CA chain changes.</p> | str | no |  |  |
| netscaler_certificate_filename | <p>The filename of the certificate to use when generating the CSR.</p> | str | yes |  |  |
| netscaler_linked_ca_certificate_name | <p>The name of the CA certificate to link to the server certificate.</p><p>If not provided, the role will not link a CA certificate.</p> | str | no |  |  |
| netscaler_save_config | <p>Whether to save the NetScaler configuration after creating the certificate.</p> | bool | no |  | True |


## License
MIT

## Author and Project Information
Jim Tarpley (@trippsc2)
<!-- END_ANSIBLE_DOCS -->
