# Protocol_DFA_Learning
Learning protocol DFA using LearnLib's L* algorithm.

## Support Protocols
* FTP
* IKEv2

## Packets
SA_INIT_ACC - ike_init_sa_acc_sa.xml  # 所有路径最先发的包，没在状态机里体现
AUTH_PSK - ike_auth_psk.xml
AUTH_CERT - ike_auth_cert.xml
AUTH_CERT_HTTP - ike_auth_cert_http.xml
REKEY_IKE_SA - cre_cld_sa_rekey_ike_sa.xml
DEL_CUR_IKE_SA - info_del_ike_sa.xml
DEL_OLD_IKE_SA - info_del_ike_sa.xml
REKEY_CHILD_SA_CUR_IKE - cre_cld_sa_rekey_cld_sa.xml
REKEY_CHILD_SA_OLD_IKE - cre_cld_sa_rekey_cld_sa.xml
DEL_CUR_CHILD_SA_CUR_IKE - info_del_cld_sa.xml
DEL_CUR_CHILD_SA_OLD_IKE - info_del_cld_sa.xml
DEL_OLD_CHILD_SA_CUR_IKE - info_del_cld_sa.xml
DEL_OLD_CHILD_SA_OLD_IKE - info_del_cld_sa.xml