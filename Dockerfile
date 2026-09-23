FROM quay.io/keycloak/keycloak:26.6.4

COPY partial-auth-import/target/kc-partial-auth-import.jar \
     /opt/keycloak/providers/kc-partial-auth-import.jar

RUN /opt/keycloak/bin/kc.sh build

ENTRYPOINT ["/opt/keycloak/bin/kc.sh"]