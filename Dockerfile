FROM quay.io/keycloak/keycloak:26.6.4

COPY partialImport/target/kc-partial-auth-import.jar \
     /opt/keycloak/providers/kc-partial-auth-import.jar

COPY logging-authenticato/target/kc-logging-authenticator.jar \
     /opt/keycloak/providers/kc-logging-authenticator.jar

RUN /opt/keycloak/bin/kc.sh build

ENTRYPOINT ["/opt/keycloak/bin/kc.sh"]