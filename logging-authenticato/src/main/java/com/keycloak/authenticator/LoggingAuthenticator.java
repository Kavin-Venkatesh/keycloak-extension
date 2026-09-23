package com.keycloak.authenticator;

import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.Authenticator;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

public class LoggingAuthenticator implements Authenticator {

    private static final Logger LOG =
            Logger.getLogger(LoggingAuthenticator.class);

    public LoggingAuthenticator(KeycloakSession session) {
    }

    @Override
    public void authenticate(AuthenticationFlowContext context) {

        LOG.infof(
                "LoggingAuthenticator executed. Realm=%s, User=%s",
                context.getRealm().getName(),
                context.getUser() != null
                        ? context.getUser().getUsername()
                        : "anonymous"
        );

        context.success();
    }

    @Override
    public void action(AuthenticationFlowContext context) {

        LOG.info("LoggingAuthenticator action() executed");

        context.success();
    }

    @Override
    public boolean requiresUser() {
        return false;
    }

    @Override
    public boolean configuredFor(
            KeycloakSession session,
            RealmModel realm,
            UserModel user) {

        return true;
    }

    @Override
    public void setRequiredActions(
            KeycloakSession session,
            RealmModel realm,
            UserModel user) {
    }

    @Override
    public void close() {
    }
}