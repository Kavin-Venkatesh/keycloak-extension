package org.keycloak.partialImport;

import org.keycloak.Config;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.services.resources.admin.ext.AdminRealmResourceProvider;
import org.keycloak.services.resources.admin.ext.AdminRealmResourceProviderFactory;

public class PartialAuthImportResourceProviderFactory implements AdminRealmResourceProviderFactory {

    public static final String ID = "partial-auth-import";

    @Override
    public AdminRealmResourceProvider create(KeycloakSession session) {
        return new PartialAuthImportResourceProvider(session);
    }

    @Override
    public void init(Config.Scope config) {

    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {

    }

    @Override
    public void close() {

    }

    @Override
    public String getId() {
        return ID;
    }
}
