package org.keycloak.partialImport.authImport;

import org.jboss.logging.Logger;
import org.keycloak.authentication.RequiredActionProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RequiredActionProviderModel;
import org.keycloak.partialImport.exception.PartialImportConflictException;
import org.keycloak.partialImport.exception.PartialImportValidationException;
import org.keycloak.partialImport.representation.PartialAuthImportRepresentation;
import org.keycloak.partialImport.result.PartialAuthImportResult;
import org.keycloak.provider.ProviderFactory;
import org.keycloak.representations.idm.RequiredActionProviderRepresentation;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

public class RequiredActionsPartialImport {

    private static final Logger LOG = Logger.getLogger(RequiredActionsPartialImport.class);

    private final Set<RequiredActionProviderRepresentation> toSkip = new HashSet<>();

    private final Set<RequiredActionProviderRepresentation> toOverwrite = new HashSet<>();

    private final List<PartialAuthImportResult> results = new ArrayList<>();

    public void prepare(PartialAuthImportRepresentation rep, RealmModel realm, KeycloakSession session) {

        List<RequiredActionProviderRepresentation> requiredActions = rep.getRequiredActions();

        if (requiredActions == null || requiredActions.isEmpty()) {
            return;
        }

        Set<String> aliases = new HashSet<>();
        for (RequiredActionProviderRepresentation actionRep : requiredActions) {

            LOG.infof("Preparing required action: alias=%s, providerId=%s, policy=%s", actionRep.getAlias(), actionRep.getProviderId(), rep.getPolicy());

            validateRequiredAction(actionRep);

            if (!aliases.add(actionRep.getAlias())) {
                throw new PartialImportValidationException(
                        "Duplicate required action alias in import: " + actionRep.getAlias());
            }

            RequiredActionProviderModel existing = realm.getRequiredActionProviderByAlias(actionRep.getAlias());

            ProviderFactory<RequiredActionProvider> factory = session.getKeycloakSessionFactory().getProviderFactory(
                    RequiredActionProvider.class,
                    actionRep.getProviderId()
            );

            if (factory == null) {
                throw new PartialImportValidationException("No required action provider found: " + actionRep.getProviderId());
            }

            if (existing == null) {
                continue;
            }

            if (rep.getPolicy() == null) {
                throw new PartialImportValidationException("ifResourceExists policy must be specified");
            }

            switch (rep.getPolicy()) {

                case SKIP:
                    toSkip.add(actionRep);
                    break;

                case OVERWRITE:
                    toOverwrite.add(actionRep);
                    break;

                case FAIL:
                    throw new PartialImportConflictException("Required action already exists: " + actionRep.getAlias());
            }

            LOG.infof(
                    "Required action classification: alias=%s, overwrite=%s, skip=%s",
                    actionRep.getAlias(),
                    toOverwrite.contains(actionRep),
                    toSkip.contains(actionRep)
            );
        }
    }

    public List<PartialAuthImportResult> doImport(
            PartialAuthImportRepresentation rep, RealmModel realm, KeycloakSession session) {

        List<RequiredActionProviderRepresentation> requiredActions = rep.getRequiredActions();

        if (requiredActions == null || requiredActions.isEmpty()) {
            return results;
        }

        for (RequiredActionProviderRepresentation actionRep : toOverwrite) {
            RequiredActionProviderModel existing =
                    realm.getRequiredActionProviderByAlias(actionRep.getAlias());
            if (existing == null) {
                throw new PartialImportValidationException(
                        "Unable to resolve required action selected for overwrite: "
                                + actionRep.getAlias());
            }

            updateExisting(existing, actionRep);
            realm.updateRequiredActionProvider(existing);
            addResult(PartialAuthImportResult.Action.OVERWRITTEN, existing, actionRep);
            LOG.infof("Overwrote required action: alias=%s, providerId=%s",
                    actionRep.getAlias(), actionRep.getProviderId());
        }

        for (RequiredActionProviderRepresentation actionRep : toSkip) {
            LOG.infof("Skipping required action: alias=%s", actionRep.getAlias());
            RequiredActionProviderModel existing = realm.getRequiredActionProviderByAlias(actionRep.getAlias());
            if (existing == null) {
                throw new PartialImportValidationException(
                        "Unable to resolve skipped required action by alias: " + actionRep.getAlias());
            }
            addResult(PartialAuthImportResult.Action.SKIPPED, existing, actionRep);
        }

        for (RequiredActionProviderRepresentation actionRep : requiredActions) {
            if (toOverwrite.contains(actionRep) || toSkip.contains(actionRep)) {
                continue;
            }

            RequiredActionProviderModel model = create(realm, actionRep);
            addResult(PartialAuthImportResult.Action.ADDED, model, actionRep);
            LOG.infof("Added required action: alias=%s, providerId=%s",
                    actionRep.getAlias(), actionRep.getProviderId());
        }

        return results;
    }

    private RequiredActionProviderModel create(
            RealmModel realm, RequiredActionProviderRepresentation actionRep) {
        RequiredActionProviderModel model = toModel(actionRep);
        realm.addRequiredActionProvider(model);
        return model;
    }

    private void addResult(
            PartialAuthImportResult.Action action,
            RequiredActionProviderModel model,
            RequiredActionProviderRepresentation actionRep) {

        results.add(new PartialAuthImportResult(
                action,
                "REQUIRED_ACTION",
                model.getId(),
                actionRep.getAlias(),
                actionRep));
    }


    private RequiredActionProviderModel toModel(RequiredActionProviderRepresentation rep) {

        RequiredActionProviderModel model = new RequiredActionProviderModel();

        model.setAlias(rep.getAlias());
        model.setName(rep.getName());
        model.setProviderId(rep.getProviderId());
        model.setEnabled(rep.isEnabled());
        model.setDefaultAction(rep.isDefaultAction());
        model.setPriority(rep.getPriority());

        if (rep.getConfig() != null) {
            model.setConfig(rep.getConfig());
        }

        return model;
    }

    private void updateExisting(RequiredActionProviderModel existing, RequiredActionProviderRepresentation rep) {

        existing.setName(rep.getName());
        existing.setEnabled(rep.isEnabled());
        existing.setDefaultAction(rep.isDefaultAction());
        existing.setPriority(rep.getPriority());
        existing.setProviderId(rep.getProviderId());

        if (rep.getConfig() != null) {
            existing.setConfig(rep.getConfig());
        } else {
            existing.setConfig(null);
        }
    }

    private void validateRequiredAction(RequiredActionProviderRepresentation actionRep) {

        if (actionRep == null) {
            throw new PartialImportValidationException("Required action cannot be null");
        }

        if (actionRep.getAlias() == null || actionRep.getAlias().isBlank()) {

            throw new PartialImportValidationException("Required action alias cannot be null or empty");
        }

        if (actionRep.getProviderId() == null || actionRep.getProviderId().isBlank()) {

            throw new PartialImportValidationException("Required action providerId cannot be null or empty: " + actionRep.getAlias());
        }
    }


}
