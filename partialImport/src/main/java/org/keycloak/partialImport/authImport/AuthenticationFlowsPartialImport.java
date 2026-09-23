package org.keycloak.partialImport.authImport;

import org.keycloak.connections.jpa.support.EntityManagers;
import org.keycloak.deployment.DeployedConfigurationsManager;
import org.keycloak.authentication.AuthenticationFlow;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.ClientAuthenticator;
import org.keycloak.authentication.ConfigurableAuthenticatorFactory;
import org.keycloak.authentication.FormAction;
import org.keycloak.migration.migrators.MigrateTo8_0_0;
import org.keycloak.models.*;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.models.utils.RepresentationToModel;
import org.keycloak.partialImport.exception.PartialImportConflictException;
import org.keycloak.partialImport.exception.PartialImportValidationException;
import org.keycloak.partialImport.representation.PartialAuthImportRepresentation;
import org.keycloak.partialImport.result.PartialAuthImportResult;
import org.keycloak.representations.idm.*;
import org.keycloak.provider.ProviderFactory;

import java.util.*;
import java.util.function.Consumer;
import java.util.stream.Collectors;

import org.jboss.logging.Logger;

public class AuthenticationFlowsPartialImport {

    private static final Logger LOG = Logger.getLogger(AuthenticationFlowsPartialImport.class);

    private final Set<AuthenticationFlowRepresentation> toOverwrite = new HashSet<>();

    private final Set<AuthenticationFlowRepresentation> toSkip = new HashSet<>();

    private final Map<String, AuthenticationFlowReferences> flowReferences = new HashMap<>();

    /** Maps IDs from the import document to IDs in the destination realm. */
    private final Map<String, String> sourceToDestinationFlowIds = new HashMap<>();

    /** Maps deleted destination flow IDs to their replacement IDs. */
    private final Map<String, String> existingToNewFlowIds = new HashMap<>();

    /** Retains the destination ID of each flow until its replacement is created. */
    private final Map<String, String> overwriteFlowIds = new HashMap<>();

    /** Config IDs detached from executions before their owning flow was deep-deleted. */
    private final Set<String> detachedConfigIds = new HashSet<>();

    private final List<PartialAuthImportResult> results = new ArrayList<>();

    public void prepare(PartialAuthImportRepresentation rep, RealmModel realm, KeycloakSession session) {

        List<AuthenticationFlowRepresentation> flows = rep.getAuthenticationFlows();

        if (flows == null || flows.isEmpty()) {
            return;
        }

        Set<String> aliases = new HashSet<>();
        Set<String> sourceFlowIds = new HashSet<>();

        for (AuthenticationFlowRepresentation flowRep : flows) {

            LOG.infof(
                    "Preparing authentication flow: alias=%s, policy=%s, ifResourceExists=%s",
                    flowRep.getAlias(),
                    rep.getPolicy(),
                    rep.getIfResourceExists()
            );

            validateFlowRepresentation(flowRep);

            if (!aliases.add(flowRep.getAlias())) {
                throw new PartialImportValidationException(
                        "Duplicate authentication flow alias in import: " + flowRep.getAlias());
            }

            if (flowRep.getId() != null && !sourceFlowIds.add(flowRep.getId())) {
                throw new PartialImportValidationException(
                        "Duplicate authentication flow id in import: " + flowRep.getId());
            }

            AuthenticationFlowModel existingFlow =
                    realm.getFlowByAlias(flowRep.getAlias());

            if (flowRep.isBuiltIn()) {
                if (existingFlow == null) {
                    throw new PartialImportValidationException(
                            "Built-in authentication flow is not available in destination realm: "
                                    + flowRep.getAlias());
                }

                toSkip.add(flowRep);
                if (flowRep.getId() != null) {
                    sourceToDestinationFlowIds.put(flowRep.getId(), existingFlow.getId());
                }
                continue;
            }

            if (existingFlow != null && existingFlow.isBuiltIn()) {

                toSkip.add(flowRep);

                if (existingFlow != null && flowRep.getId() != null) {
                    sourceToDestinationFlowIds.put(flowRep.getId(), existingFlow.getId());
                }

                LOG.infof(
                        "Skipping built-in authentication flow: alias=%s, importedBuiltIn=%s, existingBuiltIn=%s",
                        flowRep.getAlias(),
                        flowRep.isBuiltIn(),
                        existingFlow != null && existingFlow.isBuiltIn()
                );

                continue;
            }

            validateExecutionAuthenticators(session, flowRep);

            if (existingFlow == null) {
                continue;
            }

            if (rep.getPolicy() == null) {
                throw new PartialImportValidationException("ifResourceExists policy must be specified");
            }

            switch (rep.getPolicy()) {

                case SKIP:
                    toSkip.add(flowRep);
                    if (flowRep.getId() != null) {
                        sourceToDestinationFlowIds.put(flowRep.getId(), existingFlow.getId());
                    }
                    break;

                case OVERWRITE:
                    toOverwrite.add(flowRep);
                    overwriteFlowIds.put(flowRep.getAlias(), existingFlow.getId());
                    break;

                case FAIL:
                    throw new PartialImportConflictException("Authentication flow already exists: " + flowRep.getAlias());
            }

            LOG.infof(
                    "Flow classification: alias=%s, overwrite=%s, skip=%s",
                    flowRep.getAlias(),
                    toOverwrite.contains(flowRep),
                    toSkip.contains(flowRep)
            );

        }

        captureFlowReferences(realm);
    }

    private void captureFlowReferences(RealmModel realm) {

        Set<String> overwriteFlowIds = toOverwrite.stream()
                .map(flowRep -> realm.getFlowByAlias(flowRep.getAlias()))
                .filter(Objects::nonNull)
                .map(AuthenticationFlowModel::getId)
                .collect(Collectors.toSet());

        for (String flowId : overwriteFlowIds) {

            flowReferences.put(
                    flowId,
                    AuthenticationFlowReferences.capture(
                            realm,
                            flowId,
                            overwriteFlowIds
                    )
            );
        }
    }

    public void removeOverwrites(RealmModel realm, KeycloakSession session) {

        Set<String> overwriteRoots = findOverwriteRoots(realm);

        for (AuthenticationFlowReferences references : flowReferences.values()) {
            references.detach(realm);
        }

        for (String flowId : overwriteRoots) {

            AuthenticationFlowModel existing = realm.getAuthenticationFlowById(flowId);

            if (existing == null) {
                continue;
            }

            AuthenticationFlowReferences references = flowReferences.get(flowId);

            if (references == null) {
                throw new PartialImportValidationException(
                        "Missing flow references for overwritten flow: "
                                + existing.getAlias()
                );
            }

            detachAuthenticatorConfigs(realm, existing.getId(), new HashSet<>());

            KeycloakModelUtils.deepDeleteAuthenticationFlow(
                    session,
                    realm,
                    existing,
                    () -> {
                        throw new PartialImportValidationException(
                                "Authentication flow became unavailable: "
                                        + existing.getAlias());
                    },
                    () -> {
                        throw new PartialImportValidationException(
                                "Cannot overwrite built-in authentication flow: "
                                        + existing.getAlias());
                    },
                    false
            );
        }
    }


    private Set<String> findOverwriteRoots( RealmModel realm) {

        Set<String> overwriteIds = toOverwrite.stream()
                .map(rep -> realm.getFlowByAlias(rep.getAlias()))
                .filter(Objects::nonNull)
                .map(AuthenticationFlowModel::getId)
                .collect(Collectors.toSet());

        Set<String> childIds = new HashSet<>();

        for (AuthenticationFlowModel flow :
                realm.getAuthenticationFlowsStream()
                        .filter(flow -> overwriteIds.contains(flow.getId()))
                        .toList()) {

            realm.getAuthenticationExecutionsStream(flow.getId())
                    .filter(AuthenticationExecutionModel::isAuthenticatorFlow)
                    .map(AuthenticationExecutionModel::getFlowId)
                    .filter(Objects::nonNull)
                    .filter(overwriteIds::contains)
                    .forEach(childIds::add);
        }

        overwriteIds.removeAll(childIds);

        return overwriteIds;
    }

    private void detachAuthenticatorConfigs(RealmModel realm, String flowId, Set<String> visited) {

        if (flowId == null || !visited.add(flowId)) {
            return;
        }

        List<AuthenticationExecutionModel> executions =
                realm.getAuthenticationExecutionsStream(flowId).collect(Collectors.toList());

        for (AuthenticationExecutionModel execution : executions) {

            AuthenticationFlowModel subFlow = execution.getFlowId() == null
                    ? null
                    : realm.getAuthenticationFlowById(execution.getFlowId());

            if (subFlow != null) {
                detachAuthenticatorConfigs(realm, subFlow.getId(), visited);
                continue;
            }

            String configId = execution.getAuthenticatorConfig();

            if (configId == null) {
                continue;
            }

            execution.setAuthenticatorConfig(null);
            realm.updateAuthenticatorExecution(execution);

            detachedConfigIds.add(configId);

            LOG.debugf(
                    "Detached authenticator config %s from execution %s before flow deletion",
                    configId,
                    execution.getId()
            );
        }
    }

    public List<PartialAuthImportResult> doImport(PartialAuthImportRepresentation rep, RealmModel realm, KeycloakSession session) {

        List<AuthenticatorConfigRepresentation> configs = rep.getAuthenticatorConfig();

        if (configs == null) {
            LOG.info("Authenticator configs: null");
        }

        Map<String, AuthenticatorConfigModel> importedConfigs = importAuthenticatorConfig(session, realm,rep, configs);

        List<AuthenticationFlowRepresentation> flows = rep.getAuthenticationFlows();

        if (flows != null && !flows.isEmpty()) {

            importAuthenticationFlows(realm, flows);

            importExecutions(session, realm, flows, importedConfigs);

            restoreFlowReferences(realm);

            removeOrphanedConfigs(realm);
        }

        bindAuthenticationFlows(rep, realm, session);

        return results;
    }


    private Map<String, AuthenticatorConfigModel> importAuthenticatorConfig(KeycloakSession session, RealmModel realm, PartialAuthImportRepresentation rep, List<AuthenticatorConfigRepresentation> configs) {

        Map<String, AuthenticatorConfigModel> configsByAlias = new HashMap<>();

        if (configs == null || configs.isEmpty()) {
            return configsByAlias;
        }

        Set<String> configAliases = new HashSet<>();

        for (AuthenticatorConfigRepresentation config : configs) {

            if (!configAliases.add(config.getAlias())) {
                throw new PartialImportValidationException("Duplicate authenticator config alias in import: " + config.getAlias());
            }

            LOG.infof(
                    "Importing authenticator config: alias=%s, id=%s",
                    config.getAlias(),
                    config.getId()
            );

            if (config.getAlias() == null || config.getAlias().isBlank()) {
                throw new PartialImportValidationException("Authenticator config alias cannot be null");
            }

            AuthenticatorConfigModel existingConfig = realm.getAuthenticatorConfigByAlias(config.getAlias());

            if (existingConfig == null) {

                AuthenticatorConfigModel configModel = RepresentationToModel.toModel(config);
                configModel.setId(UUID.randomUUID().toString());
                existingConfig = realm.addAuthenticatorConfig(configModel);

                results.add(new PartialAuthImportResult(
                        PartialAuthImportResult.Action.ADDED,
                        "AUTHENTICATOR_CONFIG",
                        existingConfig.getId(),
                        config.getAlias(),
                        config));

                LOG.infof("Imported authenticator config: alias=%s", config.getAlias());

            } else {

                if (rep.getPolicy() == null) {
                    throw new PartialImportValidationException("ifResourceExists policy must be specified");
                }

                switch (rep.getPolicy()) {

                    case SKIP:
                        results.add(new PartialAuthImportResult(
                                PartialAuthImportResult.Action.SKIPPED,
                                "AUTHENTICATOR_CONFIG",
                                existingConfig.getId(),
                                config.getAlias(),
                                config));

                        LOG.infof("Skipping authenticator config: alias=%s", config.getAlias());
                        break;

                    case OVERWRITE:
                        existingConfig.setConfig(config.getConfig());
                        realm.updateAuthenticatorConfig(existingConfig);

                        results.add(new PartialAuthImportResult(
                                PartialAuthImportResult.Action.OVERWRITTEN,
                                "AUTHENTICATOR_CONFIG",
                                existingConfig.getId(),
                                config.getAlias(),
                                config));

                        LOG.infof("Overwritten authenticator config: alias=%s", config.getAlias());
                        break;

                    case FAIL:
                        throw new PartialImportConflictException(
                                "Authenticator config already exists: " + config.getAlias());
                }
            }

            configsByAlias.put(config.getAlias(), existingConfig);
        }

        return configsByAlias;
    }

    private void importAuthenticationFlows(RealmModel realm, List<AuthenticationFlowRepresentation> flows) {

        for (AuthenticationFlowRepresentation flowRep : flows) {

            if (toSkip.contains(flowRep)) {
                AuthenticationFlowModel existingFlow = realm.getFlowByAlias(flowRep.getAlias());
                if (existingFlow == null) {
                    throw new PartialImportValidationException(
                            "Unable to resolve skipped authentication flow by alias: "
                                    + flowRep.getAlias());
                }

                results.add(new PartialAuthImportResult(
                        PartialAuthImportResult.Action.SKIPPED,
                        "AUTHENTICATION_FLOW",
                        existingFlow.getId(),
                        flowRep.getAlias(),
                        flowRep));
                continue;
            }

            AuthenticationFlowModel flowModel =
                    RepresentationToModel.toModel(flowRep);

            String sourceFlowId = flowRep.getId();

            String destinationFlowId = generateImportFlowId();

            flowModel.setId(destinationFlowId);

            AuthenticationFlowModel importedFlow = realm.addAuthenticationFlow(flowModel);

            LOG.infof(
                    "Imported authentication flow: alias=%s, sourceId=%s, destinationId=%s, overwritten=%s",
                    flowRep.getAlias(),
                    sourceFlowId,
                    importedFlow.getId(),
                    toOverwrite.contains(flowRep)
            );

            if (sourceFlowId != null) {
                sourceToDestinationFlowIds.put(sourceFlowId, importedFlow.getId());
            }

            if (toOverwrite.contains(flowRep)) {
                String existingFlowId = overwriteFlowIds.get(flowRep.getAlias());

                if (existingFlowId == null) {
                    throw new PartialImportValidationException(
                            "Unable to determine previous destination ID for overwritten flow: "
                                    + flowRep.getAlias()
                    );
                }

                existingToNewFlowIds.put(existingFlowId, importedFlow.getId());

                results.add(new PartialAuthImportResult(
                        PartialAuthImportResult.Action.OVERWRITTEN,
                        "AUTHENTICATION_FLOW",
                        importedFlow.getId(),
                        flowRep.getAlias(),
                        flowRep));
            } else {
                results.add(new PartialAuthImportResult(
                        PartialAuthImportResult.Action.ADDED,
                        "AUTHENTICATION_FLOW",
                        importedFlow.getId(),
                        flowRep.getAlias(),
                        flowRep));
            }
        }
    }

    public static String generateImportFlowId() {
        return UUID.randomUUID().toString();
    }

    private void importExecutions(KeycloakSession session, RealmModel realm, List<AuthenticationFlowRepresentation> flows, Map<String, AuthenticatorConfigModel> importedConfigs) {

        for (AuthenticationFlowRepresentation flowRep : flows) {

            if (toSkip.contains(flowRep)) {
                continue;
            }

            AuthenticationFlowModel parentFlow = realm.getFlowByAlias(flowRep.getAlias());

            if (parentFlow == null) {
                throw new PartialImportValidationException("Unable to resolve authentication flow by alias: " + flowRep.getAlias());
            }

            if (flowRep.getAuthenticationExecutions() == null) {
                continue;
            }

            for (AuthenticationExecutionExportRepresentation executionRep : flowRep.getAuthenticationExecutions()) {

                AuthenticationExecutionModel executionModel = toModel(
                        session,
                        realm,
                        parentFlow,
                        executionRep,
                        importedConfigs
                );

                realm.addAuthenticatorExecution(executionModel);
            }
        }
    }

    private void restoreFlowReferences( RealmModel realm) {

        for (Map.Entry<String, AuthenticationFlowReferences> entry :
                flowReferences.entrySet()) {

            String oldFlowId = entry.getKey();

            AuthenticationFlowReferences references = entry.getValue();

            String newFlowId = existingToNewFlowIds.get(oldFlowId);

            if (newFlowId == null) {

                throw new PartialImportValidationException(
                        "Unable to map overwritten authentication flow "
                                + oldFlowId
                );
            }

            references.restore(realm, newFlowId);
        }
    }


    private void removeOrphanedConfigs(RealmModel realm) {

        if (detachedConfigIds.isEmpty()) {
            return;
        }

        Set<String> referenced = realm.getAuthenticationFlowsStream()
                .map(AuthenticationFlowModel::getId)
                .flatMap(realm::getAuthenticationExecutionsStream)
                .map(AuthenticationExecutionModel::getAuthenticatorConfig)
                .filter(Objects::nonNull)
                .collect(Collectors.toSet());

        for (String configId : detachedConfigIds) {

            if (referenced.contains(configId)) {
                continue;
            }

            AuthenticatorConfigModel orphan = realm.getAuthenticatorConfigById(configId);

            if (orphan == null) {
                continue;
            }

            realm.removeAuthenticatorConfig(orphan);

            LOG.infof("Removed orphaned authenticator config: alias=%s", orphan.getAlias());
        }

        detachedConfigIds.clear();
    }

    private static AuthenticationExecutionModel toModel(
            KeycloakSession session,
            RealmModel realm,
            AuthenticationFlowModel parentFlow,
            AuthenticationExecutionExportRepresentation rep,
            Map<String, AuthenticatorConfigModel> importedConfigs) {

        AuthenticationExecutionModel model = new AuthenticationExecutionModel();

        if (rep.getAuthenticatorConfig() != null) {

            AuthenticatorConfigModel config = importedConfigs.get(rep.getAuthenticatorConfig());


            LOG.infof(
                    "Resolving authenticator config: executionConfig=%s, availableConfigs=%s",
                    rep.getAuthenticatorConfig(),
                    importedConfigs.keySet()
            );

            if (config == null) {
                config = new DeployedConfigurationsManager(session)
                        .getAuthenticatorConfigByAlias(realm, rep.getAuthenticatorConfig());
            }

            if (config == null) {
                throw new PartialImportValidationException("Unable to resolve authenticator config: " + rep.getAuthenticatorConfig());
            }

            model.setAuthenticatorConfig(config.getId());
        }

        model.setAuthenticator(rep.getAuthenticator());
        model.setAuthenticatorFlow(rep.isAuthenticatorFlow());

        if (!rep.isAuthenticatorFlow()) {
            validateAuthenticatorProvider(session, parentFlow.getProviderId(), rep.getAuthenticator());
        }

        if (rep.getFlowAlias() != null) {

            AuthenticationFlowModel flow = realm.getFlowByAlias(rep.getFlowAlias());

            if (flow == null) {
                throw new PartialImportValidationException(
                        "Unable to resolve authentication flow by alias: "
                                + rep.getFlowAlias());
            }

            model.setFlowId(flow.getId());
        }

        if (rep.getPriority() != null) {
            model.setPriority(rep.getPriority());
        }

        String requirement = rep.getRequirement();
        if (requirement == null || requirement.isBlank()) {
            throw new PartialImportValidationException("Authentication execution requirement cannot be null: " + rep.getAuthenticator());
        }

        try {
            model.setRequirement(AuthenticationExecutionModel.Requirement.valueOf(requirement));

            model.setParentFlow(parentFlow.getId());

        } catch (IllegalArgumentException iae) {

            if ("OPTIONAL".equals(rep.getRequirement())) {
                MigrateTo8_0_0.migrateOptionalAuthenticationExecution(realm, parentFlow, model, false);
            } else {

                throw new PartialImportValidationException("Invalid authentication execution " + "requirement: " + rep.getRequirement(), iae);
            }
        }

        return model;
    }

    private static void validateAuthenticatorProvider(
            KeycloakSession session,
            String flowProviderId,
            String authenticator) {

        if (authenticator == null || authenticator.isBlank()) {
            throw new PartialImportValidationException("Authentication execution authenticator cannot be null or empty");
        }

        ProviderFactory providerFactory;

        if (AuthenticationFlow.CLIENT_FLOW.equals(flowProviderId)) {
            providerFactory = session.getKeycloakSessionFactory()
                    .getProviderFactory(ClientAuthenticator.class, authenticator);
        } else if (AuthenticationFlow.FORM_FLOW.equals(flowProviderId)) {
            providerFactory = session.getKeycloakSessionFactory()
                    .getProviderFactory(FormAction.class, authenticator);
        } else {
            providerFactory = session.getKeycloakSessionFactory()
                    .getProviderFactory(Authenticator.class, authenticator);
        }

        if (providerFactory == null) {
            throw new PartialImportValidationException(
                    "No authentication provider found for id: " + authenticator);
        }
    }

    private static void validateExecutionAuthenticators(
            KeycloakSession session,
            AuthenticationFlowRepresentation flowRep) {

        if (flowRep.getAuthenticationExecutions() == null) {
            return;
        }

        for (AuthenticationExecutionExportRepresentation executionRep
                : flowRep.getAuthenticationExecutions()) {
            if (executionRep == null) {
                throw new PartialImportValidationException(
                        "Authentication execution cannot be null in flow: " + flowRep.getAlias());
            }

            if (!executionRep.isAuthenticatorFlow()) {
                validateAuthenticatorProvider(
                        session,
                        flowRep.getProviderId(),
                        executionRep.getAuthenticator());
            }
        }
    }


    private void validateFlowRepresentation(AuthenticationFlowRepresentation flowRep) {

        if (flowRep == null) {
            throw new PartialImportValidationException("Authentication flow cannot be null");
        }

        if (flowRep.getAlias() == null || flowRep.getAlias().isBlank()) {

            throw new PartialImportValidationException("Authentication flow alias cannot be null or empty");
        }

        if (flowRep.getProviderId() == null || flowRep.getProviderId().isBlank()) {
            throw new PartialImportValidationException("Authentication flow providerId cannot be null or empty");
        }
    }

    public void remapClientAuthenticationFlowOverrides(PartialAuthImportRepresentation rep) {
        if (rep.getClients() == null || rep.getClients().isEmpty() || sourceToDestinationFlowIds == null || sourceToDestinationFlowIds.isEmpty()) {
            return;
        }

        for (ClientRepresentation clientRep : rep.getClients()) {
            if (clientRep == null || clientRep.getAuthenticationFlowBindingOverrides() == null || clientRep.getAuthenticationFlowBindingOverrides().isEmpty()) {
                continue;
            }

            Map<String, String> remapped = new HashMap<>();

            for (Map.Entry<String, String> entry : clientRep.getAuthenticationFlowBindingOverrides().entrySet()) {
                String binding = entry.getKey();
                String flowRef = entry.getValue();

                if (flowRef == null || flowRef.isBlank()) {
                    continue;
                }

                String mappedFlowId = sourceToDestinationFlowIds.get(flowRef);
                remapped.put(binding, mappedFlowId != null ? mappedFlowId : flowRef);
            }

            clientRep.setAuthenticationFlowBindingOverrides(remapped.isEmpty() ? null : remapped);
        }
    }


    private void bindAuthenticationFlows(PartialAuthImportRepresentation rep, RealmModel realm, KeycloakSession session) {

        bindFlow(realm, rep.getBrowserFlow(), "browserFlow", realm::setBrowserFlow);

        bindFlow(realm, rep.getRegistrationFlow(), "registrationFlow", realm::setRegistrationFlow);

        bindFlow(realm, rep.getDirectGrantFlow(), "directGrantFlow", realm::setDirectGrantFlow);

        bindFlow(realm, rep.getResetCredentialsFlow(), "resetCredentialsFlow", realm::setResetCredentialsFlow);

        bindFlow(realm, rep.getClientAuthenticationFlow(), "clientAuthenticationFlow", realm::setClientAuthenticationFlow);

        bindFlow(realm, rep.getDockerAuthenticationFlow(), "dockerAuthenticationFlow", realm::setDockerAuthenticationFlow);

        bindFlow(realm, rep.getFirstBrokerLoginFlow(), "firstBrokerLoginFlow", realm::setFirstBrokerLoginFlow);

        EntityManagers.flush(session, false);
    }


    private void bindFlow(RealmModel realm, String flowAlias, String bindingName, Consumer<AuthenticationFlowModel> setter) {

        if (flowAlias == null) {
            return;
        }

        if (flowAlias.isBlank()) {
            throw new PartialImportValidationException(bindingName + " cannot be blank");
        }

        AuthenticationFlowModel flow = realm.getFlowByAlias(flowAlias);

        if (flow == null) {
            throw new PartialImportValidationException("No available authentication flow with alias '" + flowAlias + "' for " + bindingName);
        }

        if (!flow.isTopLevel()) {
            throw new PartialImportValidationException(bindingName + " must reference a top-level authentication flow: " + flowAlias);
        }

        setter.accept(flow);

        LOG.infof("Bound %s: alias=%s, id=%s", bindingName, flow.getAlias(), flow.getId());
    }
}
