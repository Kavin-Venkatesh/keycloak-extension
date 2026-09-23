package org.keycloak.partialImport.authImport;

import org.jboss.logging.Logger;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.AuthenticationFlowModel;
import org.keycloak.models.ClientModel;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.RealmModel;
import org.keycloak.models.utils.DefaultAuthenticationFlows;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class AuthenticationFlowReferences {

    private final String oldFlowId;

    private final static Logger LOG = Logger.getLogger(AuthenticationFlowReferences.class);

    private final List<ClientFlowReference> clientFlowReferences = new ArrayList<>();
    private final List<ParentExecutionReference> parentExecutions = new ArrayList<>();
    private RealmBinding realmBinding;
    private final List<IdentityProviderFlowReference> identityProviderReferences = new ArrayList<>();


    private AuthenticationFlowReferences(String oldFlowId) {
        this.oldFlowId = oldFlowId;
    }


    public static AuthenticationFlowReferences capture(RealmModel realm, String flowId, Set<String> overwriteFlowIds) {

        AuthenticationFlowReferences references = new AuthenticationFlowReferences(flowId);

        captureClientReferences(realm, flowId, references);

        captureParentSubflowReferences(realm, flowId , overwriteFlowIds , references);

        captureRealmBinding(realm, flowId, references);

        captureIdentityProviderReferences(realm, flowId, references);

        return references;

    }

    private static void captureIdentityProviderReferences(RealmModel realm, String flowId, AuthenticationFlowReferences references) {
        realm.getIdentityProvidersStream().forEach(identityProvider -> {
            if (flowId.equals(identityProvider.getFirstBrokerLoginFlowId())) {
                references.identityProviderReferences.add(new IdentityProviderFlowReference(
                        identityProvider.getAlias(), IdentityProviderFlowBinding.FIRST_BROKER_LOGIN));
            }
            if (flowId.equals(identityProvider.getPostBrokerLoginFlowId())) {
                references.identityProviderReferences.add(new IdentityProviderFlowReference(
                        identityProvider.getAlias(), IdentityProviderFlowBinding.POST_BROKER_LOGIN));
            }
        });
    }

    private static void captureRealmBinding(RealmModel realm, String flowId, AuthenticationFlowReferences references) {

        if (realm.getBrowserFlow() != null && flowId.equals(realm.getBrowserFlow().getId())) {
            references.realmBinding = RealmBinding.BROWSER;
            return;
        }

        if (realm.getRegistrationFlow() != null && flowId.equals(realm.getRegistrationFlow().getId())) {
            references.realmBinding = RealmBinding.REGISTRATION;
            return;
        }

        if (realm.getDirectGrantFlow() != null && flowId.equals(realm.getDirectGrantFlow().getId())) {
            references.realmBinding = RealmBinding.DIRECT_GRANT;
            return;
        }

        if (realm.getResetCredentialsFlow() != null && flowId.equals(realm.getResetCredentialsFlow().getId())) {
            references.realmBinding = RealmBinding.RESET_CREDENTIALS;
            return;
        }

        if (realm.getClientAuthenticationFlow() != null && flowId.equals(realm.getClientAuthenticationFlow().getId())) {
            references.realmBinding = RealmBinding.CLIENT_AUTHENTICATION;
            return;
        }

        if (realm.getDockerAuthenticationFlow() != null && flowId.equals(realm.getDockerAuthenticationFlow().getId())) {
            references.realmBinding = RealmBinding.DOCKER_AUTHENTICATION;
            return;
        }

        if (realm.getFirstBrokerLoginFlow() != null && flowId.equals(realm.getFirstBrokerLoginFlow().getId())) {
            references.realmBinding = RealmBinding.FIRST_BROKER_LOGIN;
        }
    }


    private static void captureClientReferences(RealmModel realm, String flowId, AuthenticationFlowReferences references) {

        realm.getClientsStream().forEach(client -> {

            Map<String, String> overrides = client.getAuthenticationFlowBindingOverrides();

            if (overrides == null || overrides.isEmpty()) {
                return;
            }

            overrides.forEach((binding, referencedFlowId) -> {

                if (flowId.equals(referencedFlowId)) {

                    references.clientFlowReferences.add(
                            new ClientFlowReference(
                                    client.getId(),
                                    binding
                            )
                    );
                }
            });
        });
    }


    private static void captureParentSubflowReferences(
            RealmModel realm,
            String flowId,
            Set<String> overwriteFlowIds,
            AuthenticationFlowReferences references) {

        realm.getAuthenticationFlowsStream()
                .filter(parentFlow ->
                        !overwriteFlowIds.contains(parentFlow.getId()))
                .forEach(parentFlow -> {

                    realm.getAuthenticationExecutionsStream(
                                    parentFlow.getId())
                            .filter(AuthenticationExecutionModel::isAuthenticatorFlow)
                            .filter(execution ->
                                    flowId.equals(execution.getFlowId()))
                            .forEach(execution ->
                                    references.parentExecutions.add(
                                            ParentExecutionReference.capture(
                                                    parentFlow,
                                                    execution
                                            )
                                    )
                            );
                });
    }


    public void detach(RealmModel realm) {

        for (ClientFlowReference reference : clientFlowReferences) {

            ClientModel client =
                    realm.getClientById(reference.clientId());

            if (client != null) {
                client.removeAuthenticationFlowBindingOverride(
                        reference.binding()
                );
            }
        }

        for (ParentExecutionReference reference : parentExecutions) {

            AuthenticationExecutionModel execution =
                    realm.getAuthenticationExecutionById(
                            reference.executionId()
                    );

            if (execution != null) {
                realm.removeAuthenticatorExecution(execution);
            }
        }

        detachRealmBindings(realm);
        detachIdentityProviderReferences(realm);
    }

    private void detachIdentityProviderReferences(RealmModel realm) {
        for (IdentityProviderFlowReference reference : identityProviderReferences) {
            IdentityProviderModel identityProvider = realm.getIdentityProviderByAlias(reference.identityProviderAlias());
            if (identityProvider == null) {
                continue;
            }
            if (reference.binding() == IdentityProviderFlowBinding.FIRST_BROKER_LOGIN) {
                identityProvider.setFirstBrokerLoginFlowId(null);
            } else {
                identityProvider.setPostBrokerLoginFlowId(null);
            }
            realm.updateIdentityProvider(identityProvider);
        }
    }

    private void detachRealmBindings(RealmModel realm) {

        if (realmBinding == null) {
            return;
        }

        AuthenticationFlowModel placeholder = getPlaceholderFlow(realm, realmBinding);

        if (placeholder == null) {
            throw new IllegalStateException("Unable to resolve built-in placeholder flow for realm binding " + realmBinding.name() + ": " + realmBinding.placeholderAlias());
        }

        setRealmBinding(realm, realmBinding, placeholder);
    }


    public void restore(RealmModel realm, String newFlowId) {

        AuthenticationFlowModel newFlow = realm.getAuthenticationFlowById(newFlowId);

        if (newFlow == null) {
            throw new IllegalStateException("Unable to restore authentication flow reference. " + "New flow does not exist: " + newFlowId);
        }

        restoreClientReferences(realm, newFlowId);
        restoreParentSubflowReferences(realm, newFlowId);
        restoreRealmBinding(realm, newFlow);
        restoreIdentityProviderReferences(realm, newFlowId);
    }

    private void restoreIdentityProviderReferences(RealmModel realm, String newFlowId) {
        for (IdentityProviderFlowReference reference : identityProviderReferences) {
            IdentityProviderModel identityProvider = realm.getIdentityProviderByAlias(reference.identityProviderAlias());
            if (identityProvider == null) {
                continue;
            }
            if (reference.binding() == IdentityProviderFlowBinding.FIRST_BROKER_LOGIN) {
                identityProvider.setFirstBrokerLoginFlowId(newFlowId);
            } else {
                identityProvider.setPostBrokerLoginFlowId(newFlowId);
            }
            realm.updateIdentityProvider(identityProvider);
        }
    }

    private void restoreRealmBinding(RealmModel realm, AuthenticationFlowModel newFlow) {
        if (realmBinding == null) {
            return;
        }
        setRealmBinding(realm, realmBinding, newFlow);
    }

    private void restoreClientReferences(
            RealmModel realm,
            String newFlowId) {

        LOG.infof("Restoring the client refereneces");
        for (ClientFlowReference reference : clientFlowReferences) {

            ClientModel client = realm.getClientById(reference.clientId());

            if (client == null) {
                continue;
            }

            client.setAuthenticationFlowBindingOverride(reference.binding(), newFlowId);
        }
    }


    private void restoreParentSubflowReferences(RealmModel realm, String newFlowId) {

        LOG.infof("Restoring the parent flow refereneces");
        for (ParentExecutionReference reference : parentExecutions) {

            AuthenticationFlowModel parentFlow = realm.getAuthenticationFlowById(reference.parentFlowId());

            if (parentFlow == null) {
                throw new IllegalStateException("Unable to restore parent flow reference. " + "Parent flow does not exist: " + reference.parentFlowId());
            }

            AuthenticationExecutionModel execution = new AuthenticationExecutionModel();

            execution.setAuthenticator(reference.authenticator());

            execution.setAuthenticatorConfig(reference.authenticatorConfig());

            execution.setAuthenticatorFlow(reference.authenticatorFlow());

            execution.setFlowId(newFlowId);

            execution.setParentFlow(parentFlow.getId());

            execution.setPriority(reference.priority());

            execution.setRequirement(reference.requirement());

            realm.addAuthenticatorExecution(execution);
        }
    }

    private static AuthenticationFlowModel getPlaceholderFlow(RealmModel realm, RealmBinding binding) {
        return realm.getFlowByAlias(binding.placeholderAlias());
    }


    private static void setRealmBinding(
            RealmModel realm,
            RealmBinding binding,
            AuthenticationFlowModel flow) {

        switch (binding) {

            case BROWSER -> realm.setBrowserFlow(flow);

            case REGISTRATION -> realm.setRegistrationFlow(flow);

            case DIRECT_GRANT -> realm.setDirectGrantFlow(flow);

            case RESET_CREDENTIALS -> realm.setResetCredentialsFlow(flow);

            case CLIENT_AUTHENTICATION -> realm.setClientAuthenticationFlow(flow);

            case DOCKER_AUTHENTICATION -> realm.setDockerAuthenticationFlow(flow);

            case FIRST_BROKER_LOGIN -> realm.setFirstBrokerLoginFlow(flow);
        }
    }

    private record ClientFlowReference(
            String clientId,
            String binding) {
    }

    private record IdentityProviderFlowReference(
            String identityProviderAlias,
            IdentityProviderFlowBinding binding) {
    }

    private enum IdentityProviderFlowBinding {
        FIRST_BROKER_LOGIN,
        POST_BROKER_LOGIN
    }

    private enum RealmBinding {

        BROWSER(
                DefaultAuthenticationFlows.BROWSER_FLOW
        ),

        REGISTRATION(
                DefaultAuthenticationFlows.REGISTRATION_FLOW
        ),

        DIRECT_GRANT(
                DefaultAuthenticationFlows.DIRECT_GRANT_FLOW
        ),

        RESET_CREDENTIALS(
                DefaultAuthenticationFlows.RESET_CREDENTIALS_FLOW
        ),

        CLIENT_AUTHENTICATION(
                DefaultAuthenticationFlows.CLIENT_AUTHENTICATION_FLOW
        ),

        DOCKER_AUTHENTICATION(
                DefaultAuthenticationFlows.DOCKER_AUTH
        ),

        FIRST_BROKER_LOGIN(
                DefaultAuthenticationFlows.FIRST_BROKER_LOGIN_FLOW
        );

        private final String placeholderAlias;

        RealmBinding(String placeholderAlias) {
            this.placeholderAlias = placeholderAlias;
        }

        String placeholderAlias() {
            return placeholderAlias;
        }
    }

    public record ParentExecutionReference(
            String executionId,
            String parentFlowId,
            String authenticator,
            String authenticatorConfig,
            boolean authenticatorFlow,
            int priority,
            AuthenticationExecutionModel.Requirement requirement) {

        public static ParentExecutionReference capture(
                AuthenticationFlowModel parentFlow,
                AuthenticationExecutionModel execution) {

            return new ParentExecutionReference(
                    execution.getId(),
                    parentFlow.getId(),
                    execution.getAuthenticator(),
                    execution.getAuthenticatorConfig(),
                    execution.isAuthenticatorFlow(),
                    execution.getPriority(),
                    execution.getRequirement()
            );
        }
    }
}
