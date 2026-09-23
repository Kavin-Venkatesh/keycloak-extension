package org.keycloak.partialImport.representation;


import com.fasterxml.jackson.annotation.JsonAlias;
import com.fasterxml.jackson.annotation.JsonProperty;
import org.keycloak.representations.idm.AuthenticationFlowRepresentation;
import org.keycloak.representations.idm.AuthenticatorConfigRepresentation;
import org.keycloak.representations.idm.PartialImportRepresentation;
import org.keycloak.representations.idm.RequiredActionProviderRepresentation;
import org.keycloak.representations.idm.RealmRepresentation;

import java.util.List;

public class PartialAuthImportRepresentation extends  PartialImportRepresentation{

    private List<AuthenticatorConfigRepresentation> authenticatorConfig;
    private List<AuthenticationFlowRepresentation> authenticationFlows;
    private List<RequiredActionProviderRepresentation> requiredActions;

    private String browserFlow;
    private String registrationFlow;
    private String directGrantFlow;
    private String resetCredentialsFlow;
    private String clientAuthenticationFlow;
    private String dockerAuthenticationFlow;
    private String firstBrokerLoginFlow;


    public List<AuthenticationFlowRepresentation> getAuthenticationFlows() {
        return authenticationFlows;
    }

    public void setAuthenticationFlows(List<AuthenticationFlowRepresentation> authenticationFlows) {
        this.authenticationFlows = authenticationFlows;
    }

    public List<AuthenticatorConfigRepresentation> getAuthenticatorConfig() {
        return authenticatorConfig;
    }

    public void setAuthenticatorConfig(List<AuthenticatorConfigRepresentation> authenticatorConfig) {
        this.authenticatorConfig = authenticatorConfig;
    }

    public List<RequiredActionProviderRepresentation> getRequiredActions() {
        return requiredActions;
    }

    public void setRequiredActions(List<RequiredActionProviderRepresentation> requiredActions) {
        this.requiredActions = requiredActions;
    }

    public String getBrowserFlow() {
        return browserFlow;
    }

    public void setBrowserFlow(String browserFlow) {
        this.browserFlow = browserFlow;
    }

    public String getResetCredentialsFlow() {
        return resetCredentialsFlow;
    }

    public void setResetCredentialsFlow(String resetCredentialsFlow) {
        this.resetCredentialsFlow = resetCredentialsFlow;
    }

    public String getRegistrationFlow() {
        return registrationFlow;
    }

    public void setRegistrationFlow(String registrationFlow) {
        this.registrationFlow = registrationFlow;
    }

    public String getFirstBrokerLoginFlow() {
        return firstBrokerLoginFlow;
    }

    public void setFirstBrokerLoginFlow(String firstBrokerLoginFlow) {
        this.firstBrokerLoginFlow = firstBrokerLoginFlow;
    }

    public String getDockerAuthenticationFlow() {
        return dockerAuthenticationFlow;
    }

    public void setDockerAuthenticationFlow(String dockerAuthenticationFlow) {
        this.dockerAuthenticationFlow = dockerAuthenticationFlow;
    }

    public String getDirectGrantFlow() {
        return directGrantFlow;
    }

    public void setDirectGrantFlow(String directGrantFlow) {
        this.directGrantFlow = directGrantFlow;
    }

    public String getClientAuthenticationFlow() {
        return clientAuthenticationFlow;
    }

    public void setClientAuthenticationFlow(String clientAuthenticationFlow) {
        this.clientAuthenticationFlow = clientAuthenticationFlow;
    }
}
