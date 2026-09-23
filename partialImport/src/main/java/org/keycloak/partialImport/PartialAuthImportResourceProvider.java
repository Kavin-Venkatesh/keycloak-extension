package org.keycloak.partialImport;


import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import org.eclipse.microprofile.openapi.annotations.Operation;
import org.eclipse.microprofile.openapi.annotations.media.Content;
import org.eclipse.microprofile.openapi.annotations.media.Schema;
import org.eclipse.microprofile.openapi.annotations.responses.APIResponse;
import org.eclipse.microprofile.openapi.annotations.responses.APIResponses;
import org.eclipse.microprofile.openapi.annotations.tags.Tag;
import org.keycloak.connections.jpa.support.EntityManagers;
import org.keycloak.events.admin.OperationType;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.ModelDuplicateException;
import org.keycloak.models.ModelException;
import org.keycloak.models.RealmModel;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.partialImport.authImport.AuthenticationFlowsPartialImport;
import org.keycloak.partialImport.authImport.RequiredActionsPartialImport;
import org.keycloak.partialImport.exception.PartialImportConflictException;
import org.keycloak.partialImport.exception.PartialImportValidationException;
import org.keycloak.partialImport.representation.PartialAuthImportRepresentation;
import org.keycloak.partialImport.result.PartialAuthImportResult;
import org.keycloak.partialImport.result.PartialAuthImportResults;
import org.keycloak.partialimport.PartialImportManager;
import org.keycloak.partialimport.PartialImportResult;
import org.keycloak.partialimport.PartialImportResults;
import org.keycloak.representations.idm.ClientRepresentation;
import org.keycloak.services.ErrorResponse;
import org.keycloak.services.ErrorResponseException;
import org.keycloak.services.resources.KeycloakOpenAPI;
import org.keycloak.services.resources.admin.AdminEventBuilder;
import org.keycloak.services.resources.admin.ext.AdminRealmResourceProvider;
import org.keycloak.services.resources.admin.fgap.AdminPermissionEvaluator;
import org.keycloak.util.JsonSerialization;

import java.io.IOException;
import java.io.InputStream;
import java.util.List;

import org.jboss.logging.Logger;

public class PartialAuthImportResourceProvider implements AdminRealmResourceProvider {

    private static final Logger LOG = Logger.getLogger(PartialAuthImportResourceProvider.class);

    private final KeycloakSession session;
    private AdminPermissionEvaluator permissionEvaluator;
    private AdminEventBuilder adminEvent;

    public PartialAuthImportResourceProvider(KeycloakSession session){
        this.session = session;
    }
    @Override
    public Object getResource(KeycloakSession session,
                              RealmModel realm,
                              AdminPermissionEvaluator auth,
                              AdminEventBuilder adminEvent
    ) {
        this.permissionEvaluator = auth;
        this.adminEvent = adminEvent;
        return this;

    }

    @Override
    public void close() {

    }

    @Path("partialImportWithAuthFlows")
    @POST
    @Produces(MediaType.APPLICATION_JSON)
    @Consumes(MediaType.APPLICATION_JSON)
    @Tag(name = KeycloakOpenAPI.Admin.Tags.REALMS_ADMIN)
    @Operation(summary = "Partial import from a JSON file to an existing realm with Authentication flows and Required Actions.")
    @APIResponses(value = {
            @APIResponse(responseCode = "200", description = "OK", content = @Content(schema = @Schema(implementation = PartialAuthImportResults.class))),
            @APIResponse(responseCode = "400", description = "Invalid partial import request"),
            @APIResponse(responseCode = "403", description = "Forbidden"),
            @APIResponse(responseCode = "409", description = "Conflict"),
            @APIResponse(responseCode = "500", description = "Internal server error")
    })
    public Response partialAuthImport(InputStream requestBody){
        permissionEvaluator.realm().requireManageRealm();

        try {

            LOG.infof("Entered the partial import SPI provider ")
            return Response.ok(
                    KeycloakModelUtils.runJobInTransactionWithResult(session.getKeycloakSessionFactory(), session.getContext(), kcSession -> {
                        RealmModel kcRealm = kcSession.realms().getRealm(
                                session.getContext().getRealm().getId());
                        AdminEventBuilder adminEventClone = adminEvent.clone(kcSession);

                        PartialAuthImportRepresentation rep;
                        try{
                            rep = JsonSerialization.readValue( requestBody , PartialAuthImportRepresentation.class);
                        }catch (IOException e) {
                            throw new PartialImportValidationException("unable to read contents from stream", e);
                        }

                        return importResource(kcSession,kcRealm,rep, adminEventClone);

                    }, "Partial import in realm " + session.getContext().getRealm().getName())
            ).build();
        } catch (ErrorResponseException e) {
        throw e;
    } catch (PartialImportConflictException e) {
        throw ErrorResponse.exists(e.getMessage());
    } catch (PartialImportValidationException e) {
        throw ErrorResponse.error(
                e.getMessage(),
                Response.Status.BAD_REQUEST
        );
    } catch (ModelDuplicateException e) {
        throw ErrorResponse.exists(e.getMessage());
    } catch (IllegalArgumentException e) {
        throw ErrorResponse.error(
                e.getMessage(),
                Response.Status.BAD_REQUEST
        );
    } catch (Exception e) {
        LOG.error("Unable to perform partial authentication import", e);
        throw ErrorResponse.error(
                "Unable to perform partial authentication import",
                Response.Status.INTERNAL_SERVER_ERROR
        );
    }
    }

    private PartialAuthImportResults importResource(
            KeycloakSession session,
            RealmModel realm,
            PartialAuthImportRepresentation rep,
            AdminEventBuilder adminEvent) {

        List<PartialAuthImportResult> authenticationFlowResults = importAuthenticationFlows(session, realm, rep);
        List<PartialAuthImportResult> requiredActionResults = importRequiredActions(session, realm, rep);
        //import clients
        PartialImportManager partialImportManager = new PartialImportManager( rep, session, realm);
        PartialImportResults standardResults = partialImportManager.saveResources();

        PartialAuthImportResults results = new PartialAuthImportResults();

        results.addStandardResults(standardResults);

        authenticationFlowResults.forEach(results::add);

        requiredActionResults.forEach(results::add);

        fireStandardAdminEvents(standardResults, adminEvent);

        fireCustomAdminEvents(authenticationFlowResults, adminEvent);

        fireCustomAdminEvents(requiredActionResults, adminEvent);

        return results;
    }

    private List<PartialAuthImportResult> importAuthenticationFlows(KeycloakSession session, RealmModel realm, PartialAuthImportRepresentation rep) {

        AuthenticationFlowsPartialImport importer = new AuthenticationFlowsPartialImport();

        importer.prepare(rep, realm, session);

        importer.removeOverwrites(realm, session);

        EntityManagers.flush(session, false);

        List<PartialAuthImportResult> results = importer.doImport(rep, realm, session);

        EntityManagers.flush(session, false);

        importer.remapClientAuthenticationFlowOverrides(rep);

        return results;
    }


    private List<PartialAuthImportResult> importRequiredActions(KeycloakSession session, RealmModel realm, PartialAuthImportRepresentation rep) {

        RequiredActionsPartialImport importer = new RequiredActionsPartialImport();

        importer.prepare(rep, realm, session);

        return importer.doImport(rep, realm, session);
    }


    private static void fireStandardAdminEvents(
            PartialImportResults results,
            AdminEventBuilder adminEvent) {

        for (PartialImportResult result : results.getResults()) {

            switch (result.getAction()) {

                case ADDED:
                    adminEvent.operation(OperationType.CREATE)
                            .resourcePath(result.getResourceType().getPath(),
                                    result.getId())
                            .representation(result.getRepresentation()).success();
                    break;

                case OVERWRITTEN:
                    adminEvent.operation(OperationType.UPDATE)
                            .resourcePath(result.getResourceType().getPath(),
                                    result.getId())
                            .representation(result.getRepresentation()).success();
                    break;

                case SKIPPED:
                    // No state change, therefore no audit event.
                    break;
            }
        }
    }

    private static void fireCustomAdminEvents(
            List<PartialAuthImportResult> results,
            AdminEventBuilder adminEvent) {

        for (PartialAuthImportResult result : results) {

            switch (result.getAction()) {

                case ADDED:
                    adminEvent.operation(OperationType.CREATE)
                            .resourcePath(getResourcePath(result.getResourceType()),
                                    result.getId())
                            .representation(result.getRepresentation()).success();
                    break;

                case OVERWRITTEN:
                    adminEvent.operation(OperationType.UPDATE)
                            .resourcePath(getResourcePath(result.getResourceType()),
                                    result.getId())
                            .representation(result.getRepresentation()).success();
                    break;

                case SKIPPED:
                    // No state change, therefore no audit event.
                    break;
            }
        }
    }

    private static String getResourcePath(String resourceType) {

        return switch (resourceType) {

            case "AUTHENTICATION_FLOW" ->
                    "authentication/flows";

            case "REQUIRED_ACTION" ->
                    "authentication/required-actions";

            case "AUTHENTICATOR_CONFIG" ->
                    "authentication/config";

            default ->
                    throw new IllegalArgumentException("Unknown custom resource type: " + resourceType);
        };
    }


    }
