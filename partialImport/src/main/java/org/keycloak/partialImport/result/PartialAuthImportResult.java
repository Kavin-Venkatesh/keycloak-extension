package org.keycloak.partialImport.result;

import com.fasterxml.jackson.annotation.JsonInclude;

@JsonInclude(JsonInclude.Include.NON_NULL)
public class PartialAuthImportResult {

    public enum Action {
        ADDED,
        SKIPPED,
        OVERWRITTEN
    }

    private Action action;
    private String resourceType;
    private String id;
    private String resourceName;
    private Object representation;

    public PartialAuthImportResult() {
    }

    public PartialAuthImportResult(
            Action action,
            String resourceType,
            String id,
            String resourceName,
            Object representation) {

        this.action = action;
        this.resourceType = resourceType;
        this.id = id;
        this.resourceName = resourceName;
        this.representation = representation;
    }

    public Action getAction() {
        return action;
    }

    public void setAction(Action action) {
        this.action = action;
    }

    public String getResourceType() {
        return resourceType;
    }

    public void setResourceType(String resourceType) {
        this.resourceType = resourceType;
    }

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getResourceName() {
        return resourceName;
    }

    public void setResourceName(String resourceName) {
        this.resourceName = resourceName;
    }

    public Object getRepresentation() {
        return representation;
    }

    public void setRepresentation(Object representation) {
        this.representation = representation;
    }
}
