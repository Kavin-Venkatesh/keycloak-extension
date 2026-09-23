package org.keycloak.partialImport.result;

import org.keycloak.partialimport.Action;
import org.keycloak.partialimport.PartialImportResult;
import org.keycloak.partialimport.PartialImportResults;

import java.util.ArrayList;
import java.util.List;

public class PartialAuthImportResults {

    private int added;
    private int skipped;
    private int overwritten;

    private final List<PartialAuthImportResult> results =
            new ArrayList<>();

    public void add(PartialAuthImportResult result) {

        results.add(result);

        switch (result.getAction()) {
            case ADDED -> added++;
            case SKIPPED -> skipped++;
            case OVERWRITTEN -> overwritten++;
        }
    }

    public void addStandardResults(
            PartialImportResults standardResults) {

        if (standardResults == null
                || standardResults.getResults() == null) {
            return;
        }

        for (PartialImportResult result :
                standardResults.getResults()) {

            add(
                    new PartialAuthImportResult(
                            convertAction(result.getAction()),
                            result.getResourceType().name(),
                            result.getId(),
                            result.getResourceName(),
                            result.getRepresentation()
                    )
            );
        }
    }

    private PartialAuthImportResult.Action convertAction(
            Action action) {

        return switch (action) {
            case ADDED ->
                    PartialAuthImportResult.Action.ADDED;

            case SKIPPED ->
                    PartialAuthImportResult.Action.SKIPPED;

            case OVERWRITTEN ->
                    PartialAuthImportResult.Action.OVERWRITTEN;
        };
    }

    public int getAdded() {
        return added;
    }

    public int getSkipped() {
        return skipped;
    }

    public int getOverwritten() {
        return overwritten;
    }

    public List<PartialAuthImportResult> getResults() {
        return results;
    }
}