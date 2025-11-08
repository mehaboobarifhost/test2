# Client API
```java
/**
     * Gets a specific record from Aprimo DAM.
     * @param recordId The ID (GUID) of the record to retrieve.
     * @return The full RestAssured Response object.
     */
    public Response getRecordById(String recordId) {
        Response response = requestSpec
                .when()
                // Use the recordId as a path parameter
                .get("/record/{id}", recordId);

        // Keep the error logging we added
        if (response.getStatusCode() < 200 || response.getStatusCode() >= 300) {
            System.out.println("Error Response Body:");
            response.then().log().all();
        }

        return response;
    }
```
# Data Model Layer (New POJO: Record.java)
package com.mycompany.framework.models;
```java
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

// Ignores any fields in the JSON that we don't map in this class
@JsonIgnoreProperties(ignoreUnknown = true)
public class Record {

    @JsonProperty("id")
    private String id;

    @JsonProperty("title")
    private String title;

    // This is just a guess, check your JSON response for the correct field name
    @JsonProperty("fileName") 
    private String fileName;

    // --- Getters and Setters ---

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getTitle() {
        return title;
    }

    public void setTitle(String title) {
        this.title = title;
    }

    public String getFileName() {
        return fileName;
    }

    public void setFileName(String fileName) {
        this.fileName = fileName;
    }
}
```

# BDD Layer (Gherkin & Step Definitions)
Here is how you would write a test for this new method.

record.feature (Example Gherkin)
```gherkin
Feature: Aprimo Record Management

  Scenario: Retrieve a specific record by ID
    Given I am an authenticated user with API access
    When I request the record with ID "a1b2c3d4-e5f6-7890-a1b2-c3d4e5f67890"
    Then the API response status should be 200
    And the response should contain a record with title "My_Asset_Title"
```
