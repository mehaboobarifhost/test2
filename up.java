import io.restassured.http.ContentType;
import java.io.File;
import java.util.List;
import java.util.Map;

import static io.restassured.RestAssured.given;

public class AprimoUploaderRestAssured {

    // --- START: CONFIGURATION ---
    // TODO: Update these values with your details
    private static final String TENANT_NAME = "your-tenant-name";
    private static final String ACCESS_TOKEN = "your-bearer-access-token";
    private static final String FILE_PATH = "/path/to/your/image.jpg";
    private static final String CLASSIFICATION_ID = "your-classification-id";
    // --- END: CONFIGURATION ---

    public static void main(String[] args) {

        // --- Step 1: Upload the file to get an uploadToken ---
        
        String uploadUrl = String.format("https://%s.aprimo.com/uploads", TENANT_NAME);
        File fileToUpload = new File(FILE_PATH);
        String fileName = fileToUpload.getName();

        System.out.println("Step 1: Uploading file " + fileName + " to " + uploadUrl);

        String uploadToken = given()
            .header("Authorization", "Bearer " + ACCESS_TOKEN)
            .multiPart("file", fileToUpload)
            .log().ifValidationFails() // Log request if validation fails
        .when()
            .post(uploadUrl)
        .then()
            .statusCode(200) // Expect HTTP 200 OK
            .contentType(ContentType.JSON)
            .log().ifError() // Log response if an error occurs
            .extract()
            .path("token"); // Extract the 'token' field from the JSON response

        System.out.println("SUCCESS (Step 1): File uploaded. Token: " + uploadToken);


        // --- Step 2: Create the asset record using the uploadToken ---
        
        String createRecordUrl = String.format("https://%s.dam.aprimo.com/api/core/records", TENANT_NAME);

        // Build the JSON payload as a structure of Maps and Lists
        // This will be automatically serialized to JSON by RestAssured
        Map<String, Object> jsonPayload = Map.of(
            "classifications", Map.of(
                "addOrUpdate", List.of(
                    Map.of("id", CLASSIFICATION_ID)
                )
            ),
            "files", Map.of(
                "master", uploadToken,
                "addOrUpdate", List.of(
                    Map.of(
                        "versions", Map.of(
                            "addOrUpdate", List.of(
                                Map.of(
                                    "id", uploadToken,
                                    "fileName", fileName
                                )
                            )
                        )
                    )
                )
            )
        );

        System.out.println("Step 2: Creating record for token: " + uploadToken);

        String recordId = given()
            .header("Authorization", "Bearer " + ACCESS_TOKEN)
            .header("API-VERSION", "1")
            .contentType(ContentType.JSON) // Set content type to application/json
            .body(jsonPayload) // Pass the Map as the body
            .log().ifValidationFails()
        .when()
            .post(createRecordUrl)
        .then()
            // Aprimo documentation suggests 200-299 is valid.
            // 201 (Created) is common, but we'll check for 200.
            .statusCode(200) 
            .contentType(ContentType.JSON)
            .log().ifError()
            .extract()
            .path("id"); // Extract the 'id' of the newly created record

        System.out.println("SUCCESS (Step 2): Record created. ID: " + recordId);
        System.out.println("\nAsset creation complete!");
        System.out.printf("View asset at: https://%s.dam.aprimo.com/dam/record/%s/view%n", TENANT_NAME, recordId);
    }
}
