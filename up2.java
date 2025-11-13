import io.restassured.http.ContentType;
import java.util.Map;
import static io.restassured.RestAssured.given;

public class FindClassification {

    // --- START: CONFIGURATION ---
    private static final String TENANT_NAME = "your-tenant-name";
    private static final String ACCESS_TOKEN = "your-bearer-access-token";
    
    // The name of the folder you are looking for
    private static final String CLASSIFICATION_LABEL_TO_FIND = "Product Images"; 
    // --- END: CONFIGURATION ---

    public static void main(String[] args) {
        
        // This is the endpoint for searching for classifications
        String searchUrl = String.format("https://%s.dam.aprimo.com/api/core/search/classifications", TENANT_NAME);

        // Build the search query payload
        // We are searching for a classification where its Label matches
        Map<String, Object> jsonPayload = Map.of(
            "searchExpression", Map.of(
                "expression", String.format("Label = '%s'", CLASSIFICATION_LABEL_TO_FIND)
            ),
            "pageSize", 1 // We only need the first match
        );

        System.out.println("Searching for classification with label: '" + CLASSIFICATION_LABEL_TO_FIND + "'");

        try {
            String classificationId = given()
                .header("Authorization", "Bearer " + ACCESS_TOKEN)
                .header("API-VERSION", "1")
                .contentType(ContentType.JSON)
                .body(jsonPayload)
            .when()
                .post(searchUrl)
            .then()
                .statusCode(200)
                .log().ifError()
                .extract()
                // The ID is inside the first item in the 'items' array
                .path("items[0].id"); 
            
            if (classificationId == null || classificationId.isEmpty()) {
                System.out.println("Error: Classification not found with that label.");
            } else {
                System.out.println("SUCCESS! Found CLASSIFICATION_ID: " + classificationId);
            }

        } catch (Exception e) {
            System.err.println("Error during search: " + e.getMessage());
            System.err.println("Please check your token, tenant name, and if the classification label is correct.");
        }
    }
}
