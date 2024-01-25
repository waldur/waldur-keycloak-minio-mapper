import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

@JsonIgnoreProperties(ignoreUnknown = true)
public class ProjectPermission {
    @JsonProperty("project_uuid")
    private String projectUUID;

    public String getProjectUUID() {
        return projectUUID;
    }
}
