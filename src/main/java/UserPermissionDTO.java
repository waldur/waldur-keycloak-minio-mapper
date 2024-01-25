import java.util.List;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

@JsonIgnoreProperties(ignoreUnknown = true)
public class UserPermissionDTO {
    @JsonProperty("project_permissions")
    private List<ProjectPermission> projectPermissions;

    @JsonProperty("customer_permissions")
    private List<CustomerPermission> customerPermissions;

    public List<ProjectPermission> getProjectPermissions() {
        return projectPermissions;
    }

    public List<CustomerPermission> getCustomerPermissions() {
        return customerPermissions;
    }
}
