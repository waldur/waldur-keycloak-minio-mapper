import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

@JsonIgnoreProperties(ignoreUnknown = true)
public class CustomerPermission {
    @JsonProperty("customer_uuid")
    private String customerUUID;

    public String getCustomerUUID() {
        return customerUUID;
    }
}
