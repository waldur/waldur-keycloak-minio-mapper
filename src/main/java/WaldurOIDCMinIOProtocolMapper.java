import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import org.apache.http.HttpEntity;
import org.apache.http.HttpHeaders;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.conn.ssl.NoopHostnameVerifier;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;
import org.keycloak.models.ClientSessionContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.ProtocolMapperModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.protocol.oidc.mappers.*;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.representations.IDToken;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import org.jboss.logging.Logger;

public class WaldurOIDCMinIOProtocolMapper extends AbstractOIDCProtocolMapper
        implements OIDCAccessTokenMapper, OIDCIDTokenMapper, UserInfoTokenMapper {

    public static final String PROVIDER_ID = "oidc-waldurminiomapper";

    private static final List<ProviderConfigProperty> configProperties =
            new ArrayList<ProviderConfigProperty>();

    private static final Logger LOGGER =
            Logger.getLogger(WaldurOIDCMinIOProtocolMapper.class.getName());

    private static final ObjectMapper jacksonMapper;

    private static final String API_URL_KEY = "url.waldur.api.value";
    private static final String API_TOKEN_KEY = "token.waldur.value";
    private static final String PERMISSION_SCOPE_TYPE = "scope-type.waldur.validate";
    private static final String API_TLS_VALIDATE_KEY = "tls.waldur.validate";

    static {
        ProviderConfigProperty urlProperty = new ProviderConfigProperty(API_URL_KEY,
                "Waldur API URL",
                "URL to the Waldur API including trailing backslash, e.g. https://waldur.example.com/api/",
                ProviderConfigProperty.STRING_TYPE, "");
        configProperties.add(urlProperty);

        ProviderConfigProperty waldurTokenProperty = new ProviderConfigProperty(API_TOKEN_KEY,
                "Waldur API token", "Token for Waldur API", ProviderConfigProperty.STRING_TYPE, "");
        configProperties.add(waldurTokenProperty);

        ProviderConfigProperty waldurScopeTypeProperty = new ProviderConfigProperty(
                PERMISSION_SCOPE_TYPE, "Waldur permission scope",
                "Scope type for user permissions; can be either customer or project. Default is project.",
                ProviderConfigProperty.STRING_TYPE, "project");
        configProperties.add(waldurScopeTypeProperty);

        ProviderConfigProperty tlsValidationProperty = new ProviderConfigProperty(
                API_TLS_VALIDATE_KEY, "TLS validation enabled",
                "Enable TLS validation for Waldur API", ProviderConfigProperty.BOOLEAN_TYPE, false);
        configProperties.add(tlsValidationProperty);

        OIDCAttributeMapperHelper.addTokenClaimNameConfig(configProperties);
        OIDCAttributeMapperHelper.addIncludeInTokensConfig(configProperties,
                WaldurOIDCMinIOProtocolMapper.class);

        jacksonMapper = new ObjectMapper();
    }

    private String requestDataFromMastermind(String waldurEndpoint, String waldurToken,
            boolean tlsValidationEnabled) {
        LOGGER.info(String.format("Waldur URL: %s", waldurEndpoint));
        HttpGet request = new HttpGet(waldurEndpoint);
        request.addHeader(HttpHeaders.AUTHORIZATION, String.format("Token %s", waldurToken));
        try (CloseableHttpClient httpClient =
                tlsValidationEnabled ? HttpClients.createDefault()
                        : HttpClients.custom().setSSLHostnameVerifier(NoopHostnameVerifier.INSTANCE)
                                .build();
                CloseableHttpResponse response = httpClient.execute(request);) {
            int statusCode = response.getStatusLine().getStatusCode();

            LOGGER.info(String.format("Status Code: %s", statusCode));
            if (statusCode != 200)
                return "";

            HttpEntity entity = response.getEntity();
            if (entity == null) {
                LOGGER.error("Unable to get entity from the response");
                return "";
            }

            String result = EntityUtils.toString(entity);
            return result;
        } catch (Exception e) {
            LOGGER.error(e.getMessage(), e);
            return "";
        }
    }

    private List<UserPermissionDTO> fetchUserPermissions(String waldurApiUrl, String waldurToken,
            String waldurUserUsername, String scopeType, boolean tlsValidationEnabled) {
        final String scopeField = String.format("&field=%s_permissions", scopeType);
        final String waldurEndpoint = waldurApiUrl.concat("users/?").concat("username=")
                .concat(waldurUserUsername).concat("&is_active=true").concat(scopeField);

        String responseString =
                requestDataFromMastermind(waldurEndpoint, waldurToken, tlsValidationEnabled);

        List<UserPermissionDTO> userPermissions = Collections.emptyList();

        if (responseString == "")
            return userPermissions;

        try {
            userPermissions = jacksonMapper.readValue(responseString,
                    new TypeReference<List<UserPermissionDTO>>() {});
        } catch (JsonMappingException e) {
            LOGGER.error("Unable to extract data from the entity");
            LOGGER.error(e.getMessage());
        } catch (JsonProcessingException e) {
            LOGGER.error("Unable to process data from the entity");
            LOGGER.error(e.getMessage());
        }
        return userPermissions;
    }

    private void transformToken(IDToken token, Map<String, String> config,
            UserSessionModel userSession) {
        final String waldurUrl = config.get(API_URL_KEY);
        final String waldurToken = config.get(API_TOKEN_KEY);
        String scopeType = config.get(PERMISSION_SCOPE_TYPE);
        final boolean tlsValidationEnabled = Boolean.parseBoolean(config.get(API_TLS_VALIDATE_KEY));
        final String claimName = config.get(OIDCAttributeMapperHelper.TOKEN_CLAIM_NAME);

        if (!Arrays.asList("customer", "project").contains(scopeType)) {
            LOGGER.warn(
                    String.format("Unsupported scope type %s, defaulting to project", scopeType));
            scopeType = "project";
        }

        String waldurUserUsername = userSession.getUser().getUsername();

        LOGGER.info(
                String.format("Processing user %s, scope type: %s", waldurUserUsername, scopeType));

        List<UserPermissionDTO> userPermissions = fetchUserPermissions(waldurUrl, waldurToken,
                waldurUserUsername, scopeType, tlsValidationEnabled);

        if (userPermissions.isEmpty()) {
            LOGGER.error(String.format(String.format("Unable to retrieve user permissions for %s.",
                    waldurUserUsername)));
            return;
        }

        List<String> scopeUUIDs = Collections.emptyList();

        if (scopeType.equals("project"))
            scopeUUIDs = userPermissions.get(0).getProjectPermissions().stream()
                    .map(permission -> permission.getProjectUUID()).collect(Collectors.toList());

        if (scopeType.equals("customer"))
            scopeUUIDs = userPermissions.get(0).getCustomerPermissions().stream()
                    .map(permission -> permission.getCustomerUUID()).collect(Collectors.toList());

        String scopes = String.join(",", scopeUUIDs);

        token.getOtherClaims().put(claimName, scopes);
    }

    @Override
    protected void setClaim(IDToken token, ProtocolMapperModel mappingModel,
            UserSessionModel userSession, KeycloakSession keycloakSession,
            ClientSessionContext clientSessionCtx) {
        Map<String, String> config = mappingModel.getConfig();

        this.transformToken(token, config, userSession);
    }

    public static ProtocolMapperModel create(String name, String url, String apiToken,
            String scopeType, String claimName, boolean tlsValidationEnabled, boolean accessToken,
            boolean idToken, boolean userInfo) {
        ProtocolMapperModel mapper = new ProtocolMapperModel();
        mapper.setName(name);
        mapper.setProtocolMapper(PROVIDER_ID);
        mapper.setProtocol(OIDCLoginProtocol.LOGIN_PROTOCOL);

        Map<String, String> config = new HashMap<String, String>();
        config.put(API_URL_KEY, url);
        config.put(API_TOKEN_KEY, apiToken);
        config.put(OIDCAttributeMapperHelper.TOKEN_CLAIM_NAME, claimName);
        config.put(PERMISSION_SCOPE_TYPE, scopeType);
        config.put(API_TLS_VALIDATE_KEY, Boolean.toString(tlsValidationEnabled));

        config.put(OIDCAttributeMapperHelper.INCLUDE_IN_ACCESS_TOKEN,
                Boolean.toString(accessToken));
        config.put(OIDCAttributeMapperHelper.INCLUDE_IN_ID_TOKEN, Boolean.toString(idToken));
        config.put(OIDCAttributeMapperHelper.INCLUDE_IN_USERINFO, Boolean.toString(userInfo));

        mapper.setConfig(config);
        return mapper;
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return configProperties;
    }

    @Override
    public String getDisplayCategory() {
        return TOKEN_MAPPER_CATEGORY;
    }

    @Override
    public String getDisplayType() {
        return "Waldur MinIO mapper";
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String getHelpText() {
        return "Mapper for MinIO policies creation based on user data from Waldur";
    }
}
