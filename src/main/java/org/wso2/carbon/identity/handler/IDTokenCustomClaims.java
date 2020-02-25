package org.wso2.carbon.identity.handler;

import com.nimbusds.jwt.JWTClaimsSet;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.common.IdentityApplicationManagementException;
import org.wso2.carbon.identity.application.common.model.ClaimConfig;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.handler.internal.IDTokenCustomClaimsDataHolder;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth2.authz.OAuthAuthzReqMessageContext;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.openidconnect.CustomClaimsCallbackHandler;
import org.wso2.carbon.identity.openidconnect.DefaultOIDCClaimsCallbackHandler;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.api.UserStoreManager;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import java.util.ArrayList;
import java.util.List;

/**
 * This IDTokenCustomClaims handler is responsible for appending custom claims to the self contained access token.
 */
public class IDTokenCustomClaims extends DefaultOIDCClaimsCallbackHandler implements CustomClaimsCallbackHandler {

    private static final Log log = LogFactory.getLog(IDTokenCustomClaims.class);

    @Override
    public JWTClaimsSet handleCustomClaims(JWTClaimsSet.Builder builder, OAuthTokenReqMessageContext request) {

        JWTClaimsSet jwtClaimsSet = super.handleCustomClaims(builder, request);
        OAuthAppDO appDO = (OAuthAppDO) request.getProperty("OAuthAppDO");
        String spAppCreator = null;
        ServiceProvider serviceProvider = null;
        List<String> requestedClaims = null;

        if(appDO != null){
            spAppCreator = appDO.getAppOwner().getUserName();
        }

        String tenantDomain = MultitenantUtils.getTenantDomain(spAppCreator);
        RealmService realmService = IdentityTenantUtil.getRealmService();
        UserStoreManager userStoreManager = null;
        String [] roles = null;

        try {
            int tenantId = realmService.getTenantManager().getTenantId(tenantDomain);
            userStoreManager = realmService.getTenantUserRealm(tenantId).getUserStoreManager();
            roles = userStoreManager.getRoleListOfUser(spAppCreator);

            serviceProvider = IDTokenCustomClaimsDataHolder.getInstance().getApplicationManagementService().getServiceProvider(appDO.getApplicationName(), tenantDomain);
            requestedClaims = getRequestedClaimUris(serviceProvider.getClaimConfig().getClaimMappings());
        } catch (IdentityApplicationManagementException e){
            log.error("Error occurred while retrieving service provider by appId", e);
            e.printStackTrace();
        }
        catch (UserStoreException e) {
            log.error("Error occurred while retrieving claims for the JWT: ",e);
            e.printStackTrace();
        }

        builder.claim("spAppCreatorRole", roles);
        builder.claim("spAppCreator",spAppCreator);
        builder.claim("requestedClaims", requestedClaims);

        if (jwtClaimsSet.getClaim("email") != null) {
            builder.claim("http://wso2.org/claims/emailaddress",jwtClaimsSet.getClaim("email"));
        }

        if (jwtClaimsSet.getClaim("groups") != null) {
            builder.claim("http://wso2.org/claims/role",jwtClaimsSet.getClaim("groups"));
        }

        return builder.build();
    }

    @Override
    public JWTClaimsSet handleCustomClaims(JWTClaimsSet.Builder builder, OAuthAuthzReqMessageContext request) {

        JWTClaimsSet jwtClaimsSet = super.handleCustomClaims(builder, request);
        OAuthAppDO appDO = (OAuthAppDO) request.getProperty("OAuthAppDO");
        String spAppCreator = null;
        ServiceProvider serviceProvider = null;
        List<String> requestedClaims = null;

        if(appDO != null){
            spAppCreator = appDO.getAppOwner().getUserName();
        }

        String tenantDomain = MultitenantUtils.getTenantDomain(spAppCreator);
        RealmService realmService = IdentityTenantUtil.getRealmService();
        UserStoreManager userStoreManager = null;
        String [] roles = null;

        try {
            int tenantId = realmService.getTenantManager().getTenantId(tenantDomain);
            userStoreManager = realmService.getTenantUserRealm(tenantId).getUserStoreManager();
            roles = userStoreManager.getRoleListOfUser(spAppCreator);

            serviceProvider = IDTokenCustomClaimsDataHolder.getInstance().getApplicationManagementService().getServiceProvider(appDO.getApplicationName(), tenantDomain);
            requestedClaims = getRequestedClaimUris(serviceProvider.getClaimConfig().getClaimMappings());
        } catch (IdentityApplicationManagementException e){
            log.error("Error occurred while retrieving service provider by appId", e);
            e.printStackTrace();
        }
        catch (UserStoreException e) {
            log.error("Error occurred while retrieving claims for the JWT: ",e);
            e.printStackTrace();
        }

        builder.claim("spAppCreatorRole", roles);
        builder.claim("spAppCreator",spAppCreator);
        builder.claim("requestedClaims", requestedClaims);

        if (jwtClaimsSet.getClaim("email") != null) {
            builder.claim("http://wso2.org/claims/emailaddress",jwtClaimsSet.getClaim("email"));
        }

        if (jwtClaimsSet.getClaim("groups") != null) {
            builder.claim("http://wso2.org/claims/role",jwtClaimsSet.getClaim("groups"));
        }

        return builder.build();
    }

    private List<String> getRequestedClaimUris(ClaimMapping[] requestedLocalClaimMap) {
        List<String> claimURIList = new ArrayList<>();
        for (ClaimMapping mapping : requestedLocalClaimMap) {
            if (mapping.isRequested()) {
                claimURIList.add(mapping.getLocalClaim().getClaimUri());
            }
        }
        return claimURIList;
    }
}
