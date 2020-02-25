package org.wso2.carbon.identity.handler.internal;

import org.wso2.carbon.identity.application.mgt.ApplicationManagementService;


/**
 * This is the DataHolder class of IDTokenCustomClaims bundle. This holds a reference to the
 * ApplicationManagementService.
 */
public class  IDTokenCustomClaimsDataHolder {

    private static IDTokenCustomClaimsDataHolder thisInstance = new IDTokenCustomClaimsDataHolder();
    private ApplicationManagementService applicationManagementService = null;


    private IDTokenCustomClaimsDataHolder() {
    }

    public static IDTokenCustomClaimsDataHolder getInstance() {
        return thisInstance;
    }

    public ApplicationManagementService getApplicationManagementService() {
        if (applicationManagementService == null) {
            throw new IllegalStateException("ApplicationManagementService is not initialized properly");
        }
        return applicationManagementService;
    }

    public void setApplicationManagementService(ApplicationManagementService applicationManagementService) {
        this.applicationManagementService = applicationManagementService;
    }
}
