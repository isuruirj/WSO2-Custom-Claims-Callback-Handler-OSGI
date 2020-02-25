package org.wso2.carbon.identity.handler.internal;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.service.component.annotations.*;
import org.osgi.service.component.ComponentContext;
import org.wso2.carbon.identity.application.mgt.ApplicationManagementService;

@Component(
        name = "identity.handler",
        immediate = true
)
public class IDTokenCustomClaimsServiceComponent {

    private static final Log log = LogFactory.getLog(IDTokenCustomClaimsServiceComponent.class);

    @Activate
    protected void activate(ComponentContext context) {

        try {
            log.info("IDTokenCustomClaims handler activated");
        } catch (Throwable e) {
            log.error("Error while activating id-token-custom-claims.", e);
        }
    }

    /**
     * Sets ApplicationManagement Service.
     *
     * @param applicationManagementService An instance of ApplicationManagementService
     */
    @Reference(
            name = "application.mgt.service",
            service = ApplicationManagementService.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetApplicationManagementService"
    )
    protected void setApplicationManagementService(ApplicationManagementService applicationManagementService) {

        if (log.isDebugEnabled()) {
            log.debug("Setting ApplicationManagement Service");
        }
        IDTokenCustomClaimsDataHolder.getInstance().
                setApplicationManagementService(applicationManagementService);
    }

    /**
     * Unsets ApplicationManagement Service.
     *
     * @param applicationManagementService An instance of ApplicationManagementService
     */
    protected void unsetApplicationManagementService(ApplicationManagementService applicationManagementService) {

        if (log.isDebugEnabled()) {
            log.debug("Unsetting ApplicationManagement.");
        }
        IDTokenCustomClaimsDataHolder.getInstance().setApplicationManagementService(null);
    }



}
