function contextualMFA(user, context, cb) {
    /*
    This rule is designed to demonstrate triggering MFA based on logical/contextual information during authentication.

    MFA will be triggered if either of the below conditions are true.

    1. Risk Score > 0.5
    2. User has preferMFA in user_metadata

    The rule will also set the `app_metadata.last_location = geoip.country_code` to detect changing location.
    */

    // For Logging Events
    const log = {
        callback: cb,
        error: console.error,
        info: console.log,
        debug: console.log,
    };
    const { callback } = log;

    user.user_metadata = user.user_metadata || {};
    user.app_metadata = user.app_metadata || {};
    context.anomalyDetection = context.anomalyDetection || { confidence: 1 };

    // Check if has done MFA in the last 10 minutes
    const completedMfa =
        context.authentication &&
        !!context.authentication.methods.find((method) => {
            if (method.name === "mfa") {
                // Require MFA every 10 minutes
                const requireMFAAt = method.timestamp + 600 * 1000;
                return requireMFAAt > Date.now();
            }
            return false;
        });

    // Enforce MFA on these operations
    function isSensitiveOperation() {
        const scopes =
            (context.request.query && context.request.query.scope) ||
            (context.request.body && context.request.body.scope);
            if (!scopes) {
               return false;
            }

            const sensitiveScopes = ["read:payment", "update:payment"];
            const requestedScopes = scopes.split(" ");
            return requestedScopes.some((scope) => sensitiveScopes.includes(scope));
    }

    // Function to trigger MFA
    function forceMFA() {
        context.multifactor = {
            provider: "any",
            allowRememberBrowser: false,
        };
//        global.createAuditLog("STEP_UP_MFA_RULE", user);
    }

    // Skip if has already completed MFA
    if (completedMfa) {
        callback(null, user, context);
        return;
    }

    // Skip if not user facing app type
    if (context.clientMetadata.userApp !== "true") {
        callback(null, user, context);
        return;
    }

    // Skip if calling from mobile app, biometrics used instead
    if (context.clientName === "Travel0 Mobile") {
        callback(null, user, context);
        return;
    }

    // Check Risk Score from ThisData
    if (user.risk && user.risk.score > 0.5) {
        log.info(
            `Forcing MFA for user ${user.name} due high risk score of 0.5 > ${user.risk.score}`,
            true
        );
        forceMFA();
    }

    // Check the anomaly detection confidence score;
    if (context.anomalyDetection.confidence < 0.8) {
        log.info(
            `Forcing MFA for user ${user.name} due low confidence score of 0.8 > ${context.anomalyDetection.confidence}`,
            true
        );
        forceMFA();
    }

    // Check if the current operation is sensitive
    if (isSensitiveOperation()) {
        log.info(`Forcing MFA for user ${user.name} due sensitive action`, true);
        forceMFA();
    }

    // Check if User has MFA preference
    if (user.user_metadata.preferMFA) {
        log.info(`Forcing MFA for user ${user.name} due user preference`, true);
        forceMFA();
    }

    callback(null, user, context);
}
