
function rule (user, context, callback) {
    const LOG_PREFIX = '[Rule: Prompt user to verify or create their account] ';
    const PROMPT_UX_CLIENTS = [ 'Test App Demo', 'Test App'];
    const PRIMARY_IDENTITIES_CONNECTION = 'api-customers';

    if (context.protocol === 'redirect-callback') {
        console.log(LOG_PREFIX, 'SKIP: Do not run after redirect callback');
        return callback(null, user, context);
    }

    if (!PROMPT_UX_CLIENTS.includes(context.clientName)) {
        console.log(LOG_PREFIX, 'SKIP: Not in the list of PROMPT_UX_CLIENTS clients');
        return callback(null, user, context);
    }

    if (context.connection === PRIMARY_IDENTITIES_CONNECTION) {
        console.log(LOG_PREFIX, 'SKIP: Already authenticated as primary identity');
        return callback(null, user, context);
    }

    if (user.identities.length > 1) {
        console.log(LOG_PREFIX, `SKIP: User profile already contains linked primary identity:`, 
        user.identities.map(i => `${i.provider}|${i.user_id}`).join(', '));
        return callback(null, user, context);
    }

    context.redirect = {
        url: `${configuration.PROMPT_APP_BASE_URL}/new_account`
    };
    console.log(LOG_PREFIX, `Redirecting user '${user.user_id}' to the Prompt app to verify their (or register a new) primary account...`);

    return callback(null, user, context);
}