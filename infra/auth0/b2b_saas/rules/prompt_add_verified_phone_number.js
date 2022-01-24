function rule (user, context, callback) {
    const LOG_PREFIX = '[Rule: Prompt user to add a verified phone number] ';
    const PROMPT_UX_CLIENTS = ['Test App Demo', 'Test App'];

    if (context.protocol === 'redirect-callback') {
        console.log(LOG_PREFIX, 'SKIP: Do not run after redirect callback');
        return callback(null, user, context);
    }

    if (!PROMPT_UX_CLIENTS.includes(context.clientName)) {
        console.log(LOG_PREFIX, 'SKIP: Not in the list of PROMPT_UX_CLIENTS client');
        return callback(null, user, context);
    }

    if (context.redirect) {
        console.log(LOG_PREFIX, 'SKIP: Impending redirect to Prompt app');
        return callback(null, user, context);
    }

    if (user.identities.some(i => i.provider === 'sms')) {
        console.log(LOG_PREFIX, 'SKIP: User already has a verified phone number');
        return callback(null, user, context);
    }

    context.redirect = {
        url: `${configuration.PROMPT_APP_BASE_URL}/verify_phone`
    };
    console.log(LOG_PREFIX, `Redirecting user '${user.user_id}' to the Prompt app to add a verified phone number...`);

    return callback(null, user, context);
}