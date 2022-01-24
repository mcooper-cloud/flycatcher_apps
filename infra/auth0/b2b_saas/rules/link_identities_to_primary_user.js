
async function rule (user, context, callback) {
    const LOG_PREFIX = '[Rule: Link identities to primary user] ';
    const PROMPT_UX_CLIENTS = ['Test App Demo', 'Test App'];
    const PRIMARY_IDENTITIES_CONNECTION = 'api-customers';

    const request = require('request-promise@1.0.2');

    try {
        const { ManagementClient } = require('auth0@2.31.0');

        if (context.protocol !== 'redirect-callback') {
            console.log(LOG_PREFIX, 'SKIP: Only run after redirect callback');
            return callback(null, user, context);
        }

        if (!PROMPT_UX_CLIENTS.includes(context.clientName)) {
            console.log(LOG_PREFIX, 'SKIP: Not in the list of PROMPT_UX_CLIENTS client');
            return callback(null, user, context);
        }

        /*
        const auth0ManagementClient = new ManagementClient({
            domain: auth0.domain,
            clientId: configuration.RULES_CLIENT_ID,
            clientSecret: configuration.RULES_CLIENT_SECRET
        });
        */

        const auth0ManagementClient = new ManagementClient({
            token: auth0.accessToken,
            domain: auth0.domain
        });

        // get primary user
        let primaryUser;
        if (user.identities[0].provider === 'auth0') {
            primaryUser = user;
        } else {
            // find primary user using identities_to_link hint to get pending account links
            primaryUser = (await auth0ManagementClient.getUsers({ 
                search_engine: 'v3', 
                q: `identities.connection:"${PRIMARY_IDENTITIES_CONNECTION}" AND app_metadata.identities_to_link:"${user.user_id}"`
            }))[0];
            if (!primaryUser) {
                const message = `No primary user could be found that this identity could link to`;
                console.log(LOG_PREFIX, 'ERROR:', message, user.user_id);
                return callback(new UnauthorizedError(message));
            }
        }

        // get identities to link
        const identitiesToLink = primaryUser.app_metadata && primaryUser.app_metadata.identities_to_link;
        if (!identitiesToLink) {
            console.log(LOG_PREFIX, `Primary user ${primaryUser.user_id} does not have any identities to link`);
        } else {
            console.log(LOG_PREFIX, `Primary user ${primaryUser.user_id} with pending account links:`, identitiesToLink.join(', '));

            // perform account links
            let newSmsWasLinked = false;
            await Promise.all(identitiesToLink.map(async i => {
                const [ provider, user_id ] = i.split('|');
                // link identity to primary user
                await auth0ManagementClient.users.link(primaryUser.user_id, {
                    user_id,
                    provider
                });
                console.log(LOG_PREFIX, `Linked identity ${i} to primary user ${primaryUser.user_id}`);

                if (provider === 'sms') {
                    newSmsWasLinked = true;
                }
            }));

            // update Salesforce contact and user records if new verified phone number
            if (newSmsWasLinked) {
                console.log(LOG_PREFIX, `New verified phone number was linked ... use this block to update downstream systems`);

                // fetch primary user with updated links to get new phone number
                primaryUser = await auth0ManagementClient.getUser({ id: primaryUser.user_id });
                const newPhoneNumber = primaryUser.identities
                .find(i => i.provider === 'sms')
                .profileData.phone_number;

            }

            // remove identities_to_link hint from primary user
            await auth0ManagementClient.updateUser({ id: primaryUser.user_id }, {
                app_metadata: { identities_to_link: null }
            });

            if (user.user_id !== primaryUser.user_id) {
                // update authentication context with new primary identity
                context.primaryUser = primaryUser.user_id;
                // cache primary user object for downstream rules
                context._primaryUser = primaryUser;
            }
        }

        return callback(null, user, context);
    } catch (err) {
        console.log(LOG_PREFIX, 'ERROR:', err);
        return callback(err);
    }
}