// eslint-disable-next-line no-unused-vars
async function authorization(user, context, cb) {
  const log = global.getLogger
    ? global.getLogger('Authorization Rule', cb)
    : {
        callback: cb,
        error: console.error,
        info: console.log,
        debug: console.log
      };
  const { callback } = log;

  const namespace = 'https://travel0.net/';

  function shouldRun() {
    return context.clientMetadata.supportT0Rules === 'true';
  }

  // Ensure every user has the basic set of user permissions
  if (shouldRun() && context.stats.loginsCount === 1 && context.protocol !== 'redirect-callback') {
    try {
      const request = require('request-promise');
      await request.post(`${auth0.baseUrl}/users/${user.user_id}/permissions`, {
        body: {
          permissions: [
            {
              permission_name: 'read:profile',
              resource_server_identifier: 'https://travel0.com/api'
            },
            {
              permission_name: 'update:profile',
              resource_server_identifier: 'https://travel0.com/api'
            },
            {
              permission_name: 'link:profile',
              resource_server_identifier: 'https://travel0.com/api'
            },
            {
              permission_name: 'read:history',
              resource_server_identifier: 'https://travel0.com/api'
            },
            {
              permission_name: 'update:history',
              resource_server_identifier: 'https://travel0.com/api'
            },
            {
              permission_name: 'read:payment',
              resource_server_identifier: 'https://travel0.com/api'
            },
            {
              permission_name: 'update:payment',
              resource_server_identifier: 'https://travel0.com/api'
            },
            {
              permission_name: 'read:featured',
              resource_server_identifier: 'https://travel0.com/api'
            },
            {
              permission_name: 'enroll:mfa',
              resource_server_identifier: 'https://travel0.com/api'
            }
          ]
        },
        auth: {
          bearer: auth0.accessToken
        },
        json: true,
        timeout: 3000
      });
    } catch (error) {
      log.error(`Failed to add permissions ${error.description} ${error.toString()}`);
    }

    // Temporary fix for SIWA first signin
    const scopes =
      (context.request.query && context.request.query.scope) ||
      (context.request.body && context.request.body.scope);
    context.accessToken.scope = (scopes && scopes.split(' ')) || [];
  }

  // Enrich Token for Delegated Admin Application
  // TODO: Use new roles/groups
  // context.idToken[`${namespace}auth0-delegated-admin`] = context.authorization;

  // For now, pull in groups from IDP
  context.idToken[`${namespace}auth0-delegated-admin`] = { roles: user.groups };

  callback(null, user, context);
}
