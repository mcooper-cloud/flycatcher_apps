// eslint-disable-next-line
async function accountLinking(user, context, cb) {
  // Setup Logging and Timer
  const log = global.getLogger
    ? global.getLogger('Account Linking Rule', cb)
    : {
        callback: cb,
        error: console.error,
        info: console.log,
        debug: console.log,
      };
  const { callback } = log;

  // additional conditions to skip
  const skipConditions = [
    'oauth2-refresh-token',
    'oauth2-device-code',
    'oauth2-password',
  ];
  if (skipConditions.includes(context.protocol)) {
    return callback(null, user, context);
  }

  // 'query' can be undefined when using '/oauth/token' to log in
  context.request.query = context.request.query || {};

  const CONTINUE_PROTOCOL = 'redirect-callback';

  // Skip if MFA
  if (context.multifactor && context.multifactor.provider) {
    return callback(null, user, context);
  }

  // Skip if not user facing app type
  if (context.clientMetadata && context.clientMetadata.userApp !== 'true') {
    return callback(null, user, context);
  }

  // Skip if in checkSession and prompt none
  if (
    context.protocol === 'redirect-callback' ||
    context.request.query.prompt === 'none'
  ) {
    return callback(null, user, context);
  }

  const request = require('request@2.56.0');
  const queryString = require('querystring');
  const jwt = require('jsonwebtoken@7.1.9');

  const config = {
    endpoints: {
      linking:
        'https://fireback.us.webtask.run/4cb95bf92ced903b9b84ebedbf5ebffd',
      userApi: `${auth0.baseUrl}/users`,
      usersByEmailApi: `${auth0.baseUrl}/users-by-email`,
    },
    token: {
      clientId: 'eR9pRLPh95lnAiX1CyXTR2KMAOnVGh4z',
      clientSecret: 'kqv23yMsHE1BMCqK0rVuKfPQ1tFHXFAy3DwGHOtvB-93Wi8__y9WyteabWKqQ6M',
      issuer: 'fireback-demo.accounts.travel0.net',
    },
  };

  // If the user does not have an e-mail account,
  // just continue the authentication flow.
  // See auth0-extensions/auth0-account-link-extension#33
  if (user.email === undefined) {
    return callback(null, user, context);
  }

  // Consider moving this logic out of the rule and into the extension
  function buildRedirectUrl(token, q, errorType) {
    const params = {
      child_token: token,
      audience: q.audience,
      client_id: q.client_id,
      redirect_uri: q.redirect_uri,
      scope: q.scope,
      response_type: q.response_type,
      auth0Client: q.auth0Client,
      original_state: q.original_state || q.state,
      nonce: q.nonce,
      error_type: errorType,
    };

    return `${config.endpoints.linking}?${queryString.encode(params)}`;
  }

  function apiCall(options) {
    return new Promise((resolve, reject) => {
      const reqOptions = {
        url: options.url,
        headers: {
          Authorization: `Bearer ${auth0.accessToken}`,
          Accept: 'application/json',
        },
        json: true,
        ...options,
      };

      request(reqOptions, (err, response, body) => {
        if (err) {
          reject(err);
        } else if (response.statusCode < 200 || response.statusCode >= 300) {
          log.error(`API call failed: ${body}`);
          reject(new Error(body));
        } else {
          resolve(response.body);
        }
      });
    });
  }

  function searchUsersWithSameEmail() {
    return apiCall({
      url: config.endpoints.usersByEmailApi,
      qs: {
        email: user.email,
      },
    });
  }

  function qualifyDomain(domain) {
    return `https://${domain}/`;
  }

  function createToken(tokenInfo) {
    const options = {
      expiresIn: '5m',
      audience: tokenInfo.clientId,
      issuer: qualifyDomain(tokenInfo.issuer),
    };

    const userSub = {
      sub: user.user_id,
      email: user.email,
      base: auth0.baseUrl,
    };

    return jwt.sign(userSub, tokenInfo.clientSecret, options);
  }

  function verifyToken(token, secret) {
    return new Promise((resolve, reject) => {
      jwt.verify(token, secret, (err, decoded) => {
        if (err) {
          return reject(err);
        }

        return resolve(decoded);
      });
    });
  }

  function linkAccounts() {
    const secondAccountToken = context.request.query.link_account_token;

    return verifyToken(secondAccountToken, config.token.clientSecret).then(
      (decodedToken) => {
        // Redirect early if tokens are mismatched
        if (user.email !== decodedToken.email) {
          log.error(
            `User: ${decodedToken.email} tried to link to account ${user.email}`
          );
          context.redirect = {
            url: buildRedirectUrl(
              secondAccountToken,
              context.request.query,
              'accountMismatch'
            ),
          };

          return user;
        }

        const linkUri = `${config.endpoints.userApi}/${user.user_id}/identities`;
        const headers = {
          Authorization: `Bearer ${auth0.accessToken}`,
          'Content-Type': 'application/json',
          'Cache-Control': 'no-cache',
        };

        return apiCall({
          method: 'GET',
          url: `${config.endpoints.userApi}/${decodedToken.sub}?fields=identities`,
          headers,
        })
          .then((secondaryUser) => {
            const provider =
              secondaryUser &&
              secondaryUser.identities &&
              secondaryUser.identities[0] &&
              secondaryUser.identities[0].provider;

            return apiCall({
              method: 'POST',
              url: linkUri,
              headers,
              json: { user_id: decodedToken.sub, provider },
            });
          })
          .then((_) => {
            // TODO: Ask about this
            log.info(`Successfully linked accounts for user: ${user.email}`);
            return _;
          });
      }
    );
  }

  function continueAuth() {
    return Promise.resolve();
  }

  function promptUser() {
    return searchUsersWithSameEmail()
      .then((users) =>
        users
          .filter((u) => u.user_id !== user.user_id)
          .filter((u) => !(u.app_metadata || {}).unlinked)
          .map((_user) => ({
            userId: _user.user_id,
            email: _user.email,
            picture: _user.picture,
            connections: _user.identities.map(
              (identity) => identity.connection
            ),
          }))
      )
      .then((targetUsers) => {
        if (targetUsers.length > 0) {
          context.redirect = {
            url: buildRedirectUrl(
              createToken(config.token),
              context.request.query
            ),
          };
        }
      });
  }

  function createStrategy() {
    function shouldLink() {
      return !!context.request.query.link_account_token;
    }

    function shouldPrompt() {
      // Check if we're inside a redirect
      // in order to avoid a redirect loop
      // TODO: May no longer be necessary
      function insideRedirect() {
        return (
          context.request.query.redirect_uri &&
          context.request.query.redirect_uri.indexOf(
            config.endpoints.linking
          ) !== -1
        );
      }

      function linkScope() {
        // request query and scope are not always available
        // such as when this rule executes when /token is called
        // eg. device grant, password grant, refresh grant
        // if (context.request.query && context.request.query.scope) {
        //   return context.request.query.scope.indexOf('link:profile') >= 0;
        // }
        return context.request.query.scope.indexOf('link:profile') >= 0;
      }

      function unlinked() {
        return (user.app_metadata || {}).unlinked;
      }

      // Check if we're coming back from a redirect
      // in order to avoid a redirect loop. User will
      // be sent to /continue at this point. We need
      // to assign them to their primary user if so.
      function redirectingToContinue() {
        return context.protocol === CONTINUE_PROTOCOL;
      }

      return (
        !insideRedirect() &&
        !redirectingToContinue() &&
        !unlinked() &&
        !linkScope()
      );
    }

    if (shouldLink()) {
      return linkAccounts();
    }
    if (shouldPrompt()) {
      return promptUser();
    }

    return continueAuth();
  }

  function callbackWithSuccess() {
    return callback(null, user, context);
  }

  function callbackWithFailure(err) {
    log.error(`${err.message} ${err.stack}`);
    return callback(err, user, context);
  }

  return createStrategy().then(callbackWithSuccess).catch(callbackWithFailure);
}
