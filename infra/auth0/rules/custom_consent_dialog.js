// eslint-disable-next-line no-unused-vars
async function customConsentDialog(user, context, cb) {
  // For Logging Events
  const log = global.getLogger
    ? global.getLogger('Custom Consent Dialog Rule', cb)
    : {
        callback: cb,
        error: console.error,
        info: console.log,
        debug: console.log
      };
  const { callback } = log;

  // 'query' can be undefined when using '/oauth/token' to log in
  context.request.query = context.request.query || {};

  const appURL = 'https://fireback-demo.ppap.accounts.travel0.net';

  // Ideally you should have rely on Auth0.e
  // https://auth0.com/docs/rules/current/context
  const request = require('request-promise');
  const noRedirectProtocols = ['oauth2-resource-owner', 'oauth2-refresh-token', 'oauth2-password'];

  async function shouldDisplayCustomConsent() {
    user.user_metadata = user.user_metadata || {};
    user.app_metadata = user.app_metadata || {};
    context.clientMetadata = context.clientMetadata || {};

    // Don't redirect if someone else wants to.
    if (context.redirect && context.redirect.url) {
      return false;
    }

    // Skip if not user facing app type
    if (context.clientMetadata.userApp !== 'true') {
      return false;
    }

    // Skip if performing account linking
    if (context.request.query.scope.indexOf('link:profile') >= 0) {
      return false;
    }

    // If we are the same client
    if (context.clientName === 'Progressive0') {
      return false;
    }

    // If prompt is none, don't redirect, this will throw an
    // interaction needed error, therefore we will try to
    // avoid this, for conditions like these, the app may
    // just add more support for progressive profiling
    // using <iframe> as a widget in-app.
    if (context.request.query.prompt === 'none') {
      return false;
    }

    // If we are in one of the protocols which do not support
    // redirection.
    if (noRedirectProtocols.includes(context.protocol)) {
      return false;
    }

    // Find the minimum consent version that users must accept
    const apiResponse = await request(`${appURL}/api/v1/consent/minimum-version`, {
      json: true
    });

    // Find the latest version of consent the user has accepted
    const highestVersionAccepted = Object.keys(user.app_metadata)
      .filter(key => key.startsWith('consent-v'))
      .reduce((currentHighestVersionAccepted, key) => {
        const version = parseInt(key.substr(9), 10);
        return version > currentHighestVersionAccepted ? version : currentHighestVersionAccepted;
      }, 0);

    // Should get new user consent if the minimum consent version is
    // greater than what the user has previously accepted.
    return apiResponse.minimumVersion > highestVersionAccepted;
  }

  try {
    if (await shouldDisplayCustomConsent()) {
      log.info('Attempting to redirect...');
      context.redirect = {
        url: `${appURL}/consent?t=${Date.now()}`
      };
    }
  } catch (e) {
    log.error(`Failed to display custom consent because of ${e.toString()}`);
  }

  // All done, next it
  callback(null, user, context);
}
