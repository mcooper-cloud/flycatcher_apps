/* global auth0 */
// eslint-disable-next-line no-unused-vars
async function addDataRequest(user, context, cb) {
  // For Logging Events
  const log = global.getLogger
    ? global.getLogger('Progressive Profiling Rule', cb)
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
  const delayBeforeNext = 30000;

  // Ideally you should have rely on Auth0.e
  // https://auth0.com/docs/rules/current/context
  const request = require('request-promise');
  const noRedirectProtocols = ['oauth2-resource-owner', 'oauth2-refresh-token', 'oauth2-password'];

  // Only allow username/password and social connections for profiling. Ignore enterprise customers.
  const profileConnections = ['google-oauth2', 'facebook', 'sms', 'email', 'consumer-users'];

  // Perhaps we can just call profiler/shouldRedirect
  // although we should first try to do all we can
  // short of that.
  async function shouldPerformProgressiveProfiling() {
    user.user_metadata = user.user_metadata || {};
    user.app_metadata = user.app_metadata || {};
    context.clientMetadata = context.clientMetadata || {};

    const nextProfiling = (user.app_metadata.lastProgressiveStep || 0) + delayBeforeNext;

    // Don't redirect if MFA
    if (context.multifactor && context.multifactor.provider) {
      return false;
    }

    // Don't redirect if someone else wants to.
    if (context.redirect && context.redirect.url) {
      return false;
    }

    // If multifactor is requested skip this.
    if (context.multifactor) {
      return false;
    }

    // Skip based on connection type
    if (!profileConnections.includes(context.connection)) {
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

    // If we are in redirect-callback *for this rule*
    if (context.protocol === 'redirect-callback') {
      if (context.request.query.hasOwnProperty('progressive')) {
        // eslint-disable-line
        return false;
      }
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

    // If next profiling was scheduled and we
    // aren't at the or beyond that time coordinate
    if (nextProfiling > Date.now()) {
      return false;
    }

    // Cache requiredFields globally at max this will end up after
    // 30 seconds - 20 minutes when the container is recycled.
    if (!global.requiredFields) {
      global.requiredFields = await request(`${appURL}/api/v1/schema/required`, {
        json: true
      });
    }

    // if we have a phone number on file
    if (user.user_metadata.phone_number) {
      log.info(`Using number avaiable in metadata:${user.user_metadata.phone_number}`);
      // If we have one phone number on file and it's not enrolled
      const enrolled = user.identities.some(({ connection }) => connection === 'sms');
      if (!enrolled) {
        return true;
      }
    }

    // Check if we have a remaining field which is actually
    // defined in the schema
    const remaining = global.requiredFields.filter(
      fieldName => !user[fieldName] && !user.user_metadata[fieldName]
    );

    // If nothing is remaining, don't redirect
    if (!remaining.length) {
      return false;
    }

    return true;
  }

  try {
    if (await shouldPerformProgressiveProfiling()) {
      log.info('Attempting to redirect...');
      context.redirect = {
        url: `${appURL}/?t=${Date.now()}`
      };
      // Flag so that we don't redirect again.
      user.app_metadata.lastProgressiveStep = Date.now();
      await auth0.users.updateAppMetadata(user.user_id, user.app_metadata);
    }
  } catch (e) {
    log.error(`Failed to progressive profile because of ${e.toString()}`);
  }

  // All done, next it
  callback(null, user, context);
}
