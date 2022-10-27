/* global auth0 */
// eslint-disable-next-line no-unused-vars
async function verifyOnMigration(user, context, cb) {
  /*
    Send Verification Email if user app_metadata.migrated = true and user.email_verified is false.
    Useful if the user has migrated from a CustomDB Connection and the user's email has not been verified
   */

  // For Logging Events
  // For Logging Events
  const log = global.getLogger
    ? global.getLogger('Send Verify Email On Migration', cb)
    : {
        callback: cb,
        error: console.error,
        info: console.log,
        debug: console.log
      };
  const { callback } = log;

  // 'query' can be undefined when using '/oauth/token' to log in
  context.request.query = context.request.query || {};

  user.app_metadata = user.app_metadata || {};

  // Ignore request checkSession
  if (context.request.query && context.request.query.response_mode === 'web_message') {
    callback(null, user, context);
    return;
  }

  if (
    user.app_metadata.migrated &&
    context.stats.loginsCount === 1 &&
    !user.email_verified &&
    !user.app_metadata.duplicate_email
  ) {
    try {
      require('request-promise').post({
        url: `${auth0.baseUrl}/jobs/verification-email`,
        headers: {
          Authorization: `Bearer ${auth0.accessToken}`
        },
        json: {
          client_id: context.clientID,
          user_id: user.user_id
        }
      });
    } catch (err) {
      if (err) {
        log.error(`Problem sending verify email due to ${err}`, true);
      } else {
        log.info('Sent verify email', true);
      }
    }
  }

  // Continue processing, don't wait for rule to call api
  callback(null, user, context);
}
