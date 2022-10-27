// eslint-disable-next-line no-unused-vars
function enrollMFA(user, context, cb) {
  /*
    This rule triggers MFA when a user to trying to enroll for it
   */

  // For Logging Events
  const log = global.getLogger
    ? global.getLogger('Enroll MFA', cb)
    : {
        callback: cb,
        error: console.error,
        info: console.log,
        debug: console.log
      };
  const { callback } = log;

  // Enforce MFA on these operations
  function isEnrollingMFA() {
    const scopes =
      (context.request.query && context.request.query.scope) ||
      (context.request.body && context.request.body.scope);
    if (!scopes) {
      return false;
    }

    return scopes.includes('enroll:mfa');
  }

  // Function to trigger MFA
  function forceMFA() {
    context.multifactor = {
      provider: 'any',
      allowRememberBrowser: false
    };
  }

  // Check if the current operation is sensitive
  if (isEnrollingMFA()) {
    log.info(`Forcing MFA for user ${user.name} due sensitive action`, true);
    forceMFA();
  }

  callback(null, user, context);
}
