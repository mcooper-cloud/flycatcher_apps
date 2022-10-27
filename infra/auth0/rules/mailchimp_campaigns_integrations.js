/* global auth0 */
// eslint-disable-next-line no-unused-vars
async function mailchimpIntegration(user, context, cb) {
  // For Logging Events
  const log = global.getLogger
    ? global.getLogger('MailChimp Rule', cb)
    : {
        callback: cb,
        error: console.error,
        info: console.log,
        debug: console.log
      };
  const { callback } = log;

  const MAILCHIMP_LIST_ID = '1c1daddde4';
  const MAILCHIMP_LIST_UID = '646712';

  if (!user.email) {
    log.info('user does not have email, skipping creation of contact in MailChimp', true);
    callback(null, user, context);
    return;
  }

  user.app_metadata = user.app_metadata || {};

  // Only send an email when user signs up
  if (!user.app_metadata.mailchimpSubscribed) {
    const body = {
      email_address: user.email,
      status: 'subscribed',
      merge_fields: {
        FNAME: user.given_name,
        LNAME: user.family_name
      }
    };

    try {
      const request = require('request-promise');
      await request.post({
        url: `https://us19.api.mailchimp.com/3.0/lists/${MAILCHIMP_LIST_ID}/members`,
        headers: {
          Authorization: `apikey ${configuration.MAILCHIMP_API_KEY}`
        },
        json: body
      });

      log.info(
        `created mailchimp contact on list https://us19.admin.mailchimp.com/lists/members/?id=${MAILCHIMP_LIST_UID}`,
        true
      );

      user.app_metadata.mailchimpSubscribed = true;
      auth0.users.updateAppMetadata(user.user_id, user.app_metadata);
      callback(null, user, context);
    } catch (err) {
      const data = err.error || {};
      if (data.title === 'Member Exists') {
        log.info(
          `mailchimp contact already exists on list https://us19.admin.mailchimp.com/lists/members/?id=${MAILCHIMP_LIST_UID}`,
          true
        );
        user.app_metadata.mailchimpSubscribed = true;
        auth0.users.updateAppMetadata(user.user_id, user.app_metadata);
        callback(null, user, context);
        return;
      }

      const msg = data.detail || err.toString();
      log.error(`failed to call MailChimp API due to: ${msg}`, true);
      callback(null, user, context);
    }
  } else {
    // User had already logged in before, do nothing
    log.info('user already exists in MailChimp, skipping creation of contact');
    callback(null, user, context);
  }
}
