// eslint-disable-next-line no-unused-vars
function enrichTokens(user, context, cb) {
  // For Logging Events
  const log = global.getLogger
    ? global.getLogger('Enrich Tokens', cb)
    : {
        callback: cb,
        error: console.error,
        info: console.log,
        debug: console.log
      };
  const { callback } = log;

  const namespace = 'https://travel0.net/';

  const userMetadata = user.user_metadata || {};
  const appMetadata = user.app_metadata || {};

  const subscriptions = {};
  subscriptions.user = appMetadata.subscription || {};
  subscriptions.company = appMetadata.companySubscription || {};

  // ID Token claims
  context.idToken[`${namespace}gender`] = userMetadata.gender;
  context.idToken[`${namespace}birthday`] = userMetadata.birthday;
  context.idToken[`${namespace}locale`] = userMetadata.locale;
  context.idToken[`${namespace}location`] = userMetadata.location;
  context.idToken[`${namespace}employment`] = userMetadata.employment;
  context.idToken[`${namespace}handles`] = userMetadata.handles;
  context.idToken[`${namespace}fav_style`] = userMetadata.fav_style;
  context.idToken[`${namespace}fav_type`] = userMetadata.fav_type;
  context.idToken[`${namespace}promotion_opt_in`] = userMetadata.promotion_opt_in || false;
  context.idToken[`${namespace}identities`] = user.identities.map(
    i => `${i.provider}|${i.user_id}`
  );

  // Access Token Claims
  context.accessToken[`${namespace}email`] = user.email || userMetadata.email;
  context.accessToken[`${namespace}name`] = user.name || userMetadata.name;
  context.accessToken[`${namespace}subscriptions`] = subscriptions;

  callback(null, user, context);
}
