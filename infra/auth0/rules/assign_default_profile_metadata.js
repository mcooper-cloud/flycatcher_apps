// eslint-disable-next-line no-unused-vars
function exposeMetadataAsProps(user, context, cb) {
  // This allows the profile to be moved to user-metadata which
  // can then be used in future. Never do this in production
  // as it may open your application to attacks if inputs are not sanitized

  // For Logging Events
  const log = global.getLogger
    ? global.getLogger('Assign Default Props', cb)
    : {
        callback: cb,
        error: console.error,
        info: console.log,
        debug: console.log
      };
  const { callback } = log;

  const OVERRIDABLE_PROPS = [
    'name',
    'given_name',
    'family_name',
    'middle_name',
    'nickname',
    'preferred_username',
    'profile',
    'picture',
    'gender',
    'birthdate',
    'zoneinfo',
    'locale'
  ];

  const ADDR_PROPS = ['street_address', 'locality', 'region', 'postal_code', 'country'];

  const profile = user.user_metadata || {};
  Object.keys(profile).forEach(key => {
    if (OVERRIDABLE_PROPS.includes(key)) {
      user[key] = profile[key];
    }
  });

  // This should use for-of in future.
  // address, oidc from address in user_metadata
  // in user_metadata we will keep address as addr_*
  // in oidc these properties will just be merged
  user.address = ADDR_PROPS.reduce((addr, key) => {
    addr[key] = profile[`addr_${key}`] || '';
    return addr;
  }, {});

  // @TODO: Generate formatted address
  callback(null, user, context);
}
