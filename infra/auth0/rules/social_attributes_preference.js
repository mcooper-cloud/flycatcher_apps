/* global auth0 */
// eslint-disable-next-line no-unused-vars
function attributesPreference(user, context, cb) {
  /*
    This rule will consolidate social provider attributes taken preference from preferred providers.
   */

  // For Logging Events
  const log = global.getLogger
    ? global.getLogger('Preferred Social Metadata', cb)
    : {
        callback: cb,
        error: console.error,
        info: console.log,
        debug: console.log
      };
  const { callback } = log;

  const preference = {
    gender: 'facebook',
    age_range: '',
    birthday: '',
    locale: '',
    timezone: '',
    location: '',
    given_name: '',
    family_name: ''
  };

  // Add blank metadata if it does not exist
  user.user_metadata = user.user_metadata || {};

  // Should we update
  let updateUserMetadata = false;

  Object.entries(preference).forEach(([attr, provider]) => {
    const value = findAttr(attr, provider) || ''; // eslint-disable-line
    const existing = user.user_metadata[attr] || '';
    if (!value && !existing) return; // skip if both empty
    if (user.user_metadata[attr] !== value) {
      user.user_metadata[attr] = value;
      updateUserMetadata = true;
    }
  });

  if (updateUserMetadata) {
    log.info('saving user metadata');
    auth0.users.updateUserMetadata(user.user_id, user.user_metadata);
  }

  if (user.app_metadata.department !== user.department) {
    log.info('saving app metadata');
    user.app_metadata.department = user.department;
    // Update the user - don't block
    auth0.users.updateAppMetadata(user.user_id, user.app_metadata);
  }

  callback(null, user, context);

  // Function to look for the attrs for a particular providor
  // if not take what we can find!
  function findAttr(attrName, providorName) {
    // Already set, return
    if (attrName in user && user[attrName]) return user[attrName];

    for (const identity of user.identities) {
      const profileData = identity.profileData || {};
      if (identity.providor === providorName && attrName in profileData && profileData[attrName]) {
        log.info(`Setting ${attrName} from ${identity.providor}`);
        return profileData[attrName];
      }
      if (attrName in profileData && profileData[attrName]) {
        return profileData[attrName];
      }
    }
    return null;
  }
}
