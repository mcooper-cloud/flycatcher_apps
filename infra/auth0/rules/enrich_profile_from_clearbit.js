/* global auth0 */
// eslint-disable-next-line no-unused-vars
async function clearBitEnrich(user, context, cb) {
  // For Logging Events
  const log = global.getLogger
    ? global.getLogger('Clearbit Profile Integration', cb)
    : {
        callback: cb,
        error: console.error,
        info: console.log,
        debug: console.log
      };
  const { callback } = log;

  // skip if no email
  if (!user.email) {
    callback(null, user, context);
    return;
  }

  // skip if fullcontact metadata is already there
  if (user.app_metadata && user.app_metadata.clearbit === true) {
    callback(null, user, context);
    return;
  }

  function walk(o, path) {
    const parts = path.split('.');
    let part = parts.shift();

    while (parts.length && o) {
      if (part === '[]' && Array.isArray(o)) {
        return o.map(a => walk(a, parts.join('.')));
      }
      o = o[part];

      part = parts.shift();
    }
    return (o && o[part]) || null;
  }

  const requiredFieldsMap = {
    given_name: 'name.givenName',
    family_name: 'name.familyName',
    location: 'location',
    bio: 'bio',
    employment: 'employment',
    geo: 'geo'
  };

  const clearbit = require('clearbit@1.2.3')(configuration.CLEARBIT_API_KEY);

  clearbit.Person.find({ email: user.email, stream: true }).nodeify((err, person) => {
    if (err) {
      log.error(`Error fetching data from clearbit, ${err.toString()}`, true);
    }

    if (!err) {
      // Sometimes ClearBit API gives a fullName but not names,
      // simplify and normalize
      person.name =
        walk(person, 'name.givenName') !== null
          ? person.name
          : {
              givenName: person.name.fullName.split(' ')[0],
              familyName: person.name.fullName.split(' ')[1]
            };

      user.user_metadata = user.user_metadata || {};
      user.app_metadata = user.app_metadata || {};

      const um = user.user_metadata;

      Object.keys(requiredFieldsMap).forEach(key => {
        um[key] = um[key] || walk(person, requiredFieldsMap[key]);
      });

      um.handles = [];
      if (person.facebook && person.facebook.handle) {
        um.handles.push(`https://facebook.com/${person.facebook.handle}`);
      }
      if (person.twitter && person.twitter.handle) {
        um.handles.push(`https://twitter.com/${person.twitter.handle}`);
      }
      if (person.linkedin && person.linkedin.handle) {
        um.handles.push(`https://linkedin.com/${person.linkedin.handle}`);
      }
      if (person.googleplus && person.googleplus.handle) {
        um.handles.push(`https://plus.google.com/${person.googleplus.handle}`);
      }
      if (person.github && person.github.handle) {
        um.handles.push(`https://github.com/${person.github.handle}`);
      }

      // Store this information and make the rule self-aware
      user.app_metadata.clearbit = true;

      // Update the metadata - don't block
      auth0.users.updateUserMetadata(user.user_id, user.user_metadata);
      auth0.users.updateAppMetadata(user.user_id, user.app_metadata);
    }

    callback(null, user, context);
  });
}
