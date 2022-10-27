/* eslint-disable */
async function passwordlessSalesforceAccountLink(user, context, cb) {
  /*
      This rule will attempt to find a passwordless users mobile number in a SFDC contact.
      If the number is not found in SFDC, the user will be deleted from Auth0 and the authentication will fail.
      If the number is found against an SFDC contact, the rule will link the passwordless user
      to a user in Auth0 who shares the same email address as the SFDC contact.
    */

  const log = global.getLogger
    ? global.getLogger('SalesForce check phone number on salesforce', cb)
    : {
        callback: cb,
        error: console.error,
        info: console.log,
        debug: console.log
      };
  const { callback } = log;

  // Dependencies
  const request = require('request-promise');

  let contact = {};
  const userApiUrl = `${auth0.baseUrl}/users`;
  const userSearchApiUrl = `${auth0.baseUrl}/users-by-email`;
  const headers = {
    Authorization: `Bearer ${auth0.accessToken}`,
    'Content-Type': 'application/json',
    'Cache-Control': 'no-cache'
  };

  // 'query' can be undefined when using '/oauth/token' to log in
  context.request.query = context.request.query || {};

  const SFCOM_CLIENT_ID = configuration.SALESFORCE_CLIENT_ID;
  const SFCOM_CLIENT_SECRET = configuration.SALESFORCE_CLIENT_SECRET;
  const USERNAME = configuration.SALESFORCE_USERNAME;
  const PASSWORD = configuration.SALESFORCE_PASSWORD;

  // Option to sync contact, off by default
  const syncContact = false;

  // Get Users Metadata or set to empty if does not exist
  user.app_metadata = user.app_metadata || {};
  user.user_metadata = user.user_metadata || {};
  user.app_metadata.sfdc = user.app_metadata.sfdc || { ts: 0 };

  // Skip if we don't need to run
  if (!shouldRun()) {
    return callback(null, user, context);
  }

  function shouldRun() {
    // Skip no passwordless
    if (context.connection !== 'sms') {
      log.info('not passwordless, skipping account link with SFDC');
      return false;
    }

    // Skip no phone
    if (!user.phone_number) {
      log.info('user does not have a phone number, skipping account link with SFDC');
      return false;
    }

    // Skip if not user facing app type
    if (context.clientMetadata.userApp !== 'true') {
      return false;
    }

    // Skip already created
    if (user.app_metadata.sfdc.id && !syncContact) {
      log.info('contact created already, skipping');
      return false;
    }

    return true;
  }

  async function checkContactInSFDC() {
    const { access_token: accessToken, instance_url: instanceUrl } = await getAccessToken(
      SFCOM_CLIENT_ID,
      SFCOM_CLIENT_SECRET,
      USERNAME,
      PASSWORD
    );
    // Encoding the phone number
    const phoneNumber = user.phone_number.replace(/\+/g, '%2B');
    // Search contact with phone_number
    contact = await searchContact(instanceUrl, accessToken, phoneNumber);
    if (contact) {
      log.debug(`Existing contact found in SFDC, contact: ${JSON.stringify(contact)}`);
      const linked = await linkAccountsWithSameEmail();
      if (linked) {
        return linked;
      }
    } else {
      log.info('Contact not found in SFDC');
      const deleted = await deleteUser();
      if (deleted) throw new Error('Contact not found in SFDC');
    }
    return null;
  }

  // Function to call SFDC API for searching contacts by phone
  async function searchContact(url, accessToken, phone) {
    try {
      const where = `MobilePhone = '${phone}' or Phone = '${phone}'`;
      const query = `SELECT Id, AccountId, Department, Email, FirstName, LastName, Phone, MobilePhone, PhotoUrl, Title, Name FROM Contact WHERE ${where}`;
      const result = await request.get({
        url: `${url}/services/data/v42.0/query/?q=${query}`,
        headers: {
          Authorization: `OAuth ${accessToken}`
        },
        json: true
      });

      if (result.records && result.records.length > 0) {
        return result.records[0];
      }
      return null;
    } catch (error) {
      throw new Error(`Error searching sfdc for contact ${JSON.stringify(error.error)}`);
    }
  }

  async function getAccessTokenManagementAPI(clientId, clientSecret) {
    if (global.managementToken) return global.managementToken;
    try {
      const response = await request.post({
        url: 'https://fireback.us.auth0.com/oauth/token',
        form: {
          grant_type: 'client_credentials',
          client_id: clientId,
          client_secret: clientSecret,
          audience: 'https://fireback.us.auth0.com/api/v2/'
        }
      });
      global.managementToken = JSON.parse(response);
      return global.managementToken;
    } catch (error) {
      throw new Error(`Error Getting Management API Access Token ${JSON.stringify(error)}`);
    }
  }

  // Obtains a SFDC access_token with user credentials
  async function getAccessToken(clientId, clientSecret, username, password) {
    if (global.sfdcAccessToken) return global.sfdcAccessToken;

    try {
      log.info('getting SFDC access token');
      const rsp = await request.post({
        url: 'https://test.salesforce.com/services/oauth2/token',
        form: {
          grant_type: 'password',
          client_id: clientId,
          client_secret: clientSecret,
          username,
          password
        }
      });
      global.sfdcAccessToken = JSON.parse(rsp);
      log.debug('got SFDC access token');
      return global.sfdcAccessToken;
    } catch (error) {
      throw new Error(`Error Getting SFDC Access Token ${JSON.stringify(error)}`);
    }
  }

  async function deleteUser() {
    const { access_token: accessToken } = await getAccessTokenManagementAPI(
      'jk3lQsW6Jc0eGpCl912RlVQBLkklznbe',
      'w4hhM0we1-PEN3PQwwlEKXqze9gKZmlurusyjGrxqXeIB1r9_yS58VJG9JyxDi6M'
    );
    try {
      const deleted = await request.delete({
        url: `${userApiUrl}/${user.user_id}`,
        headers: {
          Authorization: `Bearer ${accessToken}`,
          'Content-Type': 'application/json',
          'Cache-Control': 'no-cache'
        },
        resolveWithFullResponse: true
      });
      return deleted;
    } catch (error) {
      throw new Error(`ERROR DELETING USER ${JSON.stringify(error)}`);
    }
  }

  async function linkAccountsWithSameEmail() {
    try {
      let data = await request.get({
        url: userSearchApiUrl,
        headers,
        qs: {
          email: contact.Email
        },
        json: true
      });

      data = data.filter(function d(u) {
        // return u.email_verified && (u.user_id !== user.user_id);
        return u.user_id !== user.user_id;
      });

      if (data.length > 1) {
        return callback(
          new Error(
            '[!] Rule: Multiple user profiles already exist - cannot select base profile to link with'
          )
        );
      }
      if (data.length === 0) {
        log.info(`[-] Skipping link rule, no users with associated with ${contact.Email}`);
        return callback(null, user, context);
      }

      const originalUser = data[0];
      const { provider } = user.identities[0];
      const providerUserId = user.identities[0].user_id;

      const result = await request.post({
        url: `${userApiUrl}/${originalUser.user_id}/identities`,
        headers,
        json: {
          provider,
          user_id: String(providerUserId)
        }
      });
      if (result) return originalUser;
    } catch (error) {
      throw new Error(`Error linking the accounts ${JSON.stringify(error.error)}`);
    }
    return null;
  }

  try {
    const linkedUser = await checkContactInSFDC();
    if (linkedUser) {
      context.primaryUser = linkedUser.user_id;
      linkedUser.app_metadata = { sfdc: { id: contact.Id, ts: Date.now() } };
      auth0.users.updateAppMetadata(linkedUser.user_id, linkedUser.app_metadata);
      return callback(null, linkedUser, context);
    }
  } catch (error) {
    log.error(`problem detected: \`\`\`${error.toString()}\`\`\``, true);
    return callback(error, null, context);
  }
  return callback(null, user, context);
}
