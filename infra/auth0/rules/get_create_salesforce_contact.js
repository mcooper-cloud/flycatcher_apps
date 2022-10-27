/* eslint-disable */
async function salesforceContact(user, context, cb) {
  /*
    This rule will create or link the users contact record in the SalesForce CRM
  */

  const log = global.getLogger
    ? global.getLogger('SalesForce Contact Rule', cb)
    : {
        callback: cb,
        error: console.error,
        info: console.log,
        debug: console.log
      };
  const { callback } = log;

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
  // Just example, can contain many more fields
  const contactData = {
    Email: user.email,
    FirstName: user.given_name,
    LastName: user.family_name,
    Department: 'fireback-demo',
    AccountId: '00102000009HQJcAAO'
  };

  // Skip if we don't need to run
  if (!shouldRun()) {
    return callback(null, user, context);
  }

  function shouldRun() {
    // Skip no email
    if (!user.email) {
      log.info('user does not have email, skipping creation of contact in SFDC');
      return false;
    }

    // Skip if no first/last name as those fields are required in SFDC
    if (!user.family_name || !user.given_name) {
      log.info('user does not have first/last, skipping creation of contact in SFDC');
      return false;
    }

    // Skip already created
    if (user.app_metadata.sfdc.id && !syncContact) {
      log.info('contact created already, skipping');
      return false;
    }

    // Skip if not user facing app type
    if (context.clientMetadata.userApp !== 'true') {
      return false;
    }

    // Skip if in checkSession and prompt none
    if (context.protocol === 'redirect-callback' || context.request.query.prompt === 'none') {
      return false;
    }

    // Skip if checked within 30 seconds
    const nextCheck = (user.app_metadata.sfdc.ts || 0) + 30000;
    if (nextCheck > Date.now()) {
      log.info('skipping as checked in last 30 seconds');
      return false;
    }
    return true;
  }

  const request = require('request-promise');

  async function getCreateContact() {
    const { access_token: accessToken, instance_url: instanceUrl } = await getAccessToken(
      SFCOM_CLIENT_ID,
      SFCOM_CLIENT_SECRET,
      USERNAME,
      PASSWORD
    );

    let contact = null;
    if (user.app_metadata.sfdc.id) {
      contact = await getContact(instanceUrl, accessToken, user.app_metadata.sfdc.id);
    } else {
      contact = await searchContact(instanceUrl, accessToken, user.email);
    }

    if (contact) {
      contact.existing = true;
    } else {
      contact = await createContact(instanceUrl, accessToken, contactData);
    }

    if (!user.app_metadata.sfdc.id) {
      const contactUrl = `https://ap4.lightning.force.com/one/one.app#/sObject/${contact.Id}/view`;
      if (contact.existing) {
        log.info(`existing contact found in SFDC, linked (${contactUrl})`, true);
      } else {
        log.info(`created new contact in SFDC, linked (${contactUrl})`, true);
      }
    }

    user.app_metadata.sfdc = { id: contact.Id, ts: Date.now() };
    auth0.users.updateAppMetadata(user.user_id, user.app_metadata);

    if (contact.MobilePhone) {
      user.user_metadata.mobile = contact.MobilePhone || user.user_metadata.mobile;
      auth0.users.updateUserMetadata(user.user_id, user.user_metadata);
    }
  }

  // Function to call SFDC API for searching contacts by email
  async function getContact(url, accessToken, sfdcId) {
    try {
      return request.get({
        url: `${url}/services/data/v42.0/sobjects/Contact/${sfdcId}`,
        headers: {
          Authorization: `OAuth ${accessToken}`
        },
        json: true
      });
    } catch (error) {
      throw new Error(`Error getting contact ${JSON.stringify(error.error)}`);
    }
  }

  // Function to call SFDC API for searching contacts by email
  async function searchContact(url, accessToken, email, sfdcId) {
    try {
      const where = sfdcId ? `Id = '${sfdcId}'` : `Email = '${email}'`;
      const query = `SELECT Id, AccountId, Department, Email, FirstName, LastName, MobilePhone, PhotoUrl, Title, Name FROM Contact WHERE ${where}`;
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

  // Function to call SFDC API for contact creation
  async function createContact(url, accessToken, data) {
    try {
      const contact = await request.post({
        url: `${url}/services/data/v42.0/sobjects/Contact`,
        headers: {
          Authorization: `OAuth ${accessToken}`
        },
        json: data
      });
      return { ...data, Id: contact.id };
    } catch (error) {
      throw new Error(`Error creating contact ${JSON.stringify(error.error)}`);
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
      log.info('got SFDC access token');
      return global.sfdcAccessToken;
    } catch (error) {
      throw new Error(`Error Getting SFDC Access Token ${JSON.stringify(error.error)}`);
    }
  }

  try {
    getCreateContact();
  } catch (error) {
    log.error(`problem detected: \`\`\`${error.toString()}\`\`\``, true);
  }
  return callback(null, user, context);
}
