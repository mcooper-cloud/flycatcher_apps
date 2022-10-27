// eslint-disable-next-line no-unused-vars
function deDupeEmail(user, context, callback) {
  // Set app_metadata to empty object if it has not been set
  user.app_metadata = user.app_metadata || {};
  const email = user.email || '';

  if (context.clientName === 'Duplicates0') {
    context.idToken['https://duplicate.email/duplicate_email'] = user.app_metadata.duplicate_email;
    callback(null, user, context);
    return;
  }

  function shouldTriggerEmailDeDupe() {
    // User has already been processed / verified their email
    if (user.email_verified) return false;

    // User is flagged as duplicated but has no completed de-duplication process
    if (user.app_metadata.duplicate_email) return true;
    // User email was detected by custom database script as being duplicate
    return email.includes('@duplicate.email');
  }

  if (shouldTriggerEmailDeDupe()) {
    // Redirect to the Deduplicate App
    context.redirect = {
      url: `https://fireback-demo.ddup-emails.accounts.travel0.net?t=${Date.now()}`
    };
  }

  callback(null, user, context);
}
