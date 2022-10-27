// eslint-disable-next-line no-unused-vars
function verify(user, context, cb) {
  const log = global.getLogger
    ? global.getLogger('Migration Rule', cb)
    : {
        callback: cb,
        error: console.error,
        info: console.log,
        debug: console.log
      };
  const { callback } = log;

  const consumerDomain = 'fireback-demo.travel0.net';
  const corporateDomain = 'fireback-demo.corporate.travel0.net';

  if (context.stats.loginsCount === 1 && user.app_metadata.migrated) {
    const domain = context.connection === 'consumer-users' ? consumerDomain : corporateDomain;

    request(
      {
        url: `https://${domain}/api/v1/legacy/migrate?username=${user.username}`,
        method: 'GET',
        json: true
      },
      error => {
        if (error) {
          callback(error);
        }
      }
    );
  }
  callback(null, user, context);
}
