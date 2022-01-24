
function rule (user, context, callback) {
    const LOG_PREFIX = '[Rule: Helper functions] ';

    const request = require('request-promise@1.0.2');

    global.helpers = {};

    console.log(LOG_PREFIX, 'Helper functions defined');
    callback(null, user, context);
}