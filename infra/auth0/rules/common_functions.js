// eslint-disable-next-line no-unused-vars
function common(user, context, callback) {
  /*
    The purpose of this rule is to provide a common logging style across all rules.
    Log Format
      LOG_LEVEL [TENANT] (RULE_NAME) (CONNECTION_NAME) (CURRENT_USERID): MSG;
   */

  // Slack channel
  const slackChannel = '#demo-platform-monitoring';
  const slack = require('slack-notify')(configuration.SLACK_HOOK_URL);
  const SumoLogger = require('sumo-logger');
  const opts = {
    endpoint: 'https://collectors.de.sumologic.com/receiver/v1/http/ZaVnC4dhaV3sU4phFS1JaYyNyaKvDbFVxAq5nHyeGLw_HYETMlxhWEPxPqRtZrE9dzPQq1Kbm7VyB2r-2IphHPHSqtdpR90m44YnAKs1qPoRtcobQAfDkQ==',
    sessionKey: '8be50a0c-0bde-11ec-8bcc-6e595f3e74fe',
    hostname: 'fireback-demo.accounts.travel0.net',
    sourceCategory: 'demo/tenant',
    sourceName: 'fireback',
    // ... any other options ...
    onError: () => {
      // eslint-disable-next-line no-use-before-define
      doLog('ERROR', '-', 'Sending message to SumoLogic Failed', true, true);
    }
  };

  // Instantiate the SumoLogger
  const sumoLogger = new SumoLogger(opts);

  // Write to log
  function doLog(level, rule, msg, toSlack, skipSumo = false) {
    const logLevel = level.toUpperCase();
    const userID = `${user.user_id} (${user.email})`;

    console.log(`[${logLevel}] (${rule}) (${context.connection}) (${userID}): ${msg}`);
    if (toSlack) {
      const method = logLevel === 'ERROR' ? slack.alert : slack.note;
      method(
        {
          text: `*[fireback-demo]* (\`${rule}\`) (\`${context.connection}\`) (\`${userID}\`) - ${msg}`,
          channel: slackChannel
        },
        err => {
          if (err) {
            console.log('ERROR sending slack message:', err);
          }
        }
      );
    }

    if (!skipSumo) {
      sumoLogger.log({
        logLevel: level,
        demoName: 'fireback-demo',
        rule,
        // Do we need this with all?
        context,
        // Do we need this with all?
        user,
        action: 'rule_execution',
        description: msg
      });
    }
  }

  doLog('INFO', 'Common', 'Starting new authentication transaction');

  // Logger helper
  global.getLogger = (rule, ruleCallback) => {
    const timerName = `${rule || 'Unknown Rule'}-${user.user_id}-${context.sessionID}`;
    console.time(timerName);
    doLog('INFO', rule, `Starting Rule ${rule}`);

    return {
      callback: (err, usr, ctx) => {
        doLog('INFO', rule, `Finished Rule ${rule}`);
        console.timeEnd(timerName);
        sumoLogger.flushLogs();
        ruleCallback(err, usr, ctx);
      },
      error: (msg, toSlack) => doLog('ERROR', rule, msg, toSlack),
      info: (msg, toSlack) => doLog('INFO', rule, msg, toSlack),
      debug: (msg, toSlack) => doLog('DEBUG', rule, msg, toSlack)
    };
  };

  callback(null, user, context);
}
