/* 
** See: https://auth0.com/docs/deploy/deploy-cli-tool/call-deploy-cli-tool-programmatically
*/

const { deploy, dump } = require("auth0-deploy-cli");

const config = {
    AUTH0_DOMAIN: process.env.AUTH0_DOMAIN,
    AUTH0_CLIENT_SECRET: process.env.AUTH0_CLIENT_SECRET,
    AUTH0_CLIENT_ID: process.env.AUTH0_CLIENT_ID,
    AUTH0_EXPORT_IDENTIFIERS: false,
    AUTH0_ALLOW_DELETE: true,
    AUTH0_API_MAX_RETRIES: 10,
    AUTH0_KEYWORD_REPLACE_MAPPINGS: {
        "PROJECT_NAME": process.env.PROJECT_NAME,
        "ENVIRONMENT": process.env.ENVIRONMENT,
        "SYSTEM_NUMBER": process.env.SYSTEM_NUMBER,
        "AUTH0_SUBDOMAIN": process.env.AUTH0_SUBDOMAIN,
        "AUTH0_MGMT_API_ENDPOINT": process.env.AUTH0_MGMT_API_ENDPOINT,
        "AUTH0_CALLBACK_URL" : process.env.AUTH0_CALLBACK_URL,
        "AUTH0_LOGOUT_URL" : process.env.AUTH0_LOGOUT_URL,
        "AUTH0_LOGIN_URL" : process.env.AUTH0_LOGIN_URL,
        "AUTH0_API_AUDIENCE" : process.env.AUTH0_API_AUDIENCE,
        "WEB_APP_HTTP_URL" : process.env.WEB_APP_HTTP_URL,
        "PAGE_BACKGROUND_COLOR" : process.env.PAGE_BACKGROUND_COLOR,
        "PRIMARY_COLOR" : process.env.PRIMARY_COLOR,
        "LOGO_URL" : process.env.LOGO_URL
    },
};

console.log(`[+] process.env.INPUT_PATH: ${process.env.INPUT_PATH}`)
console.log(`[+] process.env.AUTH0_CALLBACK_URL: ${process.env.AUTH0_CALLBACK_URL}`)
console.log(`[+] process.env.AUTH0_LOGOUT_URL: ${process.env.AUTH0_LOGOUT_URL}`)
console.log(`[+] process.env.AUTH0_AUDIENCE: ${process.env.AUTH0_AUDIENCE}`)


deploy({
    input_file: process.env.INPUT_PATH, // Input file for directory, change to .yaml for YAML
    config: config, // Option to sent in json as object
})
.then(() => console.log('[+] Auth0 deploy was successful'))
.catch(err => console.log(`[-] Auth0 deploy Error:`, err));
