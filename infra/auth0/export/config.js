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
    AUTH0_API_MAX_RETRIES: 10
};


//############################################################################
//############################################################################
//
// Export Tenant Config
//
//############################################################################
//############################################################################


dump({
    output_folder: process.env.OUTPUT_FOLDER, // Output directory
    base_path: process.env.BASE_PATH, // Allow to override basepath, if not take from input_file
    config: config, // Option to sent in json as object
    export_ids: true, // Export the identifier field for each object type
})
.then(() => console.log('[+] Auth0 export was successful'))
.catch(err => console.log(`[-] Auth0 export Error:`, err));
