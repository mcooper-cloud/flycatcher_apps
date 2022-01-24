exports.onExecutePostUserRegistration = async (event, api) => {

    //
    // Auth0 Management API Client
    //
    const { ManagementClient } = require("auth0@2.35.0");


    const namespace = 'https://flycatcher.auth0.pintail.rocks';
    const user = event.user
    const user_id = user.user_id
    const connection_id = event.connection.id


    /*
    console.log(
        "Event: %s",
        event
    );
    */
    try {

        const domain = event.secrets.AUTH0_DOMAIN;
        const client_id = event.secrets.AUTH0_MGMT_CLIENT_ID;
        const client_secret = event.secrets.AUTH0_MGMT_CLIENT_SECRET;
        const app_client_id = event.secrets.AUTH0_APP_CLIENT_ID;
        const audience = `https://${domain}/api/v2/`;

        const mgmt_scope = "read:users update:users delete:users create:users read:organizations update:organizations create:organizations delete:organizations read:organization_connections create:organization_connections update:organization_connections delete:organization_connections";

        //
        // TODO Management API rate limits error handling
        //
        console.log("Creating mgmt client");

        var mgmt_client = new ManagementClient({
            domain: domain,
            clientId: client_id,
            clientSecret: client_secret,
            scope: mgmt_scope,
            audience: audience,
            /*
            tokenProvider: {
                enableCache: true,
                cacheTTLInSeconds: 10,
            },
            */
        });
        console.log("Finished creating mgmt client");

        //
        // create a individual organization
        //
        var org_data = {
            name: user_id.split('|').pop(),
            display_name: `Individual Org for ${user_id}`,
            metadata: {'org_type': 'individual'}
        }

        console.log("Creating Org");

        var org_res = await mgmt_client.organizations.create(org_data);

        var org_id = org_res.id

        var org_param = {
            id : org_id
        }


        //
        // add the default database connection to the org
        //

        var connection_data = { 
            connection_id : connection_id, 
            assign_membership_on_login: false 
        };
        var conn_res = await mgmt_client.organizations.addEnabledConnection(org_param, connection_data);


        /*
        //
        // Option 1: invite the user to the org
        //

        var invite_data = {
            inviter: {
                name: "Flycatcher"
            },
            invitee: {
                email: user.email
            },
            client_id: app_client_id
        }

        var invite_res = await mgmt_client.organizations.createInvitation(org_param, invite_data);
        */


        //
        // Option 2: add the user to the org
        //
        var invite_data = { members: [ user_id ] }
        var invite_res = await mgmt_client.organizations.addMembers(org_param, invite_data);

        console.log("Finished creating org");

    } catch (e) {
        console.log("Error: %s", e);
    }
}