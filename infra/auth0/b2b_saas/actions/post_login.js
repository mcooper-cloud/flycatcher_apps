exports.onExecutePostLogin = async (event, api) => {

    //
    // Auth0 Management API Client
    //
    const { ManagementClient } = require("auth0");


    const admin_role = 'OrgAdmin'
    const member_role = 'OrgMember'

    const user = event.user
    const user_id = user.user_id
    const connection_id = event.connection.id
    const logins_count = event.stats.logins_count
    const requested_scopes = event.transaction.requested_scopes
    const roles = event.authorization.roles

    let current_org = false;
    const namespace = event.secrets.CUSTOM_SCOPE_NAMESPACE;

    const domain = event.secrets.AUTH0_DOMAIN;
    const client_id = event.secrets.AUTH0_MGMT_CLIENT_ID;
    const client_secret = event.secrets.AUTH0_MGMT_CLIENT_SECRET;
    const audience = `https://${domain}/api/v2/`;

    /*
    console.log(
        "Event: %s",
        event
    );
    */

    //
    // management client
    //
    try {

        const mgmt_scope = "read:users update:users delete:users create:users read:organizations update:organizations create:organizations delete:organizations read:organization_connections create:organization_connections update:organization_connections delete:organization_connections";

        //
        // TODO Management API rate limits error handling
        //

        var mgmt_client = new ManagementClient({
            domain: domain,
            clientId: client_id,
            clientSecret: client_secret,
            scope: mgmt_scope,
            audience: audience,

            tokenProvider: {
                enableCache: true,
                cacheTTLInSeconds: 10,
            },

        });

    } catch (e) {
        console.log("Error creating MGMT client: %s", e.message);
    }


    //
    // set custom claims
    //
    try {

        for (const [key, value] of Object.entries(event.user.app_metadata)) {
            var name = `${namespace}/${key}`;
            api.accessToken.setCustomClaim(name, value)
        }

        var role_claim = `${namespace}/roles`;
        api.accessToken.setCustomClaim(role_claim, roles)

    } catch (e) {
        console.log("Error setting custom claims: %s", e.message);
    }


    //
    // current org
    //
    try {

        if (event.organization !== undefined) {
            current_org = event.organization.id;

            if (roles.length === 0 && logins_count <= 1) {
                /*
                * if first login and no roles assigned
                */

                var params = {
                    per_page: 10,
                    page: 0
                };


                var role_names = await mgmt_client.getRoles(params)
                for (const role of role_names) {

                    if (role.name.includes(member_role)) {

                        var params =  {id : current_org, user_id: user_id};
                        var data = { roles: [ role.id ]}

                        mgmt_client.organizations.addMemberRoles(params, data);

                        var role_claim = `${namespace}/roles`;
                        api.accessToken.setCustomClaim(role_claim, [role.name])

                        var params =  { id :role.id};
                        var role_permissions = await mgmt_client.getPermissionsInRole(params)
                        api.accessToken.setCustomClaim('permissions', [role_permissions])

                    }
                }
            }
        }

        //
        // the user has logged in using an org ID and as a result has
        // the value event.organization.id
        //
        if (current_org) {

            //
            // name
            //
            var name = `${namespace}/current_org_name`;
            var value = event.organization.name
            api.accessToken.setCustomClaim(name, value)


            //
            // display name
            //
            var name = `${namespace}/current_org_display_name`;
            var value = event.organization.display_name
            api.accessToken.setCustomClaim(name, value)


            //
            // metadata
            //

            if (event.organization.metadata) {
                var name = `${namespace}/current_org_metadata`;
                var value = event.organization.metadata
                api.accessToken.setCustomClaim(name, value)

                if ('tier' in event.organization.metadata) {
                    var name = `${namespace}/current_org_tier`;
                    var value = event.organization.metadata.tier

                    api.accessToken.setCustomClaim(name, value)
                }
            }
        }

    } catch (e) {
        console.log("Current org error: %s", e.message);
    }


    //
    // primary org
    //
    try {

        const primary_org = event.user.app_metadata.primary_org || false;

        if (primary_org) {
            if (primary_org !== current_org){

                //
                // the user has logged into and org other than their
                // primary organization ... add primary org data
                // to the resulting token
                //

                var primary_org_param = {
                    id : primary_org
                }

                var primary_org_data = await mgmt_client.organizations.getByID(primary_org_param)

                if ('name' in primary_org_data) {
                    var name = `${namespace}/primary_org_name`;
                    var value = primary_org_data['name']
                    api.accessToken.setCustomClaim(name, value)

                }

                if ('display_name' in primary_org_data) {
                    var name = `${namespace}/primary_org_display_name`;
                    var value = primary_org_data['display_name']
                    api.accessToken.setCustomClaim(name, value)

                }
                if ('metadata' in primary_org_data) {

                    var name = `${namespace}/primary_org_metadata`;
                    var value = primary_org_data['metadata']
                    api.accessToken.setCustomClaim(name, value)

                    if ('tier' in primary_org_data['metadata']) {
                        var name = `${namespace}/primary_org_tier`;
                        var value = primary_org_data['metadata']['tier']
                        api.accessToken.setCustomClaim(name, value)
                    }
                }
            }
        }
    } catch (e) {
        console.log("Primary org error: %s", e.message);
    }
}