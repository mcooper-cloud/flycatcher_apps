Go here: https://flycatcher.auth0.pintail.rocks/

1. click sign up for one of the service "Tiers"

    a. provide an org name and email address

    What just happened?

    The backend just created a new org in Auth0 and invited you to join the org
    Metadata was added to the org to keep track of the tier that you signed up for

    The org was named using a UUID and the name you provided at signup was used for the display name

2. now go to your inbox and answer the invitation

    What just happened?

    a new user profile was created in Auth0 with the app_metadata value {"primary_org" : [ORG_ID]}
    The user was assigned the role OrgAdmin and given a set of permissions


3. click 'My Profile' and copy the access token and pasted into jwt.io

4. Click 'My Org'

    you'll see the metadata added to your org (including tier)

5. Click 'Add Ons' ... click one or two of the 'Subscribe' buttons

    what just happened?

    The backend


6. click 'Invite Member'

    Use the Gmail + syntax (I.E. matt.cooper+invitee@auth0.com) and click send invite

    What just happened?

    The backend created an invite to the org

6. Logout and go to your inbox and answer the new invite

    what just happened?

    a new user profile was created in Auth0 with the app_metadata value {"primary_org" : [ORG_ID]}
    The user was assigned the role OrgMember and given a set of permissions


