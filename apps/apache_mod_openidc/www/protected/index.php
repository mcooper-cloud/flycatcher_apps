<!doctype html>
<html lang="en">
    <head>

        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@4.6.0/dist/css/bootstrap.min.css">
        <!-- font awesome from BootstrapCDN -->
        <link href="//maxcdn.bootstrapcdn.com/font-awesome/4.6.3/css/font-awesome.min.css" rel="stylesheet">
        <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.5.0/font/bootstrap-icons.css">
        <link href="/css/app.css" rel="stylesheet">
        <title>Dashboard</title>
        <link rel="icon" type="image/svg+xml" href="https://openmoji.org/data/color/svg/1F984.svg">

    </head>
    <body class="dashboard">
        <div class="container-fluid dashboard-wrapper">
            <div class="row">

                <nav class="col-md-2 d-none d-md-block bg-light sidebar">
                    <div class="sidebar-sticky">
                        <div class="dashboard-logo">
                            <img src="https://openmoji.org/data/color/svg/1F984.svg" height="56" alt="Dashbaord">
                            <br/>
                            Dashboard
                        </div>

                        <ul class="nav flex-column">
                            <li class="nav-item">
                                <a class="nav-link" href="/">
                                    Home
                                </a>
                            </li>
                            <li class="nav-item">
                                <a class="nav-link" href="/protected">
                                    Protected
                                </a>
                            </li>
                            <li class="nav-item">
                                <a class="nav-link" href="/unprotected">
                                    Unprotected
                                </a>
                            </li>
                            <li class="nav-item">
                                <a class="nav-link" href="/phpinfo">
                                    phpInfo()
                                </a>
                            </li>
                        </ul>
                    </div>
                </nav>

                <main role="main" class="col-md-9 ml-sm-auto col-lg-10 pt-3 px-4">

                    <div class="dashboard-nav">
                        <nav class="navbar navbar-expand-md navbar-light header-content">
                            <div class="collapse navbar-collapse" id="navbarCollapse">
                                <button class="navbar-toggler" type="button" data-toggle="collapse" data-target="#navbar-list-4" aria-controls="navbarNav" aria-expanded="false" aria-label="Toggle navigation">
                                    <span class="navbar-toggler-icon"></span>
                                </button>
                                <div class="collapse navbar-collapse" id="navbar-list-4">
                                    <ul class="navbar-nav">
                                        <li class="nav-item dropdown">
                                            <a class="nav-link dropdown-toggle" href="#" id="navbarDropdownMenuLink" role="button" data-toggle="dropdown" aria-haspopup="true" aria-expanded="false">

                                                <?php 
                                                    $pic = apache_getenv("picture"); 
                                                    echo '<img src="'.$pic.'" width="40" height="40" class="rounded-circle profile-icon">';
                                                ?>

                                            </a>
                                            <div class="dropdown-menu profile-menu" aria-labelledby="navbarDropdownMenuLink">
                                                <table class="dropdown-profile">
                                                    <tr><td class="profile-icon">


                                                        <?php 
                                                            $pic = apache_getenv("picture"); 
                                                            echo '<img src="'.$pic.'" width="40" height="40" class="rounded-circle profile-icon">';
                                                        ?>


                                                    </td><td class="profile-name">
                                                        <?php echo apache_getenv("nickname"); ?>
                                                    </td></tr>
                                                </table>
                                                <a class="dropdown-item" href="/protected">
                                                    Edit Profile
                                                </a>


                                                <?php 

                                                    $auth0_domain = getenv('AUTH0_AUTH_DOMAIN');   
                                                    $auth0_client_id = getenv('AUTH0_CLIENT_ID');   
                                                    $http_url = getenv('WEB_APP_HTTP_URL');   

                                                    $http_on = apache_getenv("HTTPS");

                                                    if($http_on == 'on') {

                                                        $protocol = 'https://';

                                                    } else {

                                                        $protocol = 'http://';

                                                    }

                                                    $href = $protocol.$auth0_domain.'/v2/logout?client_id='.$auth0_client_id.'&returnTo='.$http_url.'/callback%3Flogout='.$http_url;

                                                    echo '<a class="btn btn-primary logout dropdown-item" href="'.$href.'">Logout</a>';

                                                ?>
                                            </div>
                                        </li>
                                    </ul>
                                </div>
                            </div>
                        </nav>
                    </div>
<h1>Apache Environment</h1>
<table class="table-responsive table-striped table-sm">
    <thead>
        <tr>
            <th>Key</th>
            <th>Value</th>
        </tr>
    </thead>
    <tbody>
        <tr>
            <th scope="row" class="profile-key">Name</th>
            <td class="profile-value"><?php echo apache_getenv("name"); ?></td>
        </tr>
        <tr>
            <th scope="row" class="profile-key">Nickname</th>
            <td class="profile-value"><?php echo apache_getenv("nickname"); ?></td>
        </tr>
        <tr>
            <th scope="row" class="profile-key">Email</th>
            <td class="profile-value"><?php echo apache_getenv("email"); ?></td>
        </tr>
        <tr>
            <th scope="row" class="profile-key">Email Verified</th>
            <td class="profile-value"><?php echo apache_getenv("email_verified"); ?></td>
        </tr>
        <tr>
            <th scope="row" class="profile-key">Subclaim</th>
            <td class="profile-value"><?php echo apache_getenv("sub"); ?></td>
        </tr>
        <tr>
            <th scope="row" class="profile-key">Access Token</th>
            <td class="profile-value">
                <div class="jwt">

                    <?php 

                        $access_token = apache_getenv("OIDC_access_token");
                        echo '<a target="_blank" href="https://jwt.io/#token='.$access_token.'">Decode Access Token</a>';

                    ?>

                </div>
                <?php echo apache_getenv("OIDC_access_token"); ?>
            </td>
        </tr>
    </tbody>
</table>


<h1>HTTP Headers</h1>
<table class="table-responsive table-striped table-sm">
    <thead>
        <tr>
            <th>Key</th>
            <th>Value</th>
        </tr>
    </thead>
    <tbody>
        <?php
            foreach (getallheaders() as $name => $value) {
                echo '<tr><th scope="row" class="profile-key">'.$name.'</th><td class="profile-value">'.$value.'</td></tr>';
            }
        ?>
    </tbody>
</table>


                </main>
            </div>
        </div>



        <script src="https://code.jquery.com/jquery-3.3.1.slim.min.js" integrity="sha384-q8i/X+965DzO0rT7abK41JStQIAqVgRVzpbzo5smXKp4YfRvH+8abtTE1Pi6jizo" crossorigin="anonymous"></script>

        <script src="https://stackpath.bootstrapcdn.com/bootstrap/4.3.1/js/bootstrap.min.js" integrity="sha384-JjSmVgyd0p3pXB1rRibZUAYoIIy6OrQ6VrjIEaFf/nJGzIxFDsf4x0xIM+B07jRM" crossorigin="anonymous"></script>

    </body>
</html>