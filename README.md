# REST API

<p align="center">
    <img src="https://i.imgur.com/ldslPC7.png" width="120" >
</p>

This API is developed using the PHP Slim Framework, In this API you can use thease feature.

* **Create an account** ( *An email verification will be sent to user email address when they rgistered an account* )
* **Login into account** ( *User can login into their account when they will successfully verified their account* )
* **Send Email Verification Code** (*You can add a feature that user can send email verifcation code again to their email address* )
* **Update Password** ( *User can update password, An email will also be send when they succesfully changed their password* )
* **Forgot Password** ( *User can make a request that they have forgot their password, An OTP will be send to user's email address* )
* **Reset Password** ( *User can reset password, by using the OTP which they have recieved, An email will also be send when they succesfully changed their password* )
* **Users List** ( *To view all usesrs information e.g. Name, Email,Id. Need authuntication to view users informations* )


## Feauter Explanation

To use this project's feature, you need to make changes only in `Constants.php` file, and that's it.

Set your database connection's information.
```bash
//Database Connection
define('DB_NAME', 'socialcodia');    //your database username
define('DB_USER', 'root');          //your database name
define('DB_PASS', '');              //your database password
define('DB_HOST', 'localhost');     //your database host name
```

And you also need to make change in website section of `Constants.php` file.

```bash
//Website Information
define('WEBSITE_DOMAIN', 'http://api.socialcodia.ml');               //your domain name
define('WEBSITE_EMAIL', 'socialcodia@gmail.com');                    //your email address
define('WEBSITE_EMAIL_PASSWORD', 'password');                        //your email password
define('WEBSITE_EMAIL_FROM', 'Social Codia');                        // your website name here
define('WEBSITE_NAME', 'Social Codia');                              //your website name here
define('WEBSITE_OWNER_NAME', 'Umair Farooqui');                      //your name, we will send this name with email verification mail.

```

```bash
// JWT ( *JSON Web Token* ) Information
define('JWT_SECRET_TOKEN','SocialCodia');                              //Your JWT secret key here,
```
> **Note :** In `JWT_SECRET_TOKEN`, Please use a very hard and dificult key which no one can guess that key.

## Register An Account

To Create An Account, Accept only post request with three parameter
* Name
* Email
* Password

The end point is to Create or Register an account is `createUser`

<b>Demo Url</b> 
* API Url <a href="http://api.socialcodia.ml/createUser">http://api.socialcodia.ml/createUser</a>
* GUI Url <a href="http://restui.socialcodia.ml/register">http://restui.socialcodia.ml/register</a>


An email verification will be send to user email address when they registered an account into the system.

In verification email the verification link will be like this.

```bash

    http://api.socialcodia.ml/verifyEmail/wdpWwmufazmit4Py2aYd7MsocialcodiavknYY3bKxS7okyO9NgpYTmufazmiTGsocialcodiaE=/$2y$10$GWEv1cnJo2YdGbmo4mrwA.LNsocialcodiai4sj8.EdxIZuyWX3fjRHEiBrBX2S

```
* Domain Name : (` http://api.socialcodia.ml/ `)
* End Point (` verifyEmail `)
* Encypted User Email (` wdpWwmufazmit4Py2aYd7MsocialcodiavknYY3bKxS7okyO9NgpYTmufazmiTGsocialcodiaE= `)
* Encypted Code ( `$2y$10$GWEv1cnJo2YdGbmo4mrwA.LNsocialcodiai4sj8.EdxIZuyWX3fjRHEiBrBX2S` )

<p align="center">
    <img src="https://i.imgur.com/AGeCYFR.png" >
</p>

<b>Demo Url</b> 
* API Url <a href="http://api.socialcodia.ml/verifyEmail/wdpWwmufazmit4Py2aYd7MsocialcodiavknYY3bKxS7okyO9NgpYTmufazmiTGsocialcodiaE=/$2y$10$GWEv1cnJo2YdGbmo4mrwA.LNsocialcodiai4sj8.EdxIZuyWX3fjRHEiBrBX2S">http://api.socialcodia.ml/verifyEmail/wdpWwmufazmit4Py2aYd7MsocialcodiavknYY3bKxS7okyO9NgpYTmufazmiTGsocialcodiaE=/$2y$10$GWEv1cnJo2YdGbmo4mrwA.LNsocialcodiai4sj8.EdxIZuyWX3fjRHEiBrBX2S</a>


## Send Email Verification Code Again

To Send The Email Verification Code again, Accept only post request with only one parameter
* Email

User can make the send email verification link code if there email address is not verified yet.

The end point of send email verification code is `updatePassword`

<b>Demo Url</b>
* API Url <a href="http://api.socialcodia.ml/updatePassword">http://api.socialcodia.ml/updatePassword</a>
* GUI Url <a href="http://restui.socialcodia.ml/updatePassword">http://restui.socialcodia.ml/updatePassword</a>


## Login Into Account

To Login into Account, Accept only post request with two parameter
* Email
* Password

The end point of login is `login`

When user provide their username & password credential for login, the request will return their public information with **Token**

The return infomration from the database will be like this.

```bash
{
    "error": false,
    "message": "Login Successfull",
    "user": {
        "id": 173,
        "name": "Social Codia",
        "email": "socialcodia@gmail.com",
        "token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJzb2NpYWxjb2RpYS5uZXQiLCJpYXQiOjE1OTIwNjE5NTcsInVzZXJfaWQiOjE3M30.JPzaIPwxUCISSM-tqfeUysm-kpmG32y6eq_1Cdxhzr4"
    }
}
```

<b>Demo Url</b> 
* API Url <a href="http://api.socialcodia.ml/login">http://api.socialcodia.ml/login</a>
* GUI Url <a href="http://restui.socialcodia.ml/login">http://restui.socialcodia.ml/login</a>

## Forgot Password

To send the Forgot Password request, Accept only post request with only one parameter
* Email

The end point of Forgot Password is `forgotPassword`

An OTP wil be sent to email address.

When you make a post request on the `forgotPassword`, 

This will perform these Validation before sending an OTP to users email address.

* The Email parameter should not be empty.
* The Email Address is a Valid email address or not.
* The Email Address is Exist into your database server or not.
* The Email Address is Verified email address or not.

<p align="center">
    <img src="https://i.imgur.com/zDJCbnS.png" >
</p>

<b>Demo Url</b> 
* API Url <a href="http://api.socialcodia.ml/forgotPassword">http://api.socialcodia.ml/forgotPassword</a>
* GUI Url <a href="http://restui.socialcodia.ml/forgotPassword">http://restui.socialcodia.ml/forgotPassword</a>

## Reset Password

To Reset the password, Accept only post request with three parameter
* Email
* OTP
* Password

The end point of Reset Password is `resetPassword`

When you make a request to Reset the password on `resetPassword`

This will perform some validation before varifying the OTP.
* The Email `Email`, `OTP` and `Password` should not be empty.
* The Email Address is a Valid email address or not.
* The Email Address is Exist into your database server or not.
* The Email Address is Verified email address or not.

Then they will check the `OTP` is correct or not, if correct then the new password will update into server.

<b>Demo Url</b> 
* API Url <a href="http://api.socialcodia.ml/resetPassword">http://api.socialcodia.ml/resetPassword</a>
* GUI Url <a href="http://restui.socialcodia.ml/resetPassword">http://restui.socialcodia.ml/resetPassword</a>


## Update Account Password

To update or changed the current password, Accept post request with two parameter with header.
* Password
* newPassword

The **Token** must be go in header, The token is mandatory for acception of request.
* Token


> Before returninng any data, This request will verify the current login users information using **Token**, and after that this will fetch the `user id` from the **Token** and update their password into database. An email notification also be sent when they will change their password with **Time**, **Date** and **Ip Address**.

The end point of update password is `updatePassword`

<b>Demo Url</b> 

* API Url <a href="http://api.socialcodia.ml/updatePassword">http://api.socialcodia.ml/updatePassword</a>
* GUI Url <a href="http://restui.socialcodia.ml/settings">http://restui.socialcodia.ml/settings</a>


an verification code will be sent to user email address when they successfull updated their password.

When any user reset there password or changed there password, a confirmation email will be deliver to their registered email address that the password has been changed,

For security reason, The email will be deliver with three parameter **Time** and **Date** and **Ip Address** .

<p align="center">
    <img src="https://i.imgur.com/dwo4Ol8.png" >
</p>

## View Users List
To view all users list from database, Authuntication is very compulsry for that, Any authunticated user can view the users public information list, e.g. Id, Name and Email,

To view the users public informations list, Accept only GET request with no parameter,
* This request will return the only the verified users public information.
* This request will take an authorization token to validate the user.

The end point of Users List is `users`

<b>Demo Url</b> 

* API Url <a href="http://api.socialcodia.ml/users">http://api.socialcodia.ml/users</a>
* GUI Url <a href="http://restui.socialcodia.ml/users">http://restui.socialcodia.ml/users</a>


### At the end

you don't need to worry about that things, you only need to change the code of `Constants.php` File.

* You can check out the UI which is mainely developed for this project, <a href="https://github.com/SocialCodia/RestUi">@SocialCodia/RestUi</a>

* Visit on the link to perform API Action, http://RestUi.SocialCodia.ml

That's it! Now go build something cool.
