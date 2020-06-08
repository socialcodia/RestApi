<?php
use Psr\Http\Message\ResponseInterface as Response;
use Psr\Http\Message\ServerRequestInterface as Request;


use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\SMTP;
use PHPMailer\PHPMailer\Exception;

//use Slim\Factory\AppFactory;

require '../vendor/autoload.php';
require_once '../include/DbOperations.php';
require_once '../vendor/autoload.php';

$app = new \Slim\App;
$app = new Slim\App([

    'settings' => [
        'displayErrorDetails' => true,
        'debug'               => true,
    ]

]);


$app->post('/createUser', function(Request $request, Response $response)
{
    $result = array();
    if(!checkEmptyParameter(array('name','email','password'),$request,$response))
    {
        $db = new DbOperations();

        $requestParameter = $request->getParsedBody();
        $email = $requestParameter['email'];
        $password = $requestParameter['password'];
        $name = $requestParameter['name'];
        $result = array();
        $result = $db->createUser($name,$email,$password);

        if($result['message'] == USER_CREATION_FAILED)
        {
            $errorDetails = array();
            $errorDetails['error'] = true;
            $errorDetails['message'] = "Failed to create an account";
            $response->write(json_encode($errorDetails));
    
            return $response->withHeader('Content-Type','application/json')
                            ->withStatus(200);
        }
        else if($result['message'] == EMAIL_EXIST)
        {
            $errorDetails = array();
            $errorDetails['error'] = true;
            $errorDetails['message'] = "Email already registered";
            $response->write(json_encode($errorDetails));
    
            return $response->withHeader('Content-Type','application/json')
                            ->withStatus(200);
        }
        else if($result['message'] == USER_CREATED)
        {
            $code = $result['code'];
            $name = $result['name'];
            if(prepareVerificationMail($name,$email,$code))
            {
                $errorDetails = array();
                $errorDetails['error'] = false;
                $errorDetails['message'] = "An Email Verification Link Has Been Sent Your Email Address: ".$email;
                $response->write(json_encode($errorDetails));
                return $response->withHeader('Content-Type','application/json')
                                ->withStatus(200);
            }
            else
            {
                $errorDetails = array();
                $errorDetails['error'] = true;
                $errorDetails['message'] = 'Failed To Send Verification Email';
                $response->write(json_encode($errorDetails));
        
                return $response->withHeader('Content-Type','application/json')
                                ->withStatus(200);
            }
        }
        else if($result['message'] == VERIFICATION_EMAIL_SENT_FAILED)
        {
            $errorDetails = array();
            $errorDetails['error'] = true;
            $errorDetails['message'] = 'Failed To Send Verification Email';
            $response->write(json_encode($errorDetails));
    
            return $response->withHeader('Content-Type','application/json')
                            ->withStatus(200);
        }
        else if($result['message'] == EMAIL_NOT_VALID)
        {
            $errorDetails = array();
            $errorDetails['error'] = true;
            $errorDetails['message'] = "Enter Valid Email";
            $response->write(json_encode($errorDetails));
    
            return $response->withHeader('Content-Type','application/json')
                            ->withStatus(200);
        }
    }

});

$app->post('/login', function(Request $request, Response $response)
{
    $result = array();
    if(!checkEmptyParameter(array('email','password'),$request,$response))
    {
        $db = new DbOperations;
        $requestParameter = $request->getParsedBody();
        $email = $requestParameter['email'];
        $password = $requestParameter['password'];
        $result = $db->login($email,$password);

        if($result['message'] ==LOGIN_SUCCESSFULL)
        {
            $user = $db->getUserByEmail($email);
            $errorDetails = array();
            $errorDetails['error'] = false;
            $errorDetails['message'] = "Login Successfull";
            $errorDetails['user'] = $user;
            $response->write(json_encode($errorDetails));
    
            return $response->withHeader('Content-Type','application/json')
                            ->withStatus(200);
        }
        
        else if($result['message'] ==USER_NOT_FOUND)
        {
            $errorDetails = array();
            $errorDetails['error'] = true;
            $errorDetails['message'] = "Email Is Not Registered";
            $response->write(json_encode($errorDetails));
    
            return $response->withHeader('Content-Type','application/json')
                            ->withStatus(200);
        }
        else if($result['message'] ==PASSWORD_WRONG)
        {
            $errorDetails = array();
            $errorDetails['error'] = true;
            $errorDetails['message'] = "Wrong Password";
            $response->write(json_encode($errorDetails));
    
            return $response->withHeader('Content-Type','application/json')
                            ->withStatus(200);
        }
        else if($result['message'] ==UNVERIFIED_EMAIL)
        {
            $errorDetails = array();
            $errorDetails['error'] = true;
            $errorDetails['message'] = "Email Is Not Verified";
            $response->write(json_encode($errorDetails));
    
            return $response->withHeader('Content-Type','application/json')
                            ->withStatus(200);
        }
        else if($result['message'] == EMAIL_NOT_VALID)
        {
            $errorDetails = array();
            $errorDetails['error'] = true;
            $errorDetails['message'] = "Enter Valid Email";
            $response->write(json_encode($errorDetails));
    
            return $response->withHeader('Content-Type','application/json')
                            ->withStatus(200);
        }
        else
        {
            $errorDetails = array();
            $errorDetails['error'] = true;
            $errorDetails['message'] = "Something Went Wrong";
            $response->write(json_encode($errorDetails));
    
            return $response->withHeader('Content-Type','application/json')
                            ->withStatus(200);
        }
    }
});

$app->post('/sendEmailVerfication',function(Request $request, Response $response)
{
    $result = array(); 
    if(!checkEmptyParameter(array('email'),$request,$response))
    {
        $db = new DbOperations();
        $requestParameter = $request->getParsedBody();
        $email = $requestParameter['email'];
        $result = $db->sendEmailVerificationAgain($email);
        if($result['message'] == VERIFICATION_EMAIL_SENT)
        {
            $errorDetails = array();
            $errorDetails['error'] = false;
            $errorDetails['message'] = "Email Has Been Sent";
            $response->write(json_encode($errorDetails));
    
            return $response->withHeader('Content-Type','application/json')
                            ->withStatus(201);
        }
        else if($result['message'] ==SEND_CODE)
        {
            $name = $result['name'];
            $email = $result ['email'];
            $code = $result['code'];
            $process = prepareVerificationMail($name,$email,$code);
            if($process)
            {
                $errorDetails = array();
                $errorDetails['error'] = false;
                $errorDetails['message'] = "An Email Verification Link Has Been Sent Your Email Address: ".$email;
                $response->write(json_encode($errorDetails));        
                return $response->withHeader('Content-Type','application/json')
                                ->withStatus(200);
            }
            $errorDetails = array();
            $errorDetails['error'] = true;
            $errorDetails['message'] = "Failed To Sent Verification Email";
            $response->write(json_encode($errorDetails));
            return $response->withHeader('Content-Type','application/json')
                            ->withStatus(200);
        }
        else if($result['message'] ==USER_NOT_FOUND)
        {
            $errorDetails = array();
            $errorDetails['error'] = true;
            $errorDetails['message'] = "No Account Registered With This Email";
            $response->write(json_encode($errorDetails));
            return $response->withHeader('Content-Type','application/json')
                            ->withStatus(200);
        }
        else if($result['message'] == EMAIL_NOT_VALID)
        {
            $errorDetails = array();
            $errorDetails['error'] = true;
            $errorDetails['message'] = "Enter Valid Email";
            $response->write(json_encode($errorDetails));
    
            return $response->withHeader('Content-Type','application/json')
                            ->withStatus(200);
        }
        else if($result['message'] ==EMAIL_ALREADY_VERIFIED)
        {
            $errorDetails = array();
            $errorDetails['error'] = true;
            $errorDetails['message'] = "Your Email Address Already Verified";
            $response->write(json_encode($errorDetails));
    
            return $response->withHeader('Content-Type','application/json')
                            ->withStatus(200);
        }
        else
        {
            $errorDetails = array();
            $errorDetails['error'] = true;
            $errorDetails['message'] = "Something Went Wrong";
            $response->write(json_encode($errorDetails));
            return $response->withHeader('Content-Type','application/json')
                            ->withStatus(200);
        }
    }
});

$app->get('/verifyEmail/{email}/{code}',function(Request  $request, Response $response, array $args)
{
    $email = $args['email']; 
    $email = decryptEmail($email);
    $code = $args['code'];
    $db = new DbOperations();
    $result = array();
    $result = $db->verfiyEmail($email,$code);

    if($result['message'] == EMAIL_VERIFIED)
    {
        $errorDetails = array();
        $errorDetails['error'] = false;
        $errorDetails['message'] = "Email Has Been Verified";
        $response->write(json_encode($errorDetails));

        return $response->withHeader('Content-Type','application/json')
                        ->withStatus(201);
    }
    else if($result['message'] ==EMAIL_NOT_VERIFIED)
    {
        $errorDetails = array();
        $errorDetails['error'] = true;
        $errorDetails['message'] = "Failed To Verify Email";
        $response->write(json_encode($errorDetails));

        return $response->withHeader('Content-Type','application/json')
                        ->withStatus(200);
    }
    else if($result['message'] ==INVAILID_USER)
    {
        $errorDetails = array();
        $errorDetails['error'] = true;
        $errorDetails['message'] = "INVALID USER";
        $response->write(json_encode($errorDetails));

        return $response->withHeader('Content-Type','application/json')
                        ->withStatus(200);
    }
    else if($result['message'] ==INVALID_VERFICATION_CODE)
    {
        $errorDetails = array();
        $errorDetails['error'] = true;
        $errorDetails['message'] = "INVALID VERIFCATION CODE";
        $response->write(json_encode($errorDetails));

        return $response->withHeader('Content-Type','application/json')
                        ->withStatus(200);
    }
    else if($result['message'] ==EMAIL_ALREADY_VERIFIED)
    {
        $errorDetails = array();
        $errorDetails['error'] = true;
        $errorDetails['message'] = "Your Email Is Already Verified";
        $response->write(json_encode($errorDetails));

        return $response->withHeader('Content-Type','application/json')
                        ->withStatus(200);
    }
    else
    {
        $errorDetails = array();
        $errorDetails['error'] = true;
        $errorDetails['message'] = "Something Went Wrong";
        $response->write(json_encode($errorDetails));

        return $response->withHeader('Content-Type','application/json')
                        ->withStatus(200);
    }

});

$app->post('/forgotPassword', function(Request $request, Response $response)
{
    $result = array();
    if(!checkEmptyParameter(array('email'),$request,$response))
    {
        $db = new DbOperations;
        $requestParameter = $request->getParsedBody();
        $email= $requestParameter['email'];
        $result = $db->forgotPassword($email);
        if($result['message'] == CODE_UPDATED)
        {
            $name = $result['name'];
            $email = $result['email'];
            $code = $result['code'];
            if(prepareForgotPasswordMail($name,$email,$code))
            {
                $errorDetails = array();
                $errorDetails['error'] = false;
                $errorDetails['message'] = "OTP has been sent to your email address";
                $response->write(json_encode($errorDetails));
                return $response->withHeader('Content-Type','application/json')
                                ->withStatus(200);
            }
            $errorDetails = array();
            $errorDetails['error'] = true;
            $errorDetails['message'] = "Failed To Send OTP Email";
            $response->write(json_encode($errorDetails));
            return $response->withHeader('Content-Type','application/json')
                            ->withStatus(200);
        }
        else if($result['message'] == EMAIL_NOT_VALID)
        {
            $errorDetails = array();
            $errorDetails['error'] = true;
            $errorDetails['message'] = "Enter Valid Email";
            $response->write(json_encode($errorDetails));
            return $response->withHeader('Content-Type','application/json')
                            ->withStatus(200);
        }       
        else if($result['message'] ==USER_NOT_FOUND)
        {
            $errorDetails = array();
            $errorDetails['error'] = true;
            $errorDetails['message'] = "Email Is Not Registered";
            $response->write(json_encode($errorDetails));
            return $response->withHeader('Content-Type','application/json')
                            ->withStatus(200);
        }
        else if($result['message'] ==EMAIL_NOT_VERIFIED)
        {
            $errorDetails = array();
            $errorDetails['error'] = true;
            $errorDetails['message'] = "Email Is Not Verified";
            $response->write(json_encode($errorDetails));
            return $response->withHeader('Content-Type','application/json')
                            ->withStatus(200);
        }
        else if($result['message'] ==CODE_UPDATE_FAILED)
        {
            $errorDetails = array();
            $errorDetails['error'] = true;
            $errorDetails['message'] = "Oops...! Some Error Occurred During Updating Code Into Database";
            $response->write(json_encode($errorDetails));
            return $response->withHeader('Content-Type','application/json')
                            ->withStatus(200);
        }
        else
        {
            $errorDetails = array();
            $errorDetails['error'] = true;
            $errorDetails['message'] = "Oops...! Something Went Wrong.";
            $response->write(json_encode($errorDetails));
            return $response->withHeader('Content-Type','application/json')
                            ->withStatus(200);
        }
    }
});

$app->post('/resetPassword', function(Request $request, Response $response)
{
    $result = array();
    if(!checkEmptyParameter(array('email','otp','newPassword'),$request,$response))
    {
        $db = new DbOperations;
        $requestParameter = $request->getParsedBody();
        $email = $requestParameter['email'];
        $otp = $requestParameter['otp'];
        $newPassword = $requestParameter['newPassword'];
        $result = $db->resetPassword($email,$otp,$newPassword);

        if($result['message'] == PASSWORD_RESET)
        {
            $name = $result['name'];
            $email = $result['email'];
            preparePasswordChangedMail($name,$email);
            $errorDetails = array();
            $errorDetails['error'] = false;
            $errorDetails['message'] = "Password Has Been Changed";
            $response->write(json_encode($errorDetails));
            return $response->withHeader('Content-Type','application/json')
                                ->withStatus(200);
        }
        else if($result['message'] == EMAIL_NOT_VALID)
        {
            $errorDetails = array();
            $errorDetails['error'] = true;
            $errorDetails['message'] = "Enter Valid Email";
            $response->write(json_encode($errorDetails));
            return $response->withHeader('Content-Type','application/json')
                            ->withStatus(200);
        }       
        else if($result['message'] ==USER_NOT_FOUND)
        {
            $errorDetails = array();
            $errorDetails['error'] = true;
            $errorDetails['message'] = "Email Is Not Registered";
            $response->write(json_encode($errorDetails));
            return $response->withHeader('Content-Type','application/json')
                            ->withStatus(200);
        }
        else if($result['message'] ==EMAIL_NOT_VERIFIED)
        {
            $errorDetails = array();
            $errorDetails['error'] = true;
            $errorDetails['message'] = "Email Is Not Verified";
            $response->write(json_encode($errorDetails));
            return $response->withHeader('Content-Type','application/json')
                            ->withStatus(200);
        }
        else if($result['message'] ==PASSWORD_RESET_FAILED)
        {
            $errorDetails = array();
            $errorDetails['error'] = true;
            $errorDetails['message'] = "Oops...! Some Error Occurred During Reseting Password";
            $response->write(json_encode($errorDetails));
            return $response->withHeader('Content-Type','application/json')
                            ->withStatus(200);
        }
        else if($result['message'] ==CODE_WRONG)
        {
            $errorDetails = array();
            $errorDetails['error'] = true;
            $errorDetails['message'] = "Invalid Otp";
            $response->write(json_encode($errorDetails));
            return $response->withHeader('Content-Type','application/json')
                            ->withStatus(200);
        }
        else
        {
            $errorDetails = array();
            $errorDetails['error'] = true;
            $errorDetails['message'] = "Oops...! Something Went Wrong.";
            $response->write(json_encode($errorDetails));
            return $response->withHeader('Content-Type','application/json')
                            ->withStatus(200);
        }


    }
});

$app->post('/updatePassword',function(Request $request, Response $response)
{
    $result = array();
    if(!checkEmptyParameter(array('password','email','newpassword'),$request,$response))
    {
        $requestParameter = $request->getParsedBody();
        $email = $requestParameter['email'];
        $password = $requestParameter['password'];
        $newPassword = $requestParameter['newpassword'];
        $db = new DbOperations;
        $result = array();
        $result = $db->updatePassword($email,$password,$newPassword);

        if($result['message'] == EMAIL_NOT_VALID)
        {
            $errorDetails = array();
            $errorDetails['error'] = true;
            $errorDetails['message'] = "Enter Valid Email";
            $response->write(json_encode($errorDetails));
            return $response->withHeader('Content-Type','application/json')
                            ->withStatus(200);
        }        else if($result['message'] ==USER_NOT_FOUND)
        {
            $errorDetails = array();
            $errorDetails['error'] = true;
            $errorDetails['message'] = "Email Is Not Registered";
            $response->write(json_encode($errorDetails));
            return $response->withHeader('Content-Type','application/json')
                            ->withStatus(200);
        }
        else if($result['message'] ==EMAIL_NOT_VERIFIED)
        {
            $errorDetails = array();
            $errorDetails['error'] = true;
            $errorDetails['message'] = "Email Is Not Verified";
            $response->write(json_encode($errorDetails));
            return $response->withHeader('Content-Type','application/json')
                            ->withStatus(200);
        }
        else if($result['message'] ==PASSWORD_WRONG)
        {
            $errorDetails = array();
            $errorDetails['error'] = true;
            $errorDetails['message'] = "Wrong Password";
            $response->write(json_encode($errorDetails));
            return $response->withHeader('Content-Type','application/json')
                            ->withStatus(200);
        }
        else if($result['message']==PASSWORD_CHANGED)
        {
            $name = $result['name'];
            $email = $result['email'];
            preparePasswordChangedMail($name,$email);
            $errorDetails = array();
            $errorDetails['error'] = false;
            $errorDetails['message'] = "Password Has Been Changed";
            $response->write(json_encode($errorDetails));
            return $response->withHeader('Content-Type','application/json')
                            ->withStatus(200);
        }
        else if($result['message'] ==PASSWORD_CHANGE_FAILED)
        {
            $errorDetails = array();
            $errorDetails['error'] = true;
            $errorDetails['message'] = "Oops..! Something Went Wrong, Password Not Changed";
            $response->write(json_encode($errorDetails));
            return $response->withHeader('Content-Type','application/json')
                            ->withStatus(200);
        }
        else
        {
            $errorDetails = array();
            $errorDetails['error'] = true;
            $errorDetails['message'] = "Oops...! Something Went Wrong.";
            $response->write(json_encode($errorDetails));
            return $response->withHeader('Content-Type','application/json')
                            ->withStatus(200);
        }
    }
});

function checkEmptyParameter($requiredParameter,$request,$response)
{
    $result = array();
    $error = false;
    $errorParam = '';
    $requestParameter = $request->getParsedBody();
    foreach($requiredParameter as $param)
    {
        if(!isset($requestParameter[$param]) || strlen($requestParameter[$param])<=1)
        {
            $error = true;
            $errorParam .= $param.', ';
        }
    }
    if($error)
    {
        $errorDetails = array();
        $errorDetails['error'] = true;
        $errorDetails['message'] = "Required Parameter ".substr($errorParam,0,-2)." is missing";
        $response->write(json_encode($errorDetails));

        return $response->withHeader('Content-Type','application/json')
                        ->withStatus(200);
    }
    return $error;
}

function prepareForgotPasswordMail($name,$email,$code)
{
    $websiteDomain = WEBSITE_DOMAIN;
    $websiteName = WEBSITE_NAME;
    $websiteEmail = WEBSITE_EMAIL;
    $websiteOwnerName = WEBSITE_OWNER_NAME;
    $ipAddress = "(".$_SERVER['REMOTE_ADDR'].")";
    $mailSubject = "Recover your $websiteName password";
    $mailBody= <<<HERE
    <body style="background-color: #f4f4f4; margin: 0 !important; padding: 0 !important;">
    <!-- HIDDEN PREHEADER TEXT -->
    <table border="0" cellpadding="0" cellspacing="0" width="100%">
        <!-- LOGO -->
        <tr>
            <td bgcolor="#FFA73B" align="center">
                <table border="0" cellpadding="0" cellspacing="0" width="100%" style="max-width: 600px;">
                    <tr>
                        <td align="center" valign="top" style="padding: 40px 10px 40px 10px;"> </td>
                    </tr>
                </table>
            </td>
        </tr>
        <tr>
            <td bgcolor="#FFA73B" align="center" style="padding: 0px 10px 0px 10px;">
                <table border="0" cellpadding="0" cellspacing="0" width="100%" style="max-width: 600px;">
                    <tr>
                        <td bgcolor="#ffffff" align="center" valign="top" style="padding: 40px 20px 20px 20px; border-radius: 4px 4px 0px 0px; color: #111111; font-family: 'Lato', Helvetica, Arial, sans-serif; font-size: 48px; font-weight: 400; letter-spacing: 4px; line-height: 48px;">
                            <h1 style="font-size: 48px; font-weight: 400; margin: 2;">Welcome!</h1><img src=" https://img.icons8.com/clouds/100/000000/handshake.png" width="125" height="120" style="display: block; border: 0px;" />
                        </td>
                    </tr>
                </table>
            </td>
        </tr>
        <tr>
            <td bgcolor="#f4f4f4" align="center" style="padding: 0px 10px 0px 10px;">
                <table border="0" cellpadding="0" cellspacing="0" width="100%" style="max-width: 600px;">
                    <tr>
                        <td bgcolor="#ffffff" align="left" style="padding: 20px 30px 40px 30px; color: #666666; font-family: 'Lato', Helvetica, Arial, sans-serif; font-size: 18px; font-weight: 400; line-height: 25px;">
                            <p style="margin: 0;">You told us you forgot your password, If you really did, Use this OTP (One Time Password) to choose a new one.</p>
                        </td>
                    </tr>
                    <tr>
                        <td bgcolor="#ffffff" align="left">
                            <table width="100%" border="0" cellspacing="0" cellpadding="0">
                                <tr>
                                    <td bgcolor="#ffffff" align="center" style="padding: 20px 30px 60px 30px;">
                                        <table border="0" cellspacing="0" cellpadding="0">
                                            <tr>
                                                <td align="center" style="border-radius: 3px;" bgcolor="#FFA73B"><b style="font-size: 20px; font-family: Helvetica, Arial, sans-serif; color: #ffffff; text-decoration: none; color: #ffffff; text-decoration: none; padding: 15px 25px; border-radius: 2px; border: 1px solid #FFA73B; display: inline-block;">$code</b></td>
                                            </tr>
                                        </table>
                                    </td>
                                </tr>
                            </table>
                        </td>
                    </tr> <!-- COPY -->
                    <tr>
                        <td bgcolor="#ffffff" align="left" style="padding: 0px 30px 0px 30px; color: #666666; font-family: 'Lato', Helvetica, Arial, sans-serif; font-size: 18px; font-weight: 400; line-height: 25px;">
                            <p style="margin: 0;">For security, this request was recieved from ip address $ipAddress. <br> If you didn't make this request, you can safely ignore this email :)</p>
                        </td>
                    </tr> <!-- COPY -->
                    <tr>
                        <td bgcolor="#ffffff" align="left" style="padding: 0px 30px 20px 30px; color: #666666; font-family: 'Lato', Helvetica, Arial, sans-serif; font-size: 15px; font-weight: 400; line-height: 25px;">
                           <br> <p style="margin: 0;">If you have any questions, just reply to this email—we're always happy to help out.</p>
                        </td>
                    </tr>
                    <tr>
                        <td bgcolor="#ffffff" align="left" style="padding: 0px 30px 40px 30px; border-radius: 0px 0px 4px 4px; color: #666666; font-family: 'Lato', Helvetica, Arial, sans-serif; font-size: 18px; font-weight: 400; line-height: 25px;">
                            <p style="margin: 0;">$websiteOwnerName,<br>$websiteName Team</p>
                        </td>
                    </tr>
                </table>
            </td>
        </tr>
        <tr>
            <td bgcolor="#f4f4f4" align="center" style="padding: 30px 10px 0px 10px;">
                <table border="0" cellpadding="0" cellspacing="0" width="100%" style="max-width: 600px;">
                    <tr>
                        <td bgcolor="#FFECD1" align="center" style="padding: 30px 30px 30px 30px; border-radius: 4px 4px 4px 4px; color: #666666; font-family: 'Lato', Helvetica, Arial, sans-serif; font-size: 18px; font-weight: 400; line-height: 25px;">
                            <h2 style="font-size: 20px; font-weight: 400; color: #111111; margin: 0;">Need more help?</h2>
                            <p style="margin: 0;"><a href="$websiteDomain" target="_blank" style="color: #FFA73B;">We&rsquo;re here to help you out</a></p>
                        </td>
                    </tr>
                </table>
            </td>
        </tr>
    </table>
    </body>
    HERE;;

    if(sendMail($name,$email,$mailSubject,$mailBody))
    {
        return true;
    }
    return false;
}

function prepareVerificationMail($name,$email,$code)
{
    $emailEncrypted = encryptEmail($email);
    $websiteDomain = WEBSITE_DOMAIN;
    $websiteName = WEBSITE_NAME;
    $websiteEmail = WEBSITE_EMAIL;
    $websiteOwnerName = WEBSITE_OWNER_NAME;
    $endPoint = "/verifyEmail/";
    $mailSubject="Verify Your Email Address For $websiteName";
    $mailBody= <<<HERE
    <body style="background-color: #f4f4f4; margin: 0 !important; padding: 0 !important;">
    <!-- HIDDEN PREHEADER TEXT -->
    <div style="display: none; font-size: 1px; color: #fefefe; line-height: 1px; font-family: 'Lato', Helvetica, Arial, sans-serif; max-height: 0px; max-width: 0px; opacity: 0; overflow: hidden;"> We're thrilled to have you here! Get ready to dive into your new account. </div>
    <table border="0" cellpadding="0" cellspacing="0" width="100%">
        <!-- LOGO -->
        <tr>
            <td bgcolor="#FFA73B" align="center">
                <table border="0" cellpadding="0" cellspacing="0" width="100%" style="max-width: 600px;">
                    <tr>
                        <td align="center" valign="top" style="padding: 40px 10px 40px 10px;"> </td>
                    </tr>
                </table>
            </td>
        </tr>
        <tr>
            <td bgcolor="#FFA73B" align="center" style="padding: 0px 10px 0px 10px;">
                <table border="0" cellpadding="0" cellspacing="0" width="100%" style="max-width: 600px;">
                    <tr>
                        <td bgcolor="#ffffff" align="center" valign="top" style="padding: 40px 20px 20px 20px; border-radius: 4px 4px 0px 0px; color: #111111; font-family: 'Lato', Helvetica, Arial, sans-serif; font-size: 48px; font-weight: 400; letter-spacing: 4px; line-height: 48px;">
                            <h1 style="font-size: 48px; font-weight: 400; margin: 2;">Welcome!</h1><img src=" https://img.icons8.com/clouds/100/000000/handshake.png" width="125" height="120" style="display: block; border: 0px;" />
                        </td>
                    </tr>
                </table>
            </td>
        </tr>
        <tr>
            <td bgcolor="#f4f4f4" align="center" style="padding: 0px 10px 0px 10px;">
                <table border="0" cellpadding="0" cellspacing="0" width="100%" style="max-width: 600px;">
                    <tr>
                        <td bgcolor="#ffffff" align="left" style="padding: 20px 30px 40px 30px; color: #666666; font-family: 'Lato', Helvetica, Arial, sans-serif; font-size: 18px; font-weight: 400; line-height: 25px;">
                            <p style="margin: 0;">We're excited to have you get started. First, you need to confirm your account. Just press the button below.</p>
                        </td>
                    </tr>
                    <tr>
                        <td bgcolor="#ffffff" align="left">
                            <table width="100%" border="0" cellspacing="0" cellpadding="0">
                                <tr>
                                    <td bgcolor="#ffffff" align="center" style="padding: 20px 30px 60px 30px;">
                                        <table border="0" cellspacing="0" cellpadding="0">
                                            <tr>
                                                <td align="center" style="border-radius: 3px;" bgcolor="#FFA73B"><a href="$websiteDomain$endPoint$emailEncrypted/$code" target="_blank" style="font-size: 20px; font-family: Helvetica, Arial, sans-serif; color: #ffffff; text-decoration: none; color: #ffffff; text-decoration: none; padding: 15px 25px; border-radius: 2px; border: 1px solid #FFA73B; display: inline-block;">Confirm Account</a></td>
                                            </tr>
                                        </table>
                                    </td>
                                </tr>
                            </table>
                        </td>
                    </tr> <!-- COPY -->
                    <tr>
                        <td bgcolor="#ffffff" align="left" style="padding: 0px 30px 0px 30px; color: #666666; font-family: 'Lato', Helvetica, Arial, sans-serif; font-size: 18px; font-weight: 400; line-height: 25px;">
                            <p style="margin: 0;">If that doesn't work, copy and paste the following link in your browser:</p>
                        </td>
                    </tr> <!-- COPY -->
                    <tr>
                        <td bgcolor="#ffffff" align="left" style="padding: 20px 30px 20px 30px; color: #666666; font-family: 'Lato', Helvetica, Arial, sans-serif; font-size: 18px; font-weight: 400; line-height: 25px;">
                            <p style="margin: 0;"><a href="#" target="_blank" style="color: #FFA73B;">$websiteDomain$endPoint$emailEncrypted/$code</a></p>
                        </td>
                    </tr>
                    <tr>
                        <td bgcolor="#ffffff" align="left" style="padding: 0px 30px 20px 30px; color: #666666; font-family: 'Lato', Helvetica, Arial, sans-serif; font-size: 18px; font-weight: 400; line-height: 25px;">
                            <p style="margin: 0;">If you have any questions, just reply to this email—we're always happy to help out.</p>
                        </td>
                    </tr>
                    <tr>
                        <td bgcolor="#ffffff" align="left" style="padding: 0px 30px 40px 30px; border-radius: 0px 0px 4px 4px; color: #666666; font-family: 'Lato', Helvetica, Arial, sans-serif; font-size: 18px; font-weight: 400; line-height: 25px;">
                            <p style="margin: 0;">$websiteOwnerName,<br>$websiteName Team</p>
                        </td>
                    </tr>
                </table>
            </td>
        </tr>
        <tr>
            <td bgcolor="#f4f4f4" align="center" style="padding: 30px 10px 0px 10px;">
                <table border="0" cellpadding="0" cellspacing="0" width="100%" style="max-width: 600px;">
                    <tr>
                        <td bgcolor="#FFECD1" align="center" style="padding: 30px 30px 30px 30px; border-radius: 4px 4px 4px 4px; color: #666666; font-family: 'Lato', Helvetica, Arial, sans-serif; font-size: 18px; font-weight: 400; line-height: 25px;">
                            <h2 style="font-size: 20px; font-weight: 400; color: #111111; margin: 0;">Need more help?</h2>
                            <p style="margin: 0;"><a href="$websiteDomain" target="_blank" style="color: #FFA73B;">We&rsquo;re here to help you out</a></p>
                        </td>
                    </tr>
                </table>
            </td>
        </tr>
    </table>
    </body>
    HERE;;
    if(sendMail($name,$email,$mailSubject,$mailBody))
    {
        return true;
    }
    return false;
}

function preparePasswordChangedMail($name,$email)
{
    $websiteDomain = WEBSITE_DOMAIN;
    $websiteName = WEBSITE_NAME;
    $websiteEmail = WEBSITE_EMAIL;
    $websiteOwnerName = WEBSITE_OWNER_NAME;
    $ipAddress = "(".$_SERVER['REMOTE_ADDR'].")";
    $currentDate = date('d');
    $currentMonth =  DateTime::createFromFormat('!m',date('m'));
    $currentMonth = $currentMonth->format('F');
    $currentYear = date('yy');
    $currentTime = date('h:m a');
    $mailSubject = "Your password has been changed.";
    $mailBody = <<<HERE
    <body style="background-color: #f4f4f4; margin: 0 !important; padding: 0 !important;">
    <!-- HIDDEN PREHEADER TEXT -->
    <table border="0" cellpadding="0" cellspacing="0" width="100%">
        <!-- LOGO -->
        <tr>
            <td bgcolor="#FFA73B" align="center">
                <table border="0" cellpadding="0" cellspacing="0" width="100%" style="max-width: 600px;">
                    <tr>
                        <td align="center" valign="top" style="padding: 40px 10px 40px 10px;"> </td>
                    </tr>
                </table>
            </td>
        </tr>
        <tr>
            <td bgcolor="#FFA73B" align="center" style="padding: 0px 10px 0px 10px;">
                <table border="0" cellpadding="0" cellspacing="0" width="100%" style="max-width: 600px;">
                    <tr>
                        <td bgcolor="#ffffff" align="center" valign="top" style="padding: 40px 20px 20px 20px; border-radius: 4px 4px 0px 0px; color: #111111; font-family: 'Lato', Helvetica, Arial, sans-serif; font-size: 48px; font-weight: 400; letter-spacing: 4px; line-height: 48px;">
                            <h1 style="font-size: 48px; font-weight: 400; margin: 2;">Welcome!</h1><img src=" https://img.icons8.com/clouds/100/000000/handshake.png" width="125" height="120" style="display: block; border: 0px;" />
                        </td>
                    </tr>
                </table>
            </td>
        </tr>
        <tr>
            <td bgcolor="#f4f4f4" align="center" style="padding: 0px 10px 0px 10px;">
                <table border="0" cellpadding="0" cellspacing="0" width="100%" style="max-width: 600px;">
                    <tr>
                        <td bgcolor="#ffffff" align="left" style="padding: 20px 30px 40px 30px; color: #666666; font-family: 'Lato', Helvetica, Arial, sans-serif; font-size: 18px; font-weight: 400; line-height: 25px;">
                            <p style="margin: 0;">This is a confirmation that you password was changed at $currentTime on $currentDate $currentMonth $currentYear</p>
                        </td>
                    </tr>
                    <tr>
                        <td bgcolor="#ffffff" align="left" style="padding: 0px 30px 0px 30px; color: #666666; font-family: 'Lato', Helvetica, Arial, sans-serif; font-size: 18px; font-weight: 400; line-height: 25px;">
                            <p style="margin: 0;">For security, The password was changed from the Ip Address $ipAddress. If this was you, then you can safely ignore this email :)</p>
                        </td>
                    </tr> <!-- COPY -->
                    <tr>
                        <td bgcolor="#ffffff" align="left" style="padding: 0px 30px 20px 30px; color: #666666; font-family: 'Lato', Helvetica, Arial, sans-serif; font-size: 15px; font-weight: 400; line-height: 25px;">
                           <br> <p style="margin: 0;">If you have any questions, just reply to this email—we're always happy to help out.</p>
                        </td>
                    </tr>
                    <tr>
                        <td bgcolor="#ffffff" align="left" style="padding: 0px 30px 40px 30px; border-radius: 0px 0px 4px 4px; color: #666666; font-family: 'Lato', Helvetica, Arial, sans-serif; font-size: 18px; font-weight: 400; line-height: 25px;">
                            <p style="margin: 0;">$websiteOwnerName,<br>$websiteName Team</p>
                        </td>
                    </tr>
                </table>
            </td>
        </tr>
        <tr>
            <td bgcolor="#f4f4f4" align="center" style="padding: 30px 10px 0px 10px;">
                <table border="0" cellpadding="0" cellspacing="0" width="100%" style="max-width: 600px;">
                    <tr>
                        <td bgcolor="#FFECD1" align="center" style="padding: 30px 30px 30px 30px; border-radius: 4px 4px 4px 4px; color: #666666; font-family: 'Lato', Helvetica, Arial, sans-serif; font-size: 18px; font-weight: 400; line-height: 25px;">
                            <h2 style="font-size: 20px; font-weight: 400; color: #111111; margin: 0;">Need more help?</h2>
                            <p style="margin: 0;"><a href="$websiteDomain" target="_blank" style="color: #FFA73B;">We&rsquo;re here to help you out</a></p>
                        </td>
                    </tr>
                </table>
            </td>
        </tr>
    </table>
    </body>
    HERE;;
    sendMail($name,$email,$mailSubject,$mailBody);
}

function sendMail($name,$email,$mailSubject,$mailBody)
{
    $websiteEmail = WEBSITE_EMAIL;
    $websiteEmailPassword = WEBSITE_EMAIL_PASSWORD;
    $websiteName = WEBSITE_NAME;
    $websiteOwnerName = WEBSITE_OWNER_NAME;
    $mail = new PHPMailer;
    $mail->SMTPDebug = 0;
    $mail->isSMTP();
    $mail->Host="smtp.gmail.com";
    $mail->Port=587;
    $mail->SMPTSecure="tls";
    $mail->SMTPAuth=true;
    $mail->Username = $websiteEmail;
    $mail->Password = $websiteEmailPassword;
    $mail->addAddress($email,$name);
    $mail->isHTML();
    $mail->Subject=$mailSubject;
    $mail->Body=$mailBody;
    $mail->From=$websiteEmail;
    $mail->FromName=$websiteName;
    if($mail->send())
    {
        return true;
    }
    return false;
}

function encryptEmail($data)
{
    $email = openssl_encrypt($data,"AES-128-ECB",null);
    $email = str_replace('/','socialcodia',$email);
    $email = str_replace('+','mufazmi',$email);
    return $email; 
}

function decryptEmail($data)
{
    $mufazmi = str_replace('mufazmi','+',$data);
    $email = str_replace('socialcodia','/',$mufazmi);
    $email = openssl_decrypt($email,"AES-128-ECB",null);
    return $email; 
}


$app->run();