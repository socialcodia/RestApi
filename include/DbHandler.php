<?php

require_once dirname(__FILE__).'/JWT.php';
    $JWT = new JWT;


class DbHandler
{
    private $con;
    private $userId;

    function __construct()
    {
        require_once dirname(__FILE__) . '/DbCon.php';
        $db = new DbCon;
        $this->con =  $db->Connect();
    }

    //Getter Setter For User Id Only

    function setUserId($userId)
    {
        $this->userId = $userId;
    }

    function getUserId()
    {
        return $this->userId;
    }

    function createUser($name,$email,$password)
    {
        $user = array();
        if($this->isEmailValid($email))
        {
            if (!$this->isEmailExist($email))
            {
                $hashPass = password_hash($password,PASSWORD_DEFAULT);
                $code = password_hash($email.time(),PASSWORD_DEFAULT);
                $code = str_replace('/','socialcodia',$code);
                $query = "INSERT INTO users (name,email,password,code,status) VALUES (?,?,?,?,?)";
                $stmt = $this->con->prepare($query);
                $status =0;
                $stmt->bind_param('sssss',$name,$email,$hashPass,$code,$status);
                if($stmt->execute())
                {        
                    return USER_CREATED;
                }
                else{
                    return FAILED_TO_CREATE_USER;
                }
            }
            else
            {
                return EMAIL_EXIST;
            }
        }
        return EMAIL_NOT_VALID;
    }

    function login($email,$password)
    {
        if($this->isEmailValid($email))
        {
            if($this->isEmailExist($email))
            {
                $hashPass = $this->getPasswordByEmail($email);
                if(password_verify($password,$hashPass))
                {
                    if($this->isEmailVerified($email))
                    {
                        return LOGIN_SUCCESSFULL;
                    }
                    else
                    {
                        return UNVERIFIED_EMAIL;
                    }
                }
                {
                    return PASSWORD_WRONG;
                }
            }
            else
            {
                return USER_NOT_FOUND;
            }
        }
        return EMAIL_NOT_VALID;
    }

    function uploadProfileImage($email,$image)
    {
        if($image['name']!=null)
        {
            $targetDir = "../uploads/";
            // $targetFile = $targetDir.uniqid().'.'.pathinfo($image['name'],PATHINFO_EXTENSION);
            $targetFile = $targetDir.uniqid().'.'.pathinfo($image['name'], PATHINFO_EXTENSION);
            if(move_uploaded_file($image['tmp_name'],$targetFile))
            {
                $query = "UPDATE users set profile_image=? WHERE email=? ";
                $stmt = $this->con->prepare($query);
                $stmt->bind_param('ss',$targetFile,$email);
                if($stmt->execute())
                {
                    return IMAGE_UPLOADED;
                }
                return IMAGE_UPLOADE_FAILED;
            }
            return IMAGE_UPLOADE_FAILED;
        }
        return IMAGE_NOT_SELECTED;
    }

    function updatePassword($id,$password, $newPassword)
    {

        $hashPass = $this->getPasswordById($id);
        if(password_verify($password,$hashPass))
        {
            $newHashPassword = password_hash($newPassword,PASSWORD_DEFAULT);
            $query = "UPDATE users SET password=? WHERE id=?";
            $stmt = $this->con->prepare($query);
            $stmt->bind_param('ss',$newHashPassword,$id);
            if($stmt->execute())
            {
                return PASSWORD_CHANGED;
            }
            return PASSWORD_CHANGE_FAILED;
        }
        return PASSWORD_WRONG;  
    }

    function forgotPassword($email)
    {
        $result = array();
        if($this->isEmailValid($email))
        {
            if($this->isEmailExist($email))
            {
                if($this->isEmailVerified($email))
                {
                    $code = rand(100000,999999);
                    $name = $this->getNameByEmail($email);
                    if($this->updateCode($email,$code))
                    {
                        return CODE_UPDATED;
                    }
                    return CODE_UPDATE_FAILED;
                }
                return EMAIL_NOT_VERIFIED;
            }
            return USER_NOT_FOUND;
        }
        return EMAIL_NOT_VALID;
    }

    function resetPassword($email,$code,$newPassword)
    {
        if($this->isEmailValid($email))
        {
            if($this->isEmailExist($email))
            {
                if($this->isEmailVerified($email))
                {
                    $hashCode = decrypt($this->getCodeByEmail($email));
                    if($code==$hashCode)
                    {
                        $hashPass = password_hash($newPassword,PASSWORD_DEFAULT);
                        $query = "UPDATE users SET password=? WHERE email=?";
                        $stmt = $this->con->prepare($query);
                        $stmt->bind_param('ss',$hashPass,$email);
                        if($stmt->execute())
                        {
                            $randCode = password_hash(rand(100000,999999),PASSWORD_DEFAULT);
                            $this->updateCode($email,$randCode);
                            return PASSWORD_RESET;
                        }
                        return PASSWORD_RESET_FAILED;
                    } 
                    return CODE_WRONG;
                }
                return EMAIL_NOT_VERIFIED;
            }
            return USER_NOT_FOUND;
        }
        return EMAIL_NOT_VALID;
    }

    function sendEmailVerificationAgain($email)
    {
        $result = array();
        if($this->isEmailValid($email))
        {
            if($this->isEmailExist($email))
            {
                if(!$this->isEmailVerified($email))
                {
                    $code = $this->getCodeByEmail($email);
                    $name = $this->getNameByEmail($email);
                    $result['code'] = $code;
                    $result['email'] = $email;
                    $result['name'] = $name;
                    return SEND_CODE;
                }
                return EMAIL_ALREADY_VERIFIED;
            }
            return USER_NOT_FOUND;
        }
        return EMAIL_NOT_VALID;
    }

    function updateCode($email,$code)
    {
        $hashCode = encrypt($code);
        $query = "UPDATE users SET code=? WHERE email=?";
        $stmt = $this->con->prepare($query);
        $stmt->bind_param('ss',$hashCode,$email);
        if($stmt->execute())
        {
            return true;
        }      
        return false;
    }

    function verfiyEmail($email,$code)
    {
        $result = array();
        if($this->isEmailExist($email))
        {
            $dbCode = $this->getCodeByEmail($email);
            if($dbCode==$code)
            { 
                if(!$this->isEmailVerified($email))
                {
                    $resp = $this->setEmailIsVerfied($email);
                    if($resp)
                    {
                        return EMAIL_VERIFIED;
                    }
                    return EMAIL_NOT_VERIFIED;
                }
                return EMAIL_ALREADY_VERIFIED;
            }
            return INVALID_VERFICATION_CODE;
        }
        return INVAILID_USER;
    }

    function isEmailExist($email)
    {
        $query = "SELECT id FROM users WHERE email=?";
        $stmt = $this->con->prepare($query);
        $stmt->bind_param('s',$email);
        $stmt->execute();
        $stmt->store_result();
        return $stmt->num_rows>0 ;
    }

    function isEmailVerified($email)
    {
        $query = "SELECT status FROM users WHERE email=?";
        $stmt = $this->con->prepare($query);
        $stmt->bind_param('s',$email);
        $stmt->execute();
        $stmt->bind_result($status);
        $stmt->fetch();
        return $status;
    }

    function getPasswordByEmail($email)
    {
        $query = "SELECT password FROM users WHERE email=?";
        $stmt = $this->con->prepare($query);
        $stmt->bind_param('s',$email);
        $stmt->execute();
        $stmt->bind_result($password);
        $stmt->fetch();
        return $password;
    }

    function getPasswordById($id)
    {
        $query = "SELECT password FROM users WHERE id=?";
        $stmt = $this->con->prepare($query);
        $stmt->bind_param('s',$id);
        $stmt->execute();
        $stmt->bind_result($password);
        $stmt->fetch();
        return $password;
    }

    function getUsers($id)
    {
        $url = "SELECT id,name,email,password FROM users WHERE id !=? AND status != ?";
        $stmt = $this->con->prepare($url);
        $status = "0";
        $stmt->bind_param("ss",$id,$status);
        $stmt->execute();
        $stmt->bind_result($id,$name,$email,$password);
        $users = array();
        while ($stmt->fetch()) {
            $user = array();
            $user['id'] = $id;
            $user['name'] = $name;
            $user['email'] = $email;
            array_push($users, $user);
        }
        return $users;
    }

    function getUserById($id)
    {
        $query = "SELECT email FROM users WHERE id=?";
        $stmt = $this->con->prepare($query);
        $stmt->bind_param('s',$id);
        $stmt->execute();
        $stmt->store_result();
        if ($stmt->num_rows>0) 
        {
            return true;
        }
        return false;
    }

    function getEmailById($id)
    {
        $query = "SELECT email FROM users WHERE id=?";
        $stmt = $this->con->prepare($query);
        $stmt->bind_param('s',$id);
        $stmt->execute();
        $stmt->bind_result($email);
        $stmt->fetch();
        return $email;
    }

    function getNameByEmail($email)
    {
        $query = "SELECT name FROM users WHERE email=?";
        $stmt = $this->con->prepare($query);
        $stmt->bind_param('s',$email);
        $stmt->execute();
        $stmt->bind_result($name);
        $stmt->fetch();
        return $name;
    }

    function getCodeByEmail($email)
    {
        $query = "SELECT code FROM users WHERE email=?";
        $stmt = $this->con->prepare($query);
        $stmt->bind_param('s',$email);
        $stmt->execute();
        $stmt->bind_result($code);
        $stmt->fetch();
        return $code;
    }

    function setEmailIsVerfied($email)
    {
        $status = 1;
        $query = "UPDATE users SET status=? WHERE email =?";
        $stmt = $this->con->prepare($query);
        $stmt->bind_param('ss',$status,$email);
        if($stmt->execute())
        {
            return true;
        }
        return false;
    }

    function getUserByEmail($email)
    {
        $query = "SELECT id,name,email FROM users WHERE email=?";
        $stmt = $this->con->prepare($query);
        $stmt->bind_param('s',$email);
        $stmt->execute();
        $stmt->bind_result($id,$name,$email);
        $stmt->fetch();
        $user = array();
        $user['id'] = $id;
        $user['name'] = $name;
        $user['email'] = $email;
        return $user;
    }

    function isEmailValid($email)
    {
        if(filter_var($email,FILTER_VALIDATE_EMAIL))
        {
            return true;
        }
        return false;
    }

    function validateToken($token)
    {
        try 
        {
            $key = JWT_SECRET_KEY;
            $payload = JWT::decode($token,$key,['HS256']);
            $id = $payload->user_id;
            if ($this->getUserById($id)) 
            {
                $this->setUserId($payload->user_id);
                return JWT_TOKEN_FINE;
            }
            return JWT_USER_NOT_FOUND;
        } 
        catch (Exception $e) 
        {
            return JWT_TOKEN_ERROR;    
        }
    }

    function encrypt($data)
    {
        $email = openssl_encrypt($data,"AES-128-ECB",null);
        $email = str_replace('/','socialcodia',$email);
        $email = str_replace('+','mufazmi',$email);
        return $email; 
    }

    function decrypt($data)
    {
        $mufazmi = str_replace('mufazmi','+',$data);
        $email = str_replace('socialcodia','/',$mufazmi);
        $email = openssl_decrypt($email,"AES-128-ECB",null);
        return $email; 
    }


    
}