<?php
class DbOperations
{
    private $con;

    function __construct()
    {
		require_once dirname(__FILE__) . '/DbCon.php';
		$db = new DbCon;
		$this->con =  $db->Connect();
    }

    function createUser($name,$email,$password)
    {
        $user = array();
        $result = array();
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
                    $user['message'] = USER_CREATED;
                    $user['code'] = $code;
                    $user['name'] = $name;
                    return $user;
                }
                else{
                    $result['message'] = FAILED_TO_CREATE_USER;
                    return $result;
                }
            }
            $result['message'] = EMAIL_EXIST;
            return $result;
        }
        $result['message'] = EMAIL_NOT_VALID;
        return $result;
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
                        $result['message'] = LOGIN_SUCCESSFULL;
                        return $result;
                    }
                    else
                    {
                        $result['message'] = UNVERIFIED_EMAIL;
                        return $result;
                    }
                }
                {
                    $result['message'] = PASSWORD_WRONG;
                    return $result;
                }
            }
            else
            {
                $result['message'] = USER_NOT_FOUND;
                return $result;
            }
        }
        $result['message'] = EMAIL_NOT_VALID;
        return $result;
    }

    function updatePassword($email,$password, $newPassword)
    {
        $result = array();
        if($this->isEmailValid($email))
        {
            if($this->isEmailExist($email))
            {
                if($this->isEmailVerified($email))
                {
                    $hashPass = $this->getPasswordByEmail($email);
                    if(password_verify($password,$hashPass))
                    {
                        $newHashPassword = password_hash($newPassword,PASSWORD_DEFAULT);
                        $query = "UPDATE users SET password=? WHERE email=?";
                        $stmt = $this->con->prepare($query);
                        $stmt->bind_param('ss',$newHashPassword,$email);
                        if($stmt->execute())
                        {
                            $name =$this->getPasswordByEmail($email);
                            $user = array();
                            $user['message'] = PASSWORD_CHANGED;
                            $user['email']  = $email;
                            $user['name'] = $name;
                            return $user;
                        }
                        $result['message'] = PASSWORD_CHANGE_FAILED;
                        return $result;
                    }
                    $result['message'] = PASSWORD_WRONG;
                    return $result;
                }
                $result['message'] = EMAIL_NOT_VERIFIED;
                return $result;
            }
            $result['message'] = USER_NOT_FOUND;
            return $result;
        }
        $result['message'] = EMAIL_NOT_VALID;
        return $result;
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
                        $result['message'] = CODE_UPDATED;
                        $result['code'] = $code;
                        $result['name'] = $name;
                        $result['email'] = $email;
                        return $result;
                    }
                    $result['message'] = CODE_UPDATE_FAILED;
                    return $result;
                }
                $result['message'] = EMAIL_NOT_VERIFIED;
                return $result;
            }
            $result['message'] = USER_NOT_FOUND;
            return $result;
        }
        $result['message'] = EMAIL_NOT_VALID;
        return $result;
    }

    function resetPassword($email,$code,$newPassword)
    {
        $result = array();
        if($this->isEmailValid($email))
        {
            if($this->isEmailExist($email))
            {
                if($this->isEmailVerified($email))
                {
                    $hashCode = $this->getCodeByEmail($email);
                    if(password_verify($code,$hashCode))
                    {
                        $hashPass = password_hash($newPassword,PASSWORD_DEFAULT);
                        $query = "UPDATE users SET password=? WHERE email=?";
                        $stmt = $this->con->prepare($query);
                        $stmt->bind_param('ss',$hashPass,$email);
                        if($stmt->execute())
                        {
                            $randCode = password_hash(rand(100000,999999),PASSWORD_DEFAULT);
                            $this->updateCode($email,$randCode);
                            $name = $this->getNameByEmail($email);
                            $result['message'] = PASSWORD_RESET;
                            $result['name'] = $name;
                            $result['email'] = $email;
                            return $result;
                        }
                        $result['message'] = PASSWORD_RESET_FAILED;
                        return $result;
                    } 
                    $result['message'] = CODE_WRONG;
                    return $result;
                }
                $result['message'] = EMAIL_NOT_VERIFIED;
                return $result;
            }
            $result['message'] = USER_NOT_FOUND;
            return $result;
        }
        $result['message'] = EMAIL_NOT_VALID;
        return $result;
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
                    $result['message'] = SEND_CODE;
                    $result['code'] = $code;
                    $result['email'] = $email;
                    $result['name'] = $name;
                    return $result;
                }
                $result['message'] = EMAIL_ALREADY_VERIFIED;
                return $result;
            }
            $result['message'] = USER_NOT_FOUND ;
            return $result;
        }
        $result['message'] = EMAIL_NOT_VALID;
        return $result;
    }

    function updateCode($email,$code)
    {
        $hashCode = password_hash($code,PASSWORD_DEFAULT);
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
                        $result['message'] = EMAIL_VERIFIED;
                        return $result;
                    }
                    $result['message'] = EMAIL_NOT_VERIFIED;
                    return $result;
                }
                $result['message'] = EMAIL_ALREADY_VERIFIED;
                return $result;
            }
            $result['message'] = INVALID_VERFICATION_CODE;
            return $result;
        }
        $result['message'] = INVAILID_USER;
        return $result;
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

    function deleteAllUser()
    {
        $query = "DELETE FROM users";
        $stmt = $this->con->prepare($query);
        if($stmt->execute())
        {
                $email = "asdf";
                echo "Database Has Been Cleared";
        }
        else
        {
            echo "Failed To Clear Database";
        }
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
}