<?php
  /** 
  *  SVEN ANDERS ROBBESTAD (C) 2009 <anders@robbestad.com>.  All rights reserved.
  *  http://www.svenardo.com
  *  http://www.robbestad.com
  * 
  *  Description:
  *  SecureHash creates a hash based on sha512 and salt based on uniqid. 
  *  This combination creates a password hash that is is virtually unfeasible
  *  to crack without ludicrous amount of funds or hardware.
  *  The password simply cannot be decrypted without knowing the password, salt and hash.
  *
  *  USAGE:
  *  Instantiate class: 
  *	 $securePassword=new secureHash(); 
  *  
  *  To get hash:
  *  if($hashArray=$securePassword->returnHash("inputPassword")){ ... }
  *  If false, then password is too short. If true, then $hashArray is populated with hash and salt
  *  for instance: 
  *  [0] => 141484a3fb3b6cbdba0.06563388 
  *  [1] => 6f301dd6d467469bee2a485bc9490c67176d310a27f4c60c1b3202f85caa93c1f6cea36b550e9689a3adcc048935b8d35da4bd18923ffafb71a8c44779ed6f2a  
  *  where [0] is salt, [1] is hash
  *
  *  To check the hash:
  *  if($verifyHash=$securePassword->verifyHash("inputPassword",$hash,$salt)) { ... }  
  *  submit submitted password plus previously stored hash and salt, returns true if match, false if not
  *   
  *  License:
  *  Redistribution and use in source and binary forms, with or without
  *  modification, are permitted provided that the following conditions are met:
  *
  *  1. Redistributions of source code must retain the above copyright
  *  notice, this list of conditions and the following disclaimer.
  *  2. Redistributions in binary form must reproduce the above copyright
  *  notice, this list of conditions and the following disclaimer in the
  *  documentation and/or other materials provided with the distribution.
  * 
  *  THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
  *  ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
  *  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
  *  ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
  *  FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
  *  DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
  *  OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
  *  HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
  *  LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
  *  OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
  *  SUCH DAMAGE.
  *
  */
             
class secureHash
    {
    public function __construct(){
        
    }
        
	private function createSalt(){
       # Create random hash based on the current time in microseconds
       # 'true' adds additional entropy
			 return $this->salt=uniqid(rand(), true);
	}

    private function createHash($input,$salt){
    	 # Create hash on supplied input and salt. Can be used to create new hash
    	 # or verify existing
    	 return $this->hash=hash("sha512",$input.$salt);  //function "hash" req. php v5.1.2 or better
    }
    
    public function returnHash($input)
    {
	 # Checks if submitted var is longer than 3 chars
     # this could be handled better with an error
     # exception
	 if(strlen($input)<3)
	 return false;

     # Will return an array with a hashed password and the salt it used
     return( array($this->CreateSalt(),$this->CreateHash($input,$this->salt)));
	}

    public function verifyHash($input,$hash,$salt)
    {
    $checkHash=$this->CreateHash($input,$salt);
    if($checkHash==$hash)
    return true;
    else
    return false; 
	}
}

?>