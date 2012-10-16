<?php
  /** 
  *  SVEN ANDERS ROBBESTAD (C) 2009 <anders@robbestad.com>.
  *  http://www.svenardo.com
  *  http://www.robbestad.com
  * 
  *  Description:
  *  SecureHash creates a hash based on blowfish. 
  *  If the passwords gets compromised after this is implemented, then you 
  *  have problems with packet sniffing, or your users select really bad passwords. 
  *  Always use SSL when transmitting and authenticating user passwords. 
  *
  *  USAGE:
  *  Instantiate class: 
  *	 $securePassword=new secureHash(); 
  *  
  *  To get hash:
  *  if($hashArray=$securePassword->returnHash("inputPassword")){ ... }
  *  If false, then password is too short. If true, then $hashArray is populated with hash and salt
  *  for instance: [0] => 141484a3fb3b6cbdba0.06563388 [1] => a6353b2bfb3c00bd2537f66ce5aa3cd2842be0848eff3ebbe252f86ab2991738  
  *  store [0] as salt, [1] as hash
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
    
    require("class.secureHash.php");

    $securePassword=new secureHash();
	
    $inputPassword='correct horse battery staple';
    $hash=$securePassword->returnHash($inputPassword);
    var_dump($hash);
    
    /*
    * Verification is as simple as calling the class  
    * and passing the submitted password and the hash
    * if the hash matches, the function returns true
    */
    
    $verifyPassword='correct horse battery staple';
    $verifyHash=$securePassword->verifyHash($verifyPassword,$hash);
    var_dump($verifyHash);
    
?>