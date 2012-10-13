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
  * ¨
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

    //SAMPLE-DATA
	$salt="2916250796fc9095ce3.42893087";
	$password="9375b663b484e794bdd4b53d36951b52eace101cf0d87b1b37c65de9a6964e091f88d049ab38aaa551c513bf91836ca78a7b741435a76b764cec6f5559764681";

	$verifyHash=$securePassword->verifyHash("inputPassword",$password,$salt);
    var_dump($verifyHash);
    
?>