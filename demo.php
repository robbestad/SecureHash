<?php
/**
 *  SVEN ANDERS ROBBESTAD (C) 2009 <anders@robbestad.com>.
 *  http://www.robestad.no
 *  http://www.robbestad.com
 *
 *  Description:
 *  secureHash creates a hash based on blowfish.
 *  If the passwords gets compromised after this is implemented, then you
 *  have problems with packet sniffing, or your users select really bad passwords.
 *  Always use SSL when transmitting and authenticating user passwords.

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

$hash="";
$inputPassword="";
$secureHash=new \Encryption\Blowfish\secureHash();
$letters=array("a","b","c","d","e","f","g","?","$","@","%","#","h","i","j","k","l","m",
	"n","o","p","q","r","s","t","u","w","x","y","z","(",")","!");
for($i=0;$i<16;$i++){
	$inputPassword.=$letters[rand(0,count($letters)-1)];
}
echo "Generated password: $inputPassword \n";

/*
* Create hash
*
* Create the hash by calling the class
* and pass the submitted password.
* This will generate a hash, which you can store
* for later verification
*/


try{
	$hash=$secureHash->returnHash($inputPassword);
	echo "The following hash was generated: $hash \n";

} catch (Exception $e) {
	echo 'Failed, function threw exception: ',  $e->getMessage(), "\n";
}

/*
* Verification
*
* Verification is as simple as calling the class
* and passing the submitted password and the hash
* If the hash matches, the function returns true
*/

$secureHash=new \Encryption\Blowfish\secureHash();
$verifyPassword=$inputPassword;

try{
	echo $secureHash->verifyHash($verifyPassword,$hash) ?  "Passed verification\n" :  "Verification failed\n";

} catch (Exception $e) {
	echo 'Caught exception: ',  $e->getMessage(), "\n";
}



?>
