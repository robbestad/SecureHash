<?php
/**
 *  SVEN ANDERS ROBBESTAD (C) 2009 <anders@robbestad.com>.
 *  @license   http://creativecommons.org/publicdomain/zero/1.0/legalcode CC0 1.0 Universal
 *
 *  http://www.robbestad.com
 *
 *  Description:
 *  secureHash creates a hash based on blowfish.
 *  If the passwords gets compromised after this is implemented, then you
 *  have problems with packet sniffing, or your users select really bad passwords.
 *  Always use SSL when transmitting and authenticating user passwords.
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
