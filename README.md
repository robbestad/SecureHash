SecureHash
==========

Secure hash class for PHP

Description:
==========
SecureHash creates a hash based on blowfish. 
This combination creates a password hash that is is virtually unfeasible
to crack without ludicrous amount of funds or hardware.
The password simply cannot be decrypted without knowing the password, salt and hash.

Usage:
==========
Include the class and create the hash like so:
$securePassword=new secureHash();
$hash=$securePassword->returnHash($user_submitted_password);

Verification is as simple as calling the class  
and passing the submitted password and the hash
if the hash matches, the function returns true
$verify=$securePassword->verifyHash($user_submitted_password,$hash);
