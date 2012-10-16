<?php
    /** 
    *  SVEN ANDERS ROBBESTAD (C) 2009 <anders@robbestad.com>.  All rights reserved.
    *  http://www.svenardo.com
    *  http://www.robbestad.com
    * 
    *  Description:
    *  SecureHash creates a hash based on blowfish. 
    *  This combination creates a password hash that is is virtually unfeasible
    *  to crack without ludicrous amount of funds or hardware.
    *  The password simply cannot be decrypted without knowing the password, salt and hash.
    *
    *  USAGE:
    *  see demo.php  
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

	    private $rounds;

        public function __construct($rounds=16){
            if(CRYPT_BLOWFISH != 1) {
                throw new Exception("Bcrypt is not supported. Please upgrade your installation.");
            }

            $this->rounds = $rounds;
        }

        
        /**
         * createSalt function.
         * Creates a random salt for the encryption
         * @access private
         * @return string
         */
        private function createSalt(){
        	//This config will run blowfish for 16 rounds
            $pre = '$2a$'.$this->rounds.'$';
            $end = '$';
            $salt = "";
			$bcryptBaseChars ='ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
            
			for($i=0; $i<21; $i++){
			    $salt .= $bcryptBaseChars[mt_rand(0,strlen($bcryptBaseChars)-1)];
			}
            
			$this->salt=$pre . $salt.'$';
			return $this->salt;
		}
        
        
        /**
         * createHash function.
         * Create hash on supplied input and salt. Can be used to create new hash or verify existing
         * @access private
         * @param mixed $input
         * @param mixed $salt
         * @return string
         */
        private function createHash($input,$salt){
            return $this->hash = crypt($input, $salt);
        }

        
        /**
         * returnHash function.
         * Will return a string with a hashed password. Will throw error if submitted
         * password is too short. 
         * @access public
         * @param mixed $input
         * @return string
         */
        public function returnHash($input)
        {
            if(strlen($input)<4)
                throw new Exception("Submitted password is too short.");

            return( $this->CreateHash($input,$this->CreateSalt()));
        }

        
        /**
         * verifyHash function.
         * Checks submitted password against hash. Will return true if it's a match
         * @access public
         * @param mixed $input
         * @param mixed $hash
         * @return bool
         */
        public function verifyHash($input,$hash)
        {
            $checkHash=$this->CreateHash($input,$hash);
            return $hash === $checkHash; 
        }
    }

?>
