<?php
class User {
    public $name;
    private $token;

    function __construct($name) {
        $this->name = $name;
        $this->token = NULL;
    }

    function canReadFlag() {
        return strcmp($flag, $this->token) == 0;
    }
}

	$another = new User('admin');
	$data = serialize($another);
	echo base64_encode(serialize($another));
?>

