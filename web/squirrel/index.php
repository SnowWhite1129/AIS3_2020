<?php
    if ($file = @$_GET['get']) {
        $output = shell_exec(\"cat '$file'\");

	if ($output !== null) {
	    echo json_encode(['output' => $output]);
	}
    } 
?>
