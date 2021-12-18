find . -name LICENSE -exec sh -c '
    FILE=$(echo {} | cut -c 3- | sed -e "s/\/LICENSE//g" )
    NAME=$(echo $FILE | cut -c 8- )
	LIC=$(grep -m 1 . {} | sed -e "s/All rights reserved.//g" | sed -e "s/Copyright (c) [0-9]*//g" | sed "s/^[ \t]*//;s/[ \t]*$//" )
	echo $FILE, , $LIC, $NAME
' sh \;
