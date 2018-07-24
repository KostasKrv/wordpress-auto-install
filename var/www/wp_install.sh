clear

BASE_PATH="/var/www"

echo "============================================"
echo "WordPress Install Script"
echo "============================================"

## Get the domain name from argument ##
while getopts d:u:p: option
	do
		case "${option}"
	in
		d) DOMAIN=${OPTARG};;
		u) MYSQLUSER=${OPTARG};;
		p) MYSQLPASS=${OPTARG};;
	esac
done

DOMAIN_SAFE=$(echo $DOMAIN | sed 's/[\._-]//g')

NEW_UUID=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 4 | head -n 1)
dbname="${DOMAIN_SAFE}_db_$NEW_UUID"
dbuser="${DOMAIN_SAFE}_user_$NEW_UUID"
dbpass="${DOMAIN_SAFE}_pass_$NEW_UUID"
mysqlhost="localhost"
dbtable="wp_"

FOLDER="$BASE_PATH/$DOMAIN"

echo "============================================"
echo "Setting up the database."
echo "============================================"
#login to MySQL, add database, add user and grant permissions
dbsetup="CREATE DATABASE $dbname;GRANT ALL PRIVILEGES ON $dbname.* TO $dbuser@$mysqlhost IDENTIFIED BY '$dbpass';FLUSH PRIVILEGES;"
echo "DB query: $dbsetup"
mysql -u $MYSQLUSER --password=$MYSQLPASS -e "$dbsetup"
if [ $? != "0" ]; then
	echo "============================================"
	echo "[Error]: Database creation failed. Aborting."
	echo "============================================"
	exit 1
else
	echo "============================================"
	echo "Database created."
	echo "============================================"
fi

echo "DB query: $dbsetup"

echo "============================================"
echo "Installing WordPress for you."
echo "============================================"

#download wordpress
echo "Downloading..."
wget -P $BASE_PATH https://wordpress.org/latest.tar.gz

#unzip wordpress
echo "Unpacking..."
tar -C $BASE_PATH -zxf "$BASE_PATH/latest.tar.gz" 

#move 
echo "Moving..."
mv $BASE_PATH/wordpress $FOLDER

echo "Configuring..."
#create wp config
mv $FOLDER/wp-config-sample.php $FOLDER/wp-config.php

#set database details with perl find and replace
perl -pi -e "s'database_name_here'"$dbname"'g" $FOLDER/wp-config.php
perl -pi -e "s'username_here'"$dbuser"'g" $FOLDER/wp-config.php
perl -pi -e "s'password_here'"$dbpass"'g" $FOLDER/wp-config.php
perl -pi -e "s/\'wp_\'/\'$dbtable\'/g" $FOLDER/wp-config.php

#set WP salts
	perl -i -pe'
	  BEGIN {
	    @chars = ("a" .. "z", "A" .. "Z", 0 .. 9);
	    push @chars, split //, "!@#$%^&*()-_ []{}<>~\`+=,.;:/?|";
	    sub salt { join "", map $chars[ rand @chars ], 1 .. 64 }
	  }
	  s/put your unique phrase here/salt()/ge
	' $FOLDER/wp-config.php

echo "Hardening..."
cat > $FOLDER/.htaccess <<'EOL'
# Protect this file
<Files ~ "^\.ht">
Order allow,deny
Deny from all
</Files>
# Prevent directory listing
Options -Indexes
## BEGIN 6G Firewall from https://perishablepress.com/6g/
# 6G:[QUERY STRINGS]
<IfModule mod_rewrite.c>
	RewriteEngine On
	RewriteCond %{QUERY_STRING} (eval\() [NC,OR]
	RewriteCond %{QUERY_STRING} (127\.0\.0\.1) [NC,OR]
	RewriteCond %{QUERY_STRING} ([a-z0-9]{2000}) [NC,OR]
	RewriteCond %{QUERY_STRING} (javascript:)(.*)(;) [NC,OR]
	RewriteCond %{QUERY_STRING} (base64_encode)(.*)(\() [NC,OR]
	RewriteCond %{QUERY_STRING} (GLOBALS|REQUEST)(=|\[|%) [NC,OR]
	RewriteCond %{QUERY_STRING} (<|%3C)(.*)script(.*)(>|%3) [NC,OR]
	RewriteCond %{QUERY_STRING} (\\|\.\.\.|\.\./|~|`|<|>|\|) [NC,OR]
	RewriteCond %{QUERY_STRING} (boot\.ini|etc/passwd|self/environ) [NC,OR]
	RewriteCond %{QUERY_STRING} (thumbs?(_editor|open)?|tim(thumb)?)\.php [NC,OR]
	RewriteCond %{QUERY_STRING} (\'|\")(.*)(drop|insert|md5|select|union) [NC]
	RewriteRule .* - [F]
</IfModule>
# 6G:[REQUEST METHOD]
<IfModule mod_rewrite.c>
	RewriteCond %{REQUEST_METHOD} ^(connect|debug|delete|move|put|trace|track) [NC]
	RewriteRule .* - [F]
</IfModule>
# 6G:[REFERRERS]
<IfModule mod_rewrite.c>
	RewriteCond %{HTTP_REFERER} ([a-z0-9]{2000}) [NC,OR]
	RewriteCond %{HTTP_REFERER} (semalt.com|todaperfeita) [NC]
	RewriteRule .* - [F]
</IfModule>
# 6G:[REQUEST STRINGS]
<IfModule mod_alias.c>
	RedirectMatch 403 (?i)([a-z0-9]{2000})
	RedirectMatch 403 (?i)(https?|ftp|php):/
	RedirectMatch 403 (?i)(base64_encode)(.*)(\()
	RedirectMatch 403 (?i)(=\\\'|=\\%27|/\\\'/?)\.
	RedirectMatch 403 (?i)/(\$(\&)?|\*|\"|\.|,|&|&amp;?)/?$
	RedirectMatch 403 (?i)(\{0\}|\(/\(|\.\.\.|\+\+\+|\\\"\\\")
	RedirectMatch 403 (?i)(~|`|<|>|:|;|,|%|\\|\s|\{|\}|\[|\]|\|)
	RedirectMatch 403 (?i)/(=|\$&|_mm|cgi-|etc/passwd|muieblack)
	RedirectMatch 403 (?i)(&pws=0|_vti_|\(null\)|\{\$itemURL\}|echo(.*)kae|etc/passwd|eval\(|self/environ)
	RedirectMatch 403 (?i)\.(aspx?|bash|bak?|cfg|cgi|dll|exe|git|hg|ini|jsp|log|mdb|out|sql|svn|swp|tar|rar|rdf)$
	RedirectMatch 403 (?i)/(^$|(wp-)?config|mobiquo|phpinfo|shell|sqlpatch|thumb|thumb_editor|thumbopen|timthumb|webshell)\.php
</IfModule>
# 6G:[USER AGENTS]
<IfModule mod_setenvif.c>
	SetEnvIfNoCase User-Agent ([a-z0-9]{2000}) bad_bot
	SetEnvIfNoCase User-Agent (archive.org|binlar|casper|checkpriv|choppy|clshttp|cmsworld|diavol|dotbot|extract|feedfinder|flicky|g00g1e|harvest|heritrix|httrack|kmccrew|loader|miner|nikto|nutch|planetwork|postrank|purebot|pycurl|python|seekerspider|siclab|skygrid|sqlmap|sucker|turnit|vikspider|winhttp|xxxyy|youda|zmeu|zune) bad_bot
	<limit GET POST PUT>
		Order Allow,Deny
		Allow from All
		Deny from env=bad_bot
	</limit>
</IfModule>
# 6G:[BAD IPS]
<Limit GET HEAD OPTIONS POST PUT>
	Order Allow,Deny
	Allow from All
	# uncomment/edit/repeat next line to block IPs
	# Deny from 123.456.789
</Limit>
## END 6G Firewall
## BEGIN htauth basic authentication
# STAGING
Require all denied
AuthType Basic
AuthUserFile /etc/apache2/wp-login
AuthName "Please Authenticate"
Require valid-user
# LIVE - prevent wp-login brute force attacks from causing load
#<FilesMatch "^(wp-login|xmlrpc)\.php$">
#	AuthType Basic
#	AuthUserFile /etc/apache2/wp-login
#	AuthName "Please Authenticate"
#	Require valid-user
#</FilesMatch>
# Exclude the file upload and WP CRON scripts from authentication
#<FilesMatch "(async-upload\.php|wp-cron\.php)$">
#	Satisfy Any
#	Order allow,deny
#	Allow from all
#	Deny from none
#</FilesMatch>
## END htauth
## BEGIN WP file protection
<Files wp-config.php>
	order allow,deny
	deny from all
</Files>
# WP includes directories
<IfModule mod_rewrite.c>
	RewriteEngine On
	RewriteBase /
	RewriteRule ^wp-admin/includes/ - [F,L]
	RewriteRule !^wp-includes/ - [S=3]
	# note - comment out next line on multisite
	RewriteRule ^wp-includes/[^/]+\.php$ - [F,L]
	RewriteRule ^wp-includes/js/tinymce/langs/.+\.php - [F,L]
	RewriteRule ^wp-includes/theme-compat/ - [F,L]
</IfModule>
## END WP file protection
# Prevent author enumeration
RewriteCond %{REQUEST_URI} !^/wp-admin [NC]
RewriteCond %{QUERY_STRING} author=\d
RewriteRule ^ /? [L,R=301]
EOL


#Folders hardening
find $FOLDER/ -type d -exec chmod 755 {} \;
#Files hardening
find $FOLDER/ -type f -exec chmod 640 {} \;
chmod -v 644 $FOLDER/.htaccess
chmod -v 444 $FOLDER/wp-config.php
chown -R www-data:www-data $FOLDER

echo "Cleaning..."
#remove zip file
rm $BASE_PATH/latest.tar.gz


echo "Creating nginx file"
CONF_FILE="/etc/nginx/sites-available/$DOMAIN.conf"

cp /etc/nginx/sites-available/default-wp-auto-install.conf $CONF_FILE
perl -pi -e "s'LOCAL_PATH_HERE'"$FOLDER"'g" $CONF_FILE
perl -pi -e "s'DOMAIN_NAME_HERE'"$DOMAIN"'g" $CONF_FILE
#create symbolic link
ln -s $CONF_FILE /etc/nginx/sites-enabled/$DOMAIN.conf 

echo "Restarting Nginx"
service nginx reload
	
echo "========================="
echo "[Success]: Installation is complete."
echo "========================="
