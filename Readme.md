# Wordpress auto installation
This script will install wordpress within a blink of an eye.

### Usage

./wp_install.sh -d test.com -u A_ROOT_USERNAME -p A_ROOT_PASSWORD

The installation script will:

  - Make a wordpress installation into folder /var/www/GIVEN_DOMAIN
  - Create a RANDOM database and user
  - Alter the wp-config.php file
  - Setup an htaccess file
  - Create an nginx configuration file
  - Restart the nginx

