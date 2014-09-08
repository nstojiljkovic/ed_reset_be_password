TYPO3 BE account password reset functionality
===========

This is a simple extension which adds a "forgot password" functionality to the TYPO3 BE login screen.

There are no configuration options, just install and use.

Few notes:

* If $GLOBALS['TYPO3_CONF_VARS']['BE']['loginSecurityLevel'] is set to 'rsa', the new passwords will be transported encrypted via HTTP.
* If saltedpasswords is installed and configured, extension will automatically save salted passwords in the DB.
* The default expiry time for the change password links is 1 hour. It cannot be changed in this version.
* There are not minimal requirements for the new password strength.