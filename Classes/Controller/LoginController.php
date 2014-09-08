<?php
namespace EssentialDots\EdResetBePassword\Controller;
use TYPO3\CMS\Core\Database\DatabaseConnection;
use TYPO3\CMS\Core\Utility\ExtensionManagementUtility;
use TYPO3\CMS\Core\Utility\GeneralUtility;
use TYPO3\CMS\Core\Utility\MailUtility;

/***************************************************************
 * Copyright notice
 *
 * (c) 2014 Nikola Stojiljkovic, Essential Dots d.o.o. Belgrade
 * All rights reserved
 *
 * This script is part of the TYPO3 project. The TYPO3 project is
 * free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * The GNU General Public License can be found at
 * http://www.gnu.org/copyleft/gpl.html.
 * A copy is found in the textfile GPL.txt and important notices to the license
 * from the author is found in LICENSE.txt distributed with these scripts.
 *
 *
 * This script is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * This copyright notice MUST APPEAR in all copies of the script!
 ***************************************************************/

class LoginController extends \TYPO3\CMS\Backend\Controller\LoginController {

	const EXPIRY_TIME = 3600;

	/**
	 * @var \TYPO3\CMS\Lang\LanguageService
	 */
	protected $languageService;

	/**
	 * Initialize the login box. Will also react on a &L=OUT flag and exit.
	 *
	 * @return void
	 */
	public function init() {
		parent::init();

		$this->languageService = $GLOBALS['LANG'];
		$this->languageService->includeLLFile('EXT:ed_reset_be_password/Resources/Private/Language/locallang.xml');
	}

	/**
	 * Making interface selector:
	 *
	 * @return void
	 */
	public function makeInterfaceSelectorBox() {
		parent::makeInterfaceSelectorBox();

		$this->interfaceSelector .= '<div style="margin-top: 5px;"><a href="index.php?showForgotPasswordScreen=1">'.$this->languageService->getLL('forgotPassword', TRUE).'</a></div>';
	}

	/**
	 * Creates the login form
	 * This is drawn when NO login exists.
	 *
	 * @return string HTML output
	 */
	public function makeLoginForm() {
		if (GeneralUtility::_GP('showForgotPasswordScreen')) {
			if (!is_null(GeneralUtility::_GP('emailOrUsername'))) {
				$view = $this->getPasswordRecoveryView('initPasswordRecovery');

				$emailOrUsername = GeneralUtility::_GP('emailOrUsername');
				$users = $this->findUsersByEmailOrUsername($emailOrUsername);
				if (count($users)==1) {
					$user = $users[0];
					$view->assign('user', $user);

					$email = $user['email'] ?: $user['username'];
					$domain = substr(strrchr($email, "@"), 1);
						// for E-mail we need to use beter validation so we include only resolvable, fully-qualified domain names
					if (filter_var($email, FILTER_VALIDATE_EMAIL) === FALSE
						|| checkdnsrr($domain, 'MX') === FALSE
						|| getmxrr($domain) === FALSE
					) { // check failed
						$view->assign('errorUserFoundEmailNotValid', true);
					} else {
						// send password request email
						$salt = mcrypt_create_iv(PBKDF2_SALT_BYTE_SIZE, MCRYPT_DEV_URANDOM);
						$hash = md5($email . $salt);

						$this->getDatabase()->exec_UPDATEquery(
							'be_users',
							'uid = '.intval($user['uid']),
							array(
								'edresetbepassword_password_recovery_hash' => $hash,
								'edresetbepassword_password_recovery_date' => $GLOBALS['EXEC_TIME'],
							)
						);

						if ($this->getDatabase()->sql_affected_rows()==1) {
							$emailView = $this->getPasswordRecoveryView('initPasswordRecoveryMail');
							$emailView->assign('user', $user);
							$emailView->assign('email', $email);
							$emailView->assign('name', $user['realName'] ?: $user['username']);
							$emailView->assign('websiteName', $GLOBALS['TYPO3_CONF_VARS']['SYS']['sitename']);
							$emailView->assign('signature', $this->getSystemFromName() ?: $GLOBALS['TYPO3_CONF_VARS']['SYS']['sitename']);
							$emailView->assign('passwordRecoveryLink', GeneralUtility::getIndpEnv('TYPO3_REQUEST_SCRIPT').'?emailOrUsername='.htmlspecialchars($emailOrUsername).'&passwordRecoveryHash='.htmlspecialchars($hash));

							$mailer = GeneralUtility::makeInstance('TYPO3\\CMS\\Core\\Mail\\Mailer'); /* @var $mailer \TYPO3\CMS\Core\Mail\Mailer */
							$htmlBody = $emailView->render();
							$message = \TYPO3\CMS\Core\Mail\MailMessage::newInstance()
								->setSubject($this->languageService->getLL('initPasswordRecoveryMailSubject'))
								->setFrom($this->getSystemFrom())
								->setTo(array($email))
								->setBody(strip_tags($htmlBody))
								->addPart($htmlBody, 'text/html');

							if ($mailer->send($message)) {
								$view->assign('emailSent', true);
							} else {
								$view->assign('emailSent', false);
							}
						} else {
							$view->assign('emailSent', false);
						}
					}
				} elseif (count($users)) {
					$view->assign('errorMultipleUsers', true);
				} else {
					$view->assign('errorUserNotFound', true);
				}
			} else {
				$view = $this->getPasswordRecoveryView('requestPasswordRecovery');
			}

			$result = $view->render();
		} elseif (GeneralUtility::_GP('emailOrUsername') && GeneralUtility::_GP('passwordRecoveryHash')) {
			$emailOrUsername = GeneralUtility::_GP('emailOrUsername');
			$users = $this->findUsersByEmailOrUsername($emailOrUsername);
			if (
				count($users)==1
				&& $this->slowEquals($users[0]['edresetbepassword_password_recovery_hash'], GeneralUtility::_GP('passwordRecoveryHash'))
				&& $users[0]['edresetbepassword_password_recovery_date'] > 0
				&& $users[0]['edresetbepassword_password_recovery_date'] < $GLOBALS['EXEC_TIME']
				&& $users[0]['edresetbepassword_password_recovery_date'] > ($GLOBALS['EXEC_TIME'] - self::EXPIRY_TIME)
			) {
				if (GeneralUtility::_GP('newPassword') && GeneralUtility::_GP('newPasswordRepeat') && GeneralUtility::_GP('newPassword') == GeneralUtility::_GP('newPasswordRepeat')) {
					$password = GeneralUtility::_GP('newPassword');

					if (ExtensionManagementUtility::isLoaded('rsaauth') && $GLOBALS['TYPO3_CONF_VARS']['BE']['loginSecurityLevel'] === 'rsa') {
						$backend = \TYPO3\CMS\Rsaauth\Backend\BackendFactory::getBackend();
						if ($backend) {
							$storage = \TYPO3\CMS\Rsaauth\Storage\StorageFactory::getStorage(); /** @var $storage \TYPO3\CMS\Rsaauth\Storage\AbstractStorage */
							$key = $storage->get();
							// Decrypt the password
							if ($key != NULL && substr($password, 0, 4) === 'rsa:') {
								// Decode password and store it in loginData
								$decryptedPassword = $backend->decrypt($key, substr($password, 4));
								if ($decryptedPassword !== NULL) {
									$password = $decryptedPassword;
								}
								// Remove the key
								$storage->put(NULL);
							}
						}
					}

					if (ExtensionManagementUtility::isLoaded('saltedpasswords') && \TYPO3\CMS\Saltedpasswords\Utility\SaltedPasswordsUtility::isUsageEnabled('BE')) {
						/** @var $saltedpasswordsInstance \TYPO3\CMS\Saltedpasswords\Salt\SaltInterface */
						$saltedpasswordsInstance = \TYPO3\CMS\Saltedpasswords\Salt\SaltFactory::getSaltingInstance(NULL, 'BE');
						$password = $saltedpasswordsInstance->getHashedPassword($password);
						// If a given password is a md5 hash (usually default be_users without saltedpasswords activated),
						// result of getHashedPassword() is a salted hashed md5 hash.
						// We prefix those with 'M', saltedpasswords will then update this password
						// to a usual salted hash upon first login of the user.
						if ($this->isMd5Password($password)) {
							$password = 'M' . $password;
						}
					}

					$this->getDatabase()->exec_UPDATEquery(
						'be_users',
						'uid = '.intval($users[0]['uid']),
						array(
							'edresetbepassword_password_recovery_hash' => '',
							'edresetbepassword_password_recovery_date' => 0,
							'password' => $password,
						)
					);

					$view = $this->getPasswordRecoveryView('passwordResetSuccessful');
					$result = $view->render();
				} else {
					/** @var $pageRenderer \TYPO3\CMS\Core\Page\PageRenderer */
					$pageRenderer = $GLOBALS['TBE_TEMPLATE']->getPageRenderer();
					$pageRenderer->addJsInlineCode('ed_reset_be_password', 'window.TYPO3ResetBEPasswordSecurityLevel = "'.$GLOBALS['TYPO3_CONF_VARS']['BE']['loginSecurityLevel'].'";');
					$pageRenderer->addJsFile(ExtensionManagementUtility::extRelPath('ed_reset_be_password').'Resources/Public/JavaScript/reset.js');

					$view = $this->getPasswordRecoveryView('passwordReset');
					$view->assign('user', $users[0]);
					$view->assign('passwordsDoNotMatch', GeneralUtility::_GP('newPassword') || GeneralUtility::_GP('newPasswordRepeat'));
					$view->assign('emailOrUsername', $emailOrUsername);
					$view->assign('passwordRecoveryHash', GeneralUtility::_GP('passwordRecoveryHash'));
					$result = $view->render();
				}
			} else {
				$view = $this->getPasswordRecoveryView('passwordResetError');
				$result = $view->render();
			}
		} else {
			$result = parent::makeLoginForm();
		}

		return $result;
	}

	/**
	 * @param $action
	 * @return \TYPO3\CMS\Fluid\View\StandaloneView
	 */
	protected function getPasswordRecoveryView($action) {
		$view = \TYPO3\CMS\Core\Utility\GeneralUtility::makeInstance('TYPO3\\CMS\\Fluid\\View\\StandaloneView'); /* @var $view \TYPO3\CMS\Fluid\View\StandaloneView */

		$fluidTemplateFilePath = \TYPO3\CMS\Core\Utility\GeneralUtility::getFileAbsFileName('EXT:ed_reset_be_password/Resources/Private/Templates/'.ucfirst($action).'.html');
		$view->setTemplatePathAndFilename($fluidTemplateFilePath);

		return $view;
	}

	/**
	 * @param $emailOrUsername
	 * @return array
	 */
	protected function findUsersByEmailOrUsername($emailOrUsername) {
		$result = array();

		if (trim($emailOrUsername)) {
			$where = '(username='.$this->getDatabase()->fullQuoteStr($emailOrUsername, 'be_users').' OR email='.$this->getDatabase()->fullQuoteStr($emailOrUsername, 'be_users').')'.\TYPO3\CMS\Backend\Utility\BackendUtility::BEenableFields('be_users');
			$res = $this->getDatabase()->exec_SELECTquery('uid, username, email, realName, edresetbepassword_password_recovery_date, edresetbepassword_password_recovery_hash', 'be_users', $where);
			if ($res !== FALSE) {
				while ($row = $GLOBALS['TYPO3_DB']->sql_fetch_assoc($res)) {
					$result[] = $row;
				}
				$GLOBALS['TYPO3_DB']->sql_free_result($res);
			}
		}

		return $result;
	}

	/**
	 * @return DatabaseConnection
	 */
	protected function getDatabase() {
		return $GLOBALS['TYPO3_DB'];
	}

	/**
	 * Checks if a given password is a md5 hash, the default for be_user records before saltedpasswords.
	 *
	 * @param string $password The password to test
	 * @return boolean TRUE if password is md5
	 */
	protected function isMd5Password($password) {
		return (bool) preg_match('/[0-9abcdef]{32,32}/i', $password);
	}

	/**
	 * Compares two strings $a and $b in length-constant time.
	 *
	 * @param $a
	 * @param $b
	 * @return bool
	 */
	protected function slowEquals($a, $b) {
		$diff = strlen($a) ^ strlen($b);
		for ($i = 0; $i < strlen($a) && $i < strlen($b); $i++) {
			$diff |= ord($a[$i]) ^ ord($b[$i]);
		}
		return $diff === 0;
	}

	/**
	 * Gets a valid "from" for mail messages (email and name).
	 *
	 * Ready to be passed to $mail->setFrom()
	 *
	 * @return array key=Valid email address which can be used as sender, value=Valid name which can be used as a sender. NULL if no address is configured
	 */
	protected function getSystemFrom() {
		$address = $this->getSystemFromAddress();
		$name = $this->getSystemFromName();
		if (!$address) {
			return NULL;
		} elseif ($name) {
			return array($address => $name);
		} else {
			return array($address);
		}
	}

	/**
	 * Creates a valid "from" name for mail messages.
	 *
	 * As configured in Install Tool.
	 *
	 * @return string The name (unquoted, unformatted). NULL if none is set
	 */
	protected function getSystemFromName() {
		if ($GLOBALS['TYPO3_CONF_VARS']['MAIL']['defaultMailFromName']) {
			return $GLOBALS['TYPO3_CONF_VARS']['MAIL']['defaultMailFromName'];
		} else {
			return NULL;
		}
	}

	/**
	 * Creates a valid email address for the sender of mail messages.
	 *
	 * Uses a fallback chain:
	 * $TYPO3_CONF_VARS['MAIL']['defaultMailFromAddress'] ->
	 * no-reply@FirstDomainRecordFound ->
	 * no-reply@php_uname('n') ->
	 * no-reply@example.com
	 *
	 * Ready to be passed to $mail->setFrom()
	 *
	 * @return string An email address
	 */
	protected function getSystemFromAddress() {
		// default, first check the localconf setting
		$address = $GLOBALS['TYPO3_CONF_VARS']['MAIL']['defaultMailFromAddress'];
		if (!\TYPO3\CMS\Core\Utility\GeneralUtility::validEmail($address)) {
			// just get us a domain record we can use as the host
			$host = '';
			$domainRecord = $GLOBALS['TYPO3_DB']->exec_SELECTgetSingleRow('domainName', 'sys_domain', 'hidden = 0', '', 'pid ASC, sorting ASC');
			if (!empty($domainRecord['domainName'])) {
				$tempUrl = $domainRecord['domainName'];
				if (!\TYPO3\CMS\Core\Utility\GeneralUtility::isFirstPartOfStr($tempUrl, 'http')) {
					// shouldn't be the case anyways, but you never know
					// ... there're crazy people out there
					$tempUrl = 'http://' . $tempUrl;
				}
				$host = parse_url($tempUrl, PHP_URL_HOST);
			}
			$address = 'no-reply@' . $host;
			if (!\TYPO3\CMS\Core\Utility\GeneralUtility::validEmail($address)) {
				// still nothing, get host name from server
				$address = 'no-reply@' . php_uname('n');
				if (!\TYPO3\CMS\Core\Utility\GeneralUtility::validEmail($address)) {
					// if everything fails use a dummy address
					$address = 'no-reply@example.com';
				}
			}
		}
		return $address;
	}
}