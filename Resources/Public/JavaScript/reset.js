
TYPO3ResetBEPassword = {
	form: null,
	passwordField: null,
	passwordRepeatField: null,
	checkingSecurityLevel: false,
	init: function() {
		var passResetBtn = Ext.get('t3-password-reset-btn');
		if (passResetBtn) {
			this.passwordField = Ext.get('t3-password-reset');
			this.passwordRepeatField = Ext.get('t3-password-reset-repeat');
			this.form = passResetBtn.parent('form');
			this.form.on('submit', function(e) {
				// @todo: check if passwords match

				if (!this.checkingSecurityLevel) {
					this.checkingSecurityLevel = true;
					this.onPasswordReset();
					e.preventDefault();
					return false;
				} else {
					this.checkingSecurityLevel = false;
				}
			}, this);
		}
	},
	onPasswordReset: function() {
		debugger;
		if (window.TYPO3ResetBEPasswordSecurityLevel === 'rsa') {
			Ext.Ajax.request({
				url: TYPO3.settings.ajaxUrls['BackendLogin::getRsaPublicKey'],
				params: {
					'skipSessionUpdate': 1
				},
				method: 'GET',
				success: function(response) {
					var publicKey = Ext.util.JSON.decode(response.responseText);
					if (publicKey.publicKeyModulus && publicKey.exponent) {
						var rsa = new RSAKey();
						rsa.setPublic(publicKey.publicKeyModulus, publicKey.exponent);
						if (this.passwordField.dom.value == this.passwordRepeatField.dom.value) {
							this.passwordRepeatField.dom.value = this.passwordField.dom.value = 'rsa:' + hex2b64(rsa.encrypt(this.passwordField.dom.value));
						} else {
							this.passwordField.dom.value = 'rsa:' + hex2b64(rsa.encrypt(this.passwordField.dom.value));
							this.passwordRepeatField.dom.value = 'rsa:' + hex2b64(rsa.encrypt(this.passwordRepeatField.dom.value));
						}
						this.form.dom.submit();
					}
				},
				scope: this
			});
		} else {
			this.form.submit();
		}
	}
};



Ext.onReady(TYPO3ResetBEPassword.init, TYPO3ResetBEPassword);