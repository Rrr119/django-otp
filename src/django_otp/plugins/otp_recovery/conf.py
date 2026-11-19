import django.conf


class OTPRecoverySettings:
    """
    A simple settings wrapper exposing the recovery plugin's defaults.

    Any value can be overridden from the project's Django settings module.
    """

    defaults = {
        # Number of backup codes handed out by issue_backup_codes().
        'OTP_RECOVERY_BACKUP_CODE_COUNT': 10,
        # Length, in characters, of each generated backup code.
        'OTP_RECOVERY_BACKUP_CODE_LENGTH': 8,
        # Exponential back-off factor shared with the other OTP devices.
        'OTP_RECOVERY_THROTTLE_FACTOR': 1,
        # How long a trusted device (remembered browser/phone) stays valid.
        'OTP_RECOVERY_TRUSTED_DEVICE_TTL_DAYS': 30,
    }

    def __getattr__(self, name):
        if name in self.defaults:
            return getattr(django.conf.settings, name, self.defaults[name])
        return getattr(django.conf.settings, name)


settings = OTPRecoverySettings()
