from base64 import b32encode
from datetime import timedelta
from hashlib import sha256
from hmac import compare_digest
from os import urandom

from django.conf import settings
from django.db import models
from django.utils import timezone

from django_otp.models import Device, ThrottlingMixin, TimestampMixin

from .conf import settings as recovery_settings


class BackupCodeDevice(TimestampMixin, ThrottlingMixin, Device):
    """
    A :class:`~django_otp.models.Device` that authenticates with single-use
    recovery (backup) codes.

    Backup codes are intended for the "I lost my phone" case: each code is a
    random secret shown to the user once and stored only as a salted hash.
    A successful verification consumes the matching code, so it can never be
    used a second time.

    .. attribute:: code_set

        The RelatedManager for the device's
        :class:`BackupCode` objects.
    """

    def get_throttle_factor(self):
        return recovery_settings.OTP_RECOVERY_THROTTLE_FACTOR

    def issue_codes(self, count=None, length=None, commit=True):
        """
        Generate a fresh batch of one-time backup codes.

        Any codes already stored on this device are replaced, so issuing a
        new batch implicitly revokes the previous one.

        :param int count: Number of codes to generate (defaults to
            :setting:`OTP_RECOVERY_BACKUP_CODE_COUNT`).
        :param int length: Length of each code (defaults to
            :setting:`OTP_RECOVERY_BACKUP_CODE_LENGTH`).
        :param bool commit: Pass ``False`` to defer the database writes.
            In that case the plaintext codes are returned but not persisted;
            the device must already be saved when committing.
        :returns: The plaintext codes, in the order they were generated.
            These are the only copies the user will ever see.
        :rtype: list[str]
        """
        count = (
            recovery_settings.OTP_RECOVERY_BACKUP_CODE_COUNT if count is None else count
        )
        length = (
            recovery_settings.OTP_RECOVERY_BACKUP_CODE_LENGTH
            if length is None
            else length
        )

        plaintext_codes = [BackupCode.random_code(length) for _ in range(count)]

        if commit:
            self.code_set.all().delete()
            self.code_set.bulk_create(
                [BackupCode(device=self, code=code) for code in plaintext_codes]
            )

        return plaintext_codes

    def verify_token(self, token):
        verify_allowed, _ = self.verify_is_allowed()
        if verify_allowed:
            match = self._find_code(token)
            if match is not None:
                # Consume the code so it can never be reused.
                match.delete()
                self.throttle_reset(commit=False)
                self.set_last_used_timestamp(commit=False)
                self.save()
            else:
                self.throttle_increment()
        else:
            match = None

        return match is not None

    def revoke_code(self, token, commit=True):
        """
        Revoke a single backup code by its plaintext value.

        :param str token: The plaintext code to invalidate.
        :param bool commit: Pass ``False`` to defer the database write.
        :returns: The number of codes actually deleted (0 or 1).
        :rtype: int
        """
        match = self._find_code(token)
        if match is None:
            return 0
        deleted, _ = match.delete()
        if commit and self.pk is not None:
            self.save()
        return deleted

    def revoke_all_codes(self):
        """
        Revoke every backup code belonging to this device.

        :returns: The number of codes that were deleted.
        :rtype: int
        """
        deleted, _ = self.code_set.all().delete()
        return deleted

    def remaining_codes(self):
        """
        :returns: How many unused backup codes remain for this device.
        :rtype: int
        """
        return self.code_set.count()

    def _find_code(self, token):
        """
        Locate the stored code matching a presented plaintext value.

        Each stored code carries its own random salt, so the candidate hash is
        recomputed for every salt rather than resolved through a single
        lookup. Backup-code sets are deliberately small, so this stays cheap.
        """
        for candidate in self.code_set.all():
            if candidate.matches(token):
                return candidate
        return None


class BackupCode(models.Model):
    """
    A single one-time backup code for a :class:`BackupCodeDevice`.

    The plaintext code is never stored: only a per-code random salt and the
    resulting SHA-256 hash are persisted. The plaintext is returned once,
    when the codes are issued.

    .. attribute:: device

        *ForeignKey*: The owning :class:`BackupCodeDevice`.

    .. attribute:: salt

        *CharField*: Random per-code salt.

    .. attribute:: code_hash

        *CharField*: SHA-256 hash of the salted code.
    """

    device = models.ForeignKey(
        BackupCodeDevice, related_name='code_set', on_delete=models.CASCADE
    )
    salt = models.CharField(max_length=16, editable=False)
    code_hash = models.CharField(max_length=64, editable=False)

    def __init__(self, *args, code=None, **kwargs):
        super().__init__(*args, **kwargs)
        if code is not None:
            if not self.salt:
                self.salt = self.random_salt()
            self.code_hash = self.hash_with_salt(code, self.salt)

    @staticmethod
    def random_salt():
        """
        :returns: A fresh random per-code salt.
        :rtype: str
        """
        return b32encode(urandom(5)).decode('utf-8').lower().rstrip('=')

    @staticmethod
    def random_code(length=None):
        """
        Generate a new random, human-typable backup code.

        :param int length: Number of base32 characters (defaults to the
            configured length).
        :rtype: str
        """
        length = (
            recovery_settings.OTP_RECOVERY_BACKUP_CODE_LENGTH
            if length is None
            else length
        )
        # Base32 of five random bytes is eight characters; scale the random
        # input with the requested length and trim to keep the alphabet.
        num_bytes = max(5, (length * 5 + 7) // 8)
        code = b32encode(urandom(num_bytes)).decode('utf-8').lower().rstrip('=')
        return code[:length]

    @staticmethod
    def hash_with_salt(code, salt):
        """
        Hash a plaintext code together with its salt and the project secret.

        :rtype: str
        """
        material = '{salt}:{code}:{secret}'.format(
            salt=salt,
            code=code,
            secret=settings.SECRET_KEY,
        )
        return sha256(material.encode('utf-8')).hexdigest()

    def matches(self, code):
        """
        Constant-time comparison of a presented code against this row's
        salted hash.

        :rtype: bool
        """
        return compare_digest(self.code_hash, self.hash_with_salt(code, self.salt))


class TrustedDeviceManager(models.Manager):
    """Manager for :class:`TrustedDevice` with trust/revocation helpers."""

    def active(self, at=None):
        """
        Return trusted devices that have not been revoked and whose trust
        has not yet expired.
        """
        at = timezone.now() if at is None else at
        return self.filter(revoked_at__isnull=True, expires_at__gt=at)

    def trust_device(self, user, fingerprint, name='', ttl_days=None, request=None):
        """
        Record (or refresh) trust for a device fingerprint.

        Re-trusting an existing active fingerprint extends its expiry and
        returns the same row rather than creating duplicates.

        :param user: The user the device belongs to.
        :param str fingerprint: The device fingerprint (see
            :func:`django_otp.plugins.otp_recovery.lib.device_fingerprint`).
        :param str name: A human-readable label for the device.
        :param int ttl_days: Override the default trust duration.
        :param request: Optional request used to record the source IP.
        :rtype: TrustedDevice
        """
        ttl_days = (
            recovery_settings.OTP_RECOVERY_TRUSTED_DEVICE_TTL_DAYS
            if ttl_days is None
            else ttl_days
        )
        now = timezone.now()
        expires_at = now + timedelta(days=ttl_days)
        ip_address = None
        if request is not None:
            ip_address = request.META.get('REMOTE_ADDR')

        trusted = self.filter(
            user=user, fingerprint=fingerprint, revoked_at__isnull=True
        ).first()
        if trusted is None:
            trusted = self.create(
                user=user,
                fingerprint=fingerprint,
                name=name,
                expires_at=expires_at,
                last_seen_at=now,
                ip_address=ip_address,
            )
        else:
            trusted.name = name or trusted.name
            trusted.expires_at = expires_at
            trusted.last_seen_at = now
            trusted.ip_address = ip_address
            trusted.save()

        return trusted

    def is_trusted(self, user, fingerprint, at=None):
        """
        :returns: ``True`` if the fingerprint is a current, unrevoked,
            unexpired trusted device for the user.
        :rtype: bool
        """
        return self.active(at=at).filter(user=user, fingerprint=fingerprint).exists()

    def get_trusted(self, user, fingerprint, at=None):
        """
        :returns: The matching active :class:`TrustedDevice` or ``None``.
        """
        return self.active(at=at).filter(user=user, fingerprint=fingerprint).first()

    def revoke(self, user, fingerprint):
        """
        Revoke a single trusted device by fingerprint.

        :returns: The number of rows revoked (0 or 1).
        :rtype: int
        """
        now = timezone.now()
        updated = self.filter(
            user=user, fingerprint=fingerprint, revoked_at__isnull=True
        ).update(revoked_at=now)
        return updated

    def revoke_all_for_user(self, user):
        """
        Revoke every trusted device belonging to a user.

        :returns: The number of rows revoked.
        :rtype: int
        """
        now = timezone.now()
        updated = self.filter(user=user, revoked_at__isnull=True).update(revoked_at=now)
        return updated


class TrustedDevice(models.Model):
    """
    A remembered browser/phone that a user has chosen to trust.

    A trusted device is identified by a stable but non-reversible
    :attr:`fingerprint` derived from the request (see
    :func:`~django_otp.plugins.otp_recovery.lib.device_fingerprint`). Trust can
    expire or be explicitly revoked, which forces the user through full
    two-factor verification on the next login from that device.

    .. attribute:: user

        *ForeignKey*: The user that owns the trusted device.

    .. attribute:: fingerprint

        *CharField*: Hashed device fingerprint (unique per active device).

    .. attribute:: name

        *CharField*: A human-readable label, e.g. "Work iPhone".

    .. attribute:: ip_address

        *GenericIPAddressField*: The IP address recorded when trust was
        established (best effort, may be null).

    .. attribute:: trusted_at

        *DateTimeField*: When trust was first granted.

    .. attribute:: last_seen_at

        *DateTimeField*: When the device was most recently recognised.

    .. attribute:: expires_at

        *DateTimeField*: When the trust automatically expires.

    .. attribute:: revoked_at

        *DateTimeField*: When trust was explicitly revoked; ``None`` while
        the device remains trusted.
    """

    user = models.ForeignKey(
        getattr(settings, 'AUTH_USER_MODEL', 'auth.User'),
        related_name='trusteddevice_set',
        on_delete=models.CASCADE,
        help_text="The user that this trusted device belongs to.",
    )
    fingerprint = models.CharField(
        max_length=64,
        db_index=True,
        help_text="A hashed fingerprint identifying the browser/device.",
    )
    name = models.CharField(
        max_length=64, blank=True, help_text="A human-readable device label."
    )
    ip_address = models.GenericIPAddressField(
        null=True, blank=True, help_text="Source IP recorded when trusting."
    )
    trusted_at = models.DateTimeField(auto_now_add=True)
    last_seen_at = models.DateTimeField(null=True, blank=True)
    expires_at = models.DateTimeField(
        help_text="The moment after which the device is no longer trusted."
    )
    revoked_at = models.DateTimeField(
        null=True,
        blank=True,
        default=None,
        help_text="When trust was revoked; null while the device is trusted.",
    )

    objects = TrustedDeviceManager()

    class Meta:
        indexes = [
            models.Index(
                fields=['user', 'fingerprint'],
                name='otp_recovery_trust_user_fp_idx',
            ),
        ]

    def __str__(self):
        return "Trusted device {0} ({1})".format(
            self.name or self.fingerprint[:8], self.user_id
        )

    @property
    def is_active(self):
        """
        :rtype: bool
        """
        return (
            self.revoked_at is None
            and self.expires_at is not None
            and self.expires_at > timezone.now()
        )

    def touch(self, commit=True):
        """Record that the device was just recognised."""
        self.last_seen_at = timezone.now()
        if commit:
            self.save()

    def revoke(self, commit=True):
        """Revoke trust for this device."""
        self.revoked_at = timezone.now()
        if commit:
            self.save()
