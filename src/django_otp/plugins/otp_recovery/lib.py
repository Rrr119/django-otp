"""
Service-level helpers for backup codes and trusted devices.

These functions wrap the model APIs in a small, stable surface that views and
other code can call without reaching into the models directly.
"""

from hashlib import sha256

from django.conf import settings

from .models import BackupCodeDevice, TrustedDevice

# Request metadata that, together, identify a browser/device. These are kept
# deliberately stable across IP changes so a user moving between networks is
# not mistakenly treated as a new (untrusted) device.
FINGERPRINT_META_KEYS = (
    'HTTP_USER_AGENT',
    'HTTP_ACCEPT_LANGUAGE',
    # An optional, application-provided stable id (e.g. from a cookie).
    'HTTP_X_DEVICE_ID',
)


def device_fingerprint(request):
    """
    Derive a stable, non-reversible fingerprint for the caller's device.

    The fingerprint hashes a few durable request headers together with the
    project :setting:`SECRET_KEY`, so the same browser produces the same value
    on every visit while the raw identifying data is never stored. Changing
    any of the inputs (e.g. a new phone or browser) yields a different value.

    :param request: The current HTTP request.
    :rtype: str
    """
    parts = [request.META.get(key, '') or '' for key in FINGERPRINT_META_KEYS]
    material = '|'.join(parts) + '|' + settings.SECRET_KEY
    return sha256(material.encode('utf-8')).hexdigest()


#
# Backup codes
#


def get_or_create_backup_device(user, name='Backup Codes'):
    """
    Return the user's backup-code device, creating a confirmed one if needed.

    :rtype: BackupCodeDevice
    """
    device = BackupCodeDevice.objects.filter(user=user).first()
    if device is None:
        device = BackupCodeDevice.objects.create(user=user, name=name)
    return device


def issue_backup_codes(user, count=None, length=None, name='Backup Codes'):
    """
    Issue a new batch of one-time backup codes for a user.

    Any previously issued codes are replaced (and thus revoked). The returned
    plaintext codes must be shown to the user exactly once.

    :returns: A ``(device, plaintext_codes)`` tuple.
    :rtype: tuple[BackupCodeDevice, list[str]]
    """
    device = get_or_create_backup_device(user, name=name)
    plaintext_codes = device.issue_codes(count=count, length=length)
    return device, plaintext_codes


def verify_backup_code(user, token):
    """
    Verify and consume a backup code across the user's backup device.

    :returns: The :class:`BackupCodeDevice` that accepted the code, else
        ``None``. The code is consumed on success and cannot be reused.
    :rtype: BackupCodeDevice or None
    """
    device = BackupCodeDevice.objects.devices_for_user(user).first()
    if device is not None and device.verify_token(token):
        return device
    return None


def revoke_backup_code(user, token):
    """
    Revoke a single backup code by its plaintext value.

    :returns: The number of codes removed (0 if it did not exist or was
        already consumed).
    :rtype: int
    """
    device = BackupCodeDevice.objects.devices_for_user(user).first()
    if device is None:
        return 0
    return device.revoke_code(token)


def revoke_all_backup_codes(user):
    """
    Revoke every backup code belonging to a user.

    :rtype: int
    """
    device = BackupCodeDevice.objects.devices_for_user(user).first()
    if device is None:
        return 0
    return device.revoke_all_codes()


def remaining_backup_codes(user):
    """
    :returns: How many unused backup codes the user has.
    :rtype: int
    """
    device = BackupCodeDevice.objects.devices_for_user(user).first()
    return 0 if device is None else device.remaining_codes()


#
# Trusted devices
#


def trust_request_device(user, request, name='', ttl_days=None):
    """
    Mark the device making ``request`` as trusted for ``user``.

    :rtype: TrustedDevice
    """
    fingerprint = device_fingerprint(request)
    return TrustedDevice.objects.trust_device(
        user,
        fingerprint,
        name=name,
        ttl_days=ttl_days,
        request=request,
    )


def request_device_is_trusted(user, request, at=None):
    """
    :returns: Whether the device making ``request`` is currently trusted.
    :rtype: bool
    """
    fingerprint = device_fingerprint(request)
    return TrustedDevice.objects.is_trusted(user, fingerprint, at=at)


def get_trusted_request_device(user, request, at=None):
    """
    :returns: The active :class:`TrustedDevice` for the request, or ``None``.
    """
    fingerprint = device_fingerprint(request)
    return TrustedDevice.objects.get_trusted(user, fingerprint, at=at)


def revoke_request_device(user, request):
    """
    Revoke trust for the device making ``request``.

    :rtype: int
    """
    fingerprint = device_fingerprint(request)
    return TrustedDevice.objects.revoke(user, fingerprint)


def revoke_trusted_fingerprint(user, fingerprint):
    """
    Revoke a trusted device identified by its fingerprint string.

    :rtype: int
    """
    return TrustedDevice.objects.revoke(user, fingerprint)


def revoke_all_trusted_devices(user):
    """
    Revoke every trusted device belonging to a user.

    :rtype: int
    """
    return TrustedDevice.objects.revoke_all_for_user(user)
