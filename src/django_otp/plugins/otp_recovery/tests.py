from datetime import timedelta

from django.test import RequestFactory
from django.test.utils import override_settings

from django_otp.test_utils import TestCase

from . import lib
from .lib import device_fingerprint
from .models import BackupCode, BackupCodeDevice, TrustedDevice


def make_request(ua='TestAgent/1.0', lang='en-US', device_id=None, ip=None):
    """Build a lightweight request carrying stable device metadata."""
    meta = {'HTTP_USER_AGENT': ua, 'HTTP_ACCEPT_LANGUAGE': lang}
    if device_id is not None:
        meta['HTTP_X_DEVICE_ID'] = device_id
    if ip is not None:
        meta['REMOTE_ADDR'] = ip
    return RequestFactory().get('/', **meta)


@override_settings(OTP_RECOVERY_THROTTLE_FACTOR=0)
class BackupCodeTestCase(TestCase):
    """Core behaviour of the one-time backup-code device."""

    def setUp(self):
        self.user = self.create_user('alice', 'password')

    def test_issue_codes_returns_plaintext_and_persists_only_hashes(self):
        device, codes = lib.issue_backup_codes(self.user, count=5)

        self.assertEqual(len(codes), 5)
        self.assertEqual(device.remaining_codes(), 5)
        # Plaintext secrets must never be persisted.
        for stored in device.code_set.all():
            self.assertNotIn(stored.code_hash, codes)
            self.assertTrue(stored.salt)
            self.assertTrue(stored.code_hash)

    def test_code_is_single_use(self):
        device, codes = lib.issue_backup_codes(self.user, count=3)
        code = codes[0]

        self.assertTrue(device.verify_token(code))
        self.assertEqual(device.remaining_codes(), 2)
        # Replaying the same consumed code must fail.
        self.assertFalse(device.verify_token(code))
        self.assertEqual(device.remaining_codes(), 2)

    def test_verify_backup_code_helper_consumes_code(self):
        _, codes = lib.issue_backup_codes(self.user, count=3)

        accepted = lib.verify_backup_code(self.user, codes[1])

        self.assertIsInstance(accepted, BackupCodeDevice)
        self.assertEqual(lib.remaining_backup_codes(self.user), 2)
        self.assertIsNone(lib.verify_backup_code(self.user, codes[1]))

    def test_unknown_code_is_rejected(self):
        lib.issue_backup_codes(self.user, count=3)

        self.assertIsNone(lib.verify_backup_code(self.user, 'not-a-real-code'))
        self.assertEqual(lib.remaining_backup_codes(self.user), 3)

    def test_reissue_revokes_previous_batch(self):
        _, first = lib.issue_backup_codes(self.user, count=3)
        _, second = lib.issue_backup_codes(self.user, count=3)

        self.assertEqual(lib.remaining_backup_codes(self.user), 3)
        # Every code from the old batch is now invalid.
        for code in first:
            self.assertIsNone(lib.verify_backup_code(self.user, code))
        self.assertTrue(lib.verify_backup_code(self.user, second[0]))

    def test_revoke_single_code(self):
        _, codes = lib.issue_backup_codes(self.user, count=3)

        removed = lib.revoke_backup_code(self.user, codes[0])

        self.assertEqual(removed, 1)
        self.assertIsNone(lib.verify_backup_code(self.user, codes[0]))
        self.assertEqual(lib.remaining_backup_codes(self.user), 2)

    def test_revoke_all_codes(self):
        lib.issue_backup_codes(self.user, count=3)

        removed = lib.revoke_all_backup_codes(self.user)

        self.assertEqual(removed, 3)
        self.assertEqual(lib.remaining_backup_codes(self.user), 0)

    def test_revoke_unknown_code_is_a_no_op(self):
        lib.issue_backup_codes(self.user, count=3)

        self.assertEqual(lib.revoke_backup_code(self.user, 'missing'), 0)
        self.assertEqual(lib.remaining_backup_codes(self.user), 3)

    def test_random_code_respects_length(self):
        code = BackupCode.random_code(12)

        self.assertEqual(len(code), 12)


class TrustedDeviceTestCase(TestCase):
    """Core behaviour of fingerprint-bound trusted devices."""

    def setUp(self):
        self.user = self.create_user('alice', 'password')

    def test_fingerprint_is_stable_and_distinguishes_devices(self):
        request_a = make_request(ua='Phone-A')
        request_b = make_request(ua='Phone-B')
        request_a_again = make_request(ua='Phone-A')

        self.assertEqual(
            device_fingerprint(request_a), device_fingerprint(request_a_again)
        )
        self.assertNotEqual(
            device_fingerprint(request_a), device_fingerprint(request_b)
        )

    def test_trust_then_recognise_same_device(self):
        request = make_request(device_id='device-123', ip='10.0.0.1')

        trusted = lib.trust_request_device(self.user, request, name='My phone')

        self.assertTrue(lib.request_device_is_trusted(self.user, request))
        self.assertEqual(trusted.ip_address, '10.0.0.1')
        # Fingerprints are hashed, the raw headers are not stored.
        self.assertNotIn('device-123', trusted.fingerprint)

    def test_retrust_extends_existing_record_instead_of_duplicating(self):
        request = make_request(device_id='device-123')

        first = lib.trust_request_device(self.user, request, name='Phone')
        second = lib.trust_request_device(self.user, request, name='Phone renamed')

        self.assertEqual(first.pk, second.pk)
        self.assertEqual(TrustedDevice.objects.filter(user=self.user).count(), 1)
        self.assertEqual(second.name, 'Phone renamed')

    def test_trust_is_scoped_per_user(self):
        other = self.create_user('bob', 'password')
        request = make_request(device_id='shared-phone')

        lib.trust_request_device(self.user, request)

        self.assertFalse(lib.request_device_is_trusted(other, request))

    def test_expired_device_is_not_trusted(self):
        request = make_request(device_id='old-phone')
        trusted = lib.trust_request_device(self.user, request, ttl_days=1)

        future = trusted.expires_at + timedelta(days=1)
        self.assertFalse(lib.request_device_is_trusted(self.user, request, at=future))

    def test_revoke_request_device(self):
        request = make_request(device_id='phone-x')
        lib.trust_request_device(self.user, request)

        revoked = lib.revoke_request_device(self.user, request)

        self.assertEqual(revoked, 1)
        self.assertFalse(lib.request_device_is_trusted(self.user, request))
        # Re-revoking is a harmless no-op.
        self.assertEqual(lib.revoke_request_device(self.user, request), 0)

    def test_revoke_by_fingerprint_and_revoke_all(self):
        request_one = make_request(device_id='phone-1')
        request_two = make_request(device_id='phone-2')
        lib.trust_request_device(self.user, request_one)
        lib.trust_request_device(self.user, request_two)

        fingerprint = device_fingerprint(request_one)
        self.assertEqual(lib.revoke_trusted_fingerprint(self.user, fingerprint), 1)
        self.assertFalse(lib.request_device_is_trusted(self.user, request_one))
        self.assertTrue(lib.request_device_is_trusted(self.user, request_two))

        self.assertEqual(lib.revoke_all_trusted_devices(self.user), 1)
        self.assertFalse(lib.request_device_is_trusted(self.user, request_two))

    def test_model_revoke_and_is_active(self):
        request = make_request(device_id='phone-model')
        trusted = lib.trust_request_device(self.user, request)

        self.assertTrue(trusted.is_active)
        trusted.revoke()
        trusted.refresh_from_db()
        self.assertFalse(trusted.is_active)
        self.assertIsNotNone(trusted.revoked_at)


class BackupCodeThrottlingTestCase(TestCase):
    """The backup-code device honours the shared throttling mixin."""

    def setUp(self):
        self.user = self.create_user('alice', 'password')
        self.device, self.codes = lib.issue_backup_codes(self.user, count=3)

    def test_failed_attempt_blocks_immediate_retry(self):
        # A wrong guess increments the throttle; the next attempt (even with a
        # valid code) is rejected until the back-off window passes.
        self.assertFalse(self.device.verify_token('wrong'))
        self.assertFalse(self.device.verify_token(self.codes[0]))
        self.assertEqual(self.device.throttling_failure_count, 1)

    def test_valid_code_after_backoff_succeeds(self):
        from freezegun import freeze_time

        self.device.verify_token('wrong')
        with freeze_time() as frozen_time:
            frozen_time.tick(delta=timedelta(seconds=1.1))
            self.assertTrue(self.device.verify_token(self.codes[0]))
        self.assertEqual(self.device.remaining_codes(), 2)


@override_settings(OTP_RECOVERY_THROTTLE_FACTOR=0)
class DeviceLossScenarioTestCase(TestCase):
    """
    End-to-end "lost device" scenarios the recovery feature is meant to
    cover. Throttling is disabled so each scenario can exercise several
    verification attempts in quick succession.
    """

    def setUp(self):
        self.user = self.create_user('alice', 'password')

    def test_lost_phone_recovery_with_single_use_backup_code(self):
        """
        Scenario 1: the user's primary phone (their TOTP device) is lost.
        They fall back to a backup code to get in, and that code is consumed
        so whoever later finds the phone cannot replay it.
        """
        _, codes = lib.issue_backup_codes(self.user, count=5)
        rescue_code = codes[0]

        # First recovery login works and burns the code.
        device = lib.verify_backup_code(self.user, rescue_code)
        self.assertIsNotNone(device)
        self.assertEqual(lib.remaining_backup_codes(self.user), 4)

        # An attacker (or the user again) cannot reuse the same code.
        self.assertIsNone(lib.verify_backup_code(self.user, rescue_code))
        # Other, unused backup codes still work.
        self.assertIsNotNone(lib.verify_backup_code(self.user, codes[1]))

    def test_new_phone_fingerprint_is_not_trusted_until_verified(self):
        """
        Scenario 2: the user replaces their phone. The new browser/device
        presents a different fingerprint, so it must not inherit the trust
        granted to the old device, even though the account is the same.
        """
        old_phone = make_request(device_id='old-phone', ua='Mobile/1.0')
        new_phone = make_request(device_id='new-phone', ua='Mobile/2.0')

        lib.trust_request_device(self.user, old_phone, name='Old phone')

        self.assertTrue(lib.request_device_is_trusted(self.user, old_phone))
        self.assertFalse(lib.request_device_is_trusted(self.user, new_phone))

        # After explicitly trusting the new phone it is recognised, while the
        # old one remains independently manageable.
        lib.trust_request_device(self.user, new_phone, name='New phone')
        self.assertTrue(lib.request_device_is_trusted(self.user, new_phone))
        self.assertTrue(lib.request_device_is_trusted(self.user, old_phone))

    def test_revocation_locks_out_the_lost_trusted_device(self):
        """
        Scenario 3: a trusted device is lost or sold without logging out.
        Revoking its trust immediately forces full two-factor verification on
        that device; revocation of backup codes blocks the parallel recovery
        path as well.
        """
        lost_phone = make_request(device_id='lost-phone', ua='Mobile/1.0')
        lib.trust_request_device(self.user, lost_phone, name='Lost phone')
        _, codes = lib.issue_backup_codes(self.user, count=3)
        self.assertTrue(lib.request_device_is_trusted(self.user, lost_phone))

        # The user (or an admin) revokes the lost device and all backup codes.
        lib.revoke_request_device(self.user, lost_phone)
        removed_codes = lib.revoke_all_backup_codes(self.user)

        self.assertFalse(lib.request_device_is_trusted(self.user, lost_phone))
        self.assertEqual(removed_codes, 3)
        for code in codes:
            self.assertIsNone(lib.verify_backup_code(self.user, code))
        self.assertEqual(lib.remaining_backup_codes(self.user), 0)
