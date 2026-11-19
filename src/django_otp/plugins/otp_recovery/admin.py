from django.contrib import admin
from django.contrib.admin.sites import AlreadyRegistered
from django.contrib.auth import get_user_model

from django_otp.admin import user_model_search_fields

from .models import BackupCode, BackupCodeDevice, TrustedDevice


class BackupCodeInline(admin.TabularInline):
    model = BackupCode
    extra = 0
    # The salt/hash are derived automatically; only stored hashes are ever
    # kept, so the inline never exposes or accepts plaintext secrets.
    exclude = ['salt', 'code_hash']
    can_delete = True


class BackupCodeDeviceAdmin(admin.ModelAdmin):
    """
    :class:`~django.contrib.admin.ModelAdmin` for
    :class:`~django_otp.plugins.otp_recovery.models.BackupCodeDevice`.
    """

    User = get_user_model()
    candidate_search_field = [User.USERNAME_FIELD, 'email']

    list_display = ['user', 'name', 'confirmed', 'created_at', 'last_used_at']
    list_filter = ['confirmed', 'created_at', 'last_used_at']
    search_fields, search_help_text = user_model_search_fields(candidate_search_field)

    raw_id_fields = ['user']
    readonly_fields = ['created_at', 'last_used_at']
    inlines = [BackupCodeInline]


class TrustedDeviceAdmin(admin.ModelAdmin):
    """
    :class:`~django.contrib.admin.ModelAdmin` for
    :class:`~django_otp.plugins.otp_recovery.models.TrustedDevice`.
    """

    User = get_user_model()
    candidate_search_field = [User.USERNAME_FIELD, 'email']

    list_display = [
        'user',
        'name',
        'trusted_at',
        'last_seen_at',
        'expires_at',
        'revoked_at',
    ]
    list_filter = ['trusted_at', 'expires_at', 'revoked_at']
    search_fields, search_help_text = user_model_search_fields(candidate_search_field)

    raw_id_fields = ['user']
    readonly_fields = [
        'fingerprint',
        'trusted_at',
        'last_seen_at',
        'expires_at',
        'revoked_at',
    ]
    actions = ['revoke_selected']

    @admin.action(description="Revoke trust for selected devices")
    def revoke_selected(self, request, queryset):
        from django.utils import timezone

        queryset.filter(revoked_at__isnull=True).update(revoked_at=timezone.now())


for model, model_admin in (
    (BackupCodeDevice, BackupCodeDeviceAdmin),
    (TrustedDevice, TrustedDeviceAdmin),
):
    try:
        admin.site.register(model, model_admin)
    except AlreadyRegistered:
        pass
