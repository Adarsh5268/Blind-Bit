from allauth.socialaccount.adapter import DefaultSocialAccountAdapter
from django.contrib.auth.models import User


class BlindBitSocialAccountAdapter(DefaultSocialAccountAdapter):
    """Force explicit username confirmation during social signup."""

    @staticmethod
    def _social_email(sociallogin) -> str:
        email = (getattr(sociallogin.user, 'email', '') or '').strip()
        if email:
            return email

        account = getattr(sociallogin, 'account', None)
        extra_data = getattr(account, 'extra_data', {}) or {}
        email = (extra_data.get('email') or '').strip()
        if email:
            return email

        for email_address in getattr(sociallogin, 'email_addresses', []):
            email = (getattr(email_address, 'email', '') or '').strip()
            if email:
                return email
        return ''

    def pre_social_login(self, request, sociallogin):
        """
        If a local account already exists with the same email, link this
        social login to that user instead of forcing signup.
        """
        if getattr(request.user, 'is_authenticated', False):
            return
        if sociallogin.is_existing:
            return

        email = self._social_email(sociallogin)
        if not email:
            return

        matches = list(User.objects.filter(email__iexact=email).order_by('id')[:2])
        if len(matches) != 1:
            return
        sociallogin.connect(request, matches[0])

    def populate_user(self, request, sociallogin, data):
        user = super().populate_user(request, sociallogin, data)
        # Keep username empty so allauth shows the signup form and asks the user explicitly.
        user.username = ''
        return user
