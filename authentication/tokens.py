from django.contrib.auth.tokens import PasswordResetTokenGenerator
from six import text_type

from django.core.mail import send_mail


from gfg import settings

class TokenGenerator(PasswordResetTokenGenerator):
    def _make_hash_value(self, user, timestamp):
        return (
            text_type(user.pk) + text_type(timestamp)
        )

generate_token = TokenGenerator()

def send_forgot_password_mail(email, token):
    # token = str(uuid.uuid4())
    subject = "Reset your Django account password"
    message = f"Dear user,\n\nPlease use the below link to reset your Django account password.\n\nLink: http://127.0.0.1:8000/change_password/{token}"
    from_email = settings.EMAIL_HOST_USER
    to_list = [email]

    send_mail(subject, message, from_email, to_list, fail_silently=False)
    return True