from django.contrib.auth.tokens import PasswordResetTokenGenerator
import six

class TokenGenerator(PasswordResetTokenGenerator):
    '''to generate a token for account activation'''
    def _make_hash_value(self, user,timestamp):
        '''to generate token'''
        return (six.text_type(user.pk) + six.text_type(timestamp) +
                six.text_type(user.is_active))
    


class PasswordTokenGenerator(PasswordResetTokenGenerator):
    '''to generate a token for reset password'''
    def _make_hash_value(self, user, timestamp):
        '''to generate token'''
        return (six.text_type(user.pk) + six.text_type(timestamp) +
        six.text_type(user.is_active))  
account_activation_token = TokenGenerator()
password_reset_token = PasswordTokenGenerator()