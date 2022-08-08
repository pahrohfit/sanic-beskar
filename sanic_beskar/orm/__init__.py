# flake8: noqa
# I know this is ugly, will clean it up later

try:
    from .tortoise_user_mixins import TortoiseUserMixin
except (ModuleNotFoundError, ImportError) as e:
    # this is ok, this is optional
    pass

try:
    from .umongo_user_mixins import UmongoUserMixin
except (ModuleNotFoundError, ImportError) as e:
    # this is ok, this is optional
    pass
