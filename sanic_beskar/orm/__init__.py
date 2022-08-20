# flake8: noqa
# I know this is ugly, will clean it up later

try:
    from .tortoise_user_mixins import TortoiseUserMixin
    TortoiseUserMixin  # to shut up pyflakes
except (ModuleNotFoundError, ImportError) as e:
    # this is ok, this is optional
    pass

try:
    from .umongo_user_mixins import UmongoUserMixin
    UmongoUserMixin  # to shut up pyflakes
except (ModuleNotFoundError, ImportError) as e:
    # this is ok, this is optional
    pass

try:
    from .beanie_user_mixins import BeanieUserMixin
    BeanieUserMixin # to shut up pyflakes
except (ModuleNotFoundError, ImportError) as e:
    # this is ok, this is optional
    pass
