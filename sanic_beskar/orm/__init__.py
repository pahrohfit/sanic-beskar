# flake8: noqa
# I know this is ugly, will clean it up later

try: # pragma: no cover
    from .tortoise_user_mixins import TortoiseUserMixin
    TortoiseUserMixin  # to shut up pyflakes
except (ModuleNotFoundError, ImportError): # pragma: no cover
    # this is ok, this is optional
    pass

try: # pragma: no cover
    from .umongo_user_mixins import UmongoUserMixin
    UmongoUserMixin  # to shut up pyflakes
except (ModuleNotFoundError, ImportError): # pragma: no cover
    # this is ok, this is optional
    pass

try: # pragma: no cover
    from .beanie_user_mixins import BeanieUserMixin
    BeanieUserMixin # to shut up pyflakes
except (ModuleNotFoundError, ImportError): # pragma: no cover
    # this is ok, this is optional
    pass
