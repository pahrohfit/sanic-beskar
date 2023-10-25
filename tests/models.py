from typing import Optional
from sanic_beskar.orm import TortoiseUserMixin, BeanieUserMixin, UmongoUserMixin
from tortoise import fields as tortoise_field
from pydantic import Field as pydantic_field
from umongo import Document as UmongoDocument, fields as umongo_field  # type: ignore[import-untyped]

from mongomock_motor import AsyncMongoMockClient  # type: ignore[import-untyped]
from umongo.frameworks import MotorAsyncIOInstance  # type: ignore[import-untyped]


umongo_db = AsyncMongoMockClient()["umongo_test"]
umongo_instance = MotorAsyncIOInstance(umongo_db)
umongo_instance.set_db(umongo_db)


class MixinUserTortoise(TortoiseUserMixin):
    """
    MixinUserTortoise for unit tests
    """

    class Meta:
        table = "MixinUserTortoise"

    id: tortoise_field.IntField = tortoise_field.IntField(pk=True)
    username: tortoise_field.CharField = tortoise_field.CharField(unique=True, max_length=255)
    password: tortoise_field.CharField = tortoise_field.CharField(max_length=255)
    email: tortoise_field.CharField = tortoise_field.CharField(
        max_length=255, unique=True, required=False
    )
    roles: tortoise_field.CharField = tortoise_field.CharField(max_length=255, default="")

    @classmethod
    async def cls_create(cls, **kwargs):
        """``tortoise`` document create caller"""
        return await cls.create(**kwargs)


class MixinUserBeanie(BeanieUserMixin):
    """
    MixinUserBeanie for unit tests
    """

    class Meta:
        table = "BeanieMixinUser"

    username: str = pydantic_field(unique=True)
    password: str = pydantic_field()
    email: str = pydantic_field(unique=True, required=False)
    roles: str = pydantic_field(default="")

    @classmethod
    async def cls_create(cls, **kwargs):
        """``beanie`` document create caller"""
        return await cls(**kwargs).insert()


umongo_instance.register(UmongoUserMixin)


@umongo_instance.register
class MixinUserUmongo(UmongoDocument, UmongoUserMixin):
    """
    MixinUserUmongo for unit testing
    """

    id: int = umongo_field.IntField()
    username: str = umongo_field.StrField(unique=True)
    password: str = umongo_field.StrField()
    email: str = umongo_field.StrField(unique=True, required=False)
    roles: str = umongo_field.StrField(dump_default="")
    is_active: bool = umongo_field.BooleanField(load_default=True)

    @classmethod
    async def cls_create(cls, **kwargs):
        """``umongo`` document create caller"""
        _user = await cls(**kwargs).commit()
        return await cls.find_one({"id": _user.inserted_id})


class ValidatingUser(TortoiseUserMixin):
    """
    ValidatingUser for unit testing
    """

    class Meta:
        table = "ValidatingUser"

    id: tortoise_field.IntField = tortoise_field.IntField(pk=True)
    username: tortoise_field.CharField = tortoise_field.CharField(unique=True, max_length=255)
    password: tortoise_field.CharField = tortoise_field.CharField(max_length=255)
    email: tortoise_field.CharField = tortoise_field.CharField(
        max_length=255, unique=True, required=False
    )
    roles: tortoise_field.CharField = tortoise_field.CharField(max_length=255, default="")
    is_active = tortoise_field.BooleanField(default=True)

    def is_valid(self):
        """return `is_active` logic"""
        return self.is_active

    @classmethod
    async def cls_create(cls, **kwargs):
        """``tortoise`` document create caller"""
        return await cls.create(**kwargs)


class TotpUser(MixinUserTortoise):
    """
    TotpUser user class with TOTP additions for unit testing
    """

    class Meta:
        table = "TotpUser"

    totp = tortoise_field.CharField(max_length=255, default=None, null=True)
    totp_last_counter = tortoise_field.IntField(default=None, null=True)

    async def cache_verify(self, counter: int, seconds: Optional[int] = None):
        """
        simple totp validation counter flag

        Args:
            counter (int): counter value
            seconds (int, optional): Not used for unit tests. Defaults to None.
        """
        self.totp_last_counter = counter
        await self.save(update_fields=["totp_last_counter"])

    async def get_cache_verify(self):
        """simple totp cache verifier for unit testing"""
        return self.totp_last_counter
