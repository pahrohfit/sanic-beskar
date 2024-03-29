from typing import Optional

from beanie import Indexed
from mongomock_motor import AsyncMongoMockClient  # type: ignore[import-untyped]
from pydantic import Field as pydantic_field
from sanic_beskar.orm import BeanieUserMixin, TortoiseUserMixin, UmongoUserMixin
from tortoise import fields as tortoise_field
from umongo import Document as UmongoDocument  # type: ignore[import-untyped]
from umongo import fields as umongo_field
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

    username: str = Indexed(unique=True)
    password: str = pydantic_field()
    email: str = Indexed(unique=True, required=False)
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


class ValidatingUser(BeanieUserMixin):
    """
    ValidatingUser for unit testing
    """

    class Meta:
        table = "ValidatingUser"

    username: str = Indexed(unique=True)
    password: str = pydantic_field()
    roles: str = pydantic_field(default="")
    is_active: bool = pydantic_field(default=True)

    @classmethod
    async def cls_create(cls, **kwargs):
        """``beanie`` document create caller"""
        return await cls(**kwargs).insert()

    def is_valid(self):
        """return `is_active` logic"""
        return self.is_active


class TotpUser(MixinUserBeanie):
    """
    TotpUser user class with TOTP additions for unit testing
    """

    class Meta:
        table = "TotpUser"

    totp: str = pydantic_field(max_length=255, default=None)
    totp_last_counter: Optional[int] = pydantic_field(default=None)

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
