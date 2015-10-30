import enum


class NotDefined(object):
    def __init__(self, value=None):
        self.value = value
        self.name = "NOT_DEFINED"


def make_display_name(str):
    return " ".join(
        s.capitalize() for s in str.lower().split("_")
    )


class BaseEnum(enum.Enum):
    @classmethod
    def members(self):
        return (
            (name, value) for name, value in self.__members__.items() if not name.startswith("_")
        )
    
    @classmethod
    def get_default(cls):
        if hasattr(cls, "NOT_DEFINED"):
            default = cls.NOT_DEFINED
        elif hasattr(cls, "NONE"):
            default = cls.NONE
        else:
            default = cls(min(value.value for name, value in cls.members()))
        return default

    @classmethod
    def get_value_from_vector(cls, key):
        key = key.lower()

        if key in {"x", "nd"} and hasattr(cls, "NOT_DEFINED"):
            return cls.NOT_DEFINED

        # Vectors is a way to override the keys given to a value. Used in CVSSv2
        if hasattr(cls, "_vectors") and key in cls._vectors.value:
            return getattr(cls, cls._vectors.value[key])

        for name, value in cls.members():
            if name == "NOT_DEFINED":
                continue

            if name[0].lower() == key:
                return value

        raise RuntimeError("Unknown vector key '{0}' for {1}".format(key, cls.__name__))

    @classmethod
    def choices(cls):
        return [(value.value, make_display_name(name)) for name, value in cls.members()]

    @classmethod
    def extend(cls, name, extra, doc=""):
        new_cls = enum.Enum(
            value=name,
            names=cls.to_mapping(extra),
            type=BaseEnum
        )
        new_cls._parent = cls
        new_cls.__doc__ = doc
        return new_cls

    @classmethod
    def to_mapping(cls, extra=None):
        returner = {
            name: value.value
            for name, value in cls.members()
        }

        if extra:
            returner.update(extra)

        return returner