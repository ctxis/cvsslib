import enum


def make_display_name(str):
    return " ".join(
        s.capitalize() for s in str.lower().split("_")
    )


class BaseEnum(enum.Enum):
    @classmethod
    def get_value_from_vector(cls, key):
        key = key.lower()

        for name, value in cls.__members__.items():
            if name[0].lower() == key:
                return value

        if key == "x" and hasattr(cls, "NOT_DEFINED"):
            return cls.NOT_DEFINED

        raise RuntimeError("Unknown vector key {0} for {1}".format(key, cls))

    @classmethod
    def choices(cls):
        return [(value.value, make_display_name(name)) for name, value in cls.__members__.items()]

    @classmethod
    def extend(cls, name, extra, doc=""):
        cls = enum.Enum(
            value=name,
            names=cls.to_mapping(extra),
            type=BaseEnum
        )
        cls.__doc__ = doc
        return cls

    @classmethod
    def to_mapping(cls, extra=None):
        returner = {
            name: value.value
            for name, value in cls.__members__.items()
        }

        if extra:
            returner.update(extra)

        return returner