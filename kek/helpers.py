from kek import constants, exceptions


def validate_supported_algorithm_version(algorithm_version: int) -> None:
    """Get algorithm version and raise exception if it is not supported."""
    if algorithm_version > constants.LATEST_KEK_VERSION:
        raise exceptions.DecryptionError(
            "Data is encrypted with unsupported version of algorithm ({})".format(
                algorithm_version
            )
        )
