from kek import constants, exceptions


def extract_and_validate_algorithm_version(message: bytes) -> int:
    """Get algorithm version and raise exception if it is not supported."""
    algorithm_version = message[0]
    if algorithm_version > constants.LATEST_KEK_VERSION:
        raise exceptions.DecryptionError(
            "Data is encrypted with unsupported version of algorithm ({})".format(
                algorithm_version
            )
        )
    return algorithm_version
