class DriveError(Exception):
    """Base class for expected PSN Drive errors."""


class VaultNotInitialized(DriveError):
    pass


class InvalidVirtualPath(DriveError):
    pass


class FileNotFoundInVault(DriveError):
    pass


class IntegrityError(DriveError):
    pass


class QuotaExceeded(DriveError):
    pass


class RestoreConflict(DriveError):
    pass


class UploadConflict(DriveError):
    pass


class UploadSessionExpired(DriveError):
    pass


class UploadSessionNotFound(DriveError):
    pass


class AuthenticationError(DriveError):
    pass


class AuthorizationError(DriveError):
    pass


class PairingError(DriveError):
    pass


class RateLimitExceeded(DriveError):
    def __init__(self, message: str, retry_after: int = 1):
        super().__init__(message)
        self.retry_after = retry_after


class CertificatePinError(DriveError):
    pass


class HTTPClientError(DriveError):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status


class SyncAlreadyRunning(DriveError):
    pass


class ServiceAlreadyRunning(DriveError):
    pass
