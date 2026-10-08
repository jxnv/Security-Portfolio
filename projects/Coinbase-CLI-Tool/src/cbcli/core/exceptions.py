class CBCLIError(Exception):
    """Base application error."""


class ConfigurationError(CBCLIError):
    """Raised when configuration is invalid or missing."""


class ExchangeError(CBCLIError):
    """Raised when exchange communication fails."""


class ValidationError(CBCLIError):
    """Raised when business-rule validation fails."""