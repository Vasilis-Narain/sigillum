"""sigillum — verify and open eIDAS/CAdES .p7m signed files."""
import warnings

# Italian TSL contains certificate attributes longer than RFC 5280's 64-char
# limit; cryptography emits a UserWarning when serializing them. Harmless here.
warnings.filterwarnings("ignore", message=r".*Attribute's length must.*")
warnings.filterwarnings("ignore", category=UserWarning, module=r"cryptography\..*")

__version__ = "0.2.1"
