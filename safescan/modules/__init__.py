"""Module index — re-exports every check so the scanner can iterate them."""

from safescan.modules.headers import check_security_headers
from safescan.modules.xss import check_reflected_xss
from safescan.modules.sqli import check_sqli
from safescan.modules.directory_listing import check_directory_listing
from safescan.modules.tech_detect import check_tech

ALL_CHECKS = [
    check_security_headers,
    check_reflected_xss,
    check_sqli,
    check_directory_listing,
    check_tech,
]
