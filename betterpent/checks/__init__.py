from betterpent.checks.content import check_forms, check_mixed_content, detect_technology
from betterpent.checks.cookies import check_cookies
from betterpent.checks.cors import check_cors
from betterpent.checks.files import check_exposed_files, check_well_known
from betterpent.checks.headers import check_headers
from betterpent.checks.links import check_links
from betterpent.checks.performance import check_performance
from betterpent.checks.transport import check_https, check_tls

ALL_CHECKS = [
    detect_technology,
    check_https,
    check_tls,
    check_headers,
    check_cookies,
    check_forms,
    check_mixed_content,
    check_cors,
    check_well_known,
    check_exposed_files,
    check_links,
    check_performance,
]
