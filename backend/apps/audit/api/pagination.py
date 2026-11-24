from rest_framework.pagination import CursorPagination

DEFAULT_PAGE_SIZE = 50
MAX_PAGE_SIZE = 100


class AuditCursorPagination(CursorPagination):
    """Newest first, with the id as a tie-breaker, so pages are stable under concurrent inserts.

    ``?cursor=`` is opaque; ``?page_size=`` is capped at 100. A malformed cursor is a 404.
    """

    ordering = ("-created_at", "-id")
    page_size = DEFAULT_PAGE_SIZE
    page_size_query_param = "page_size"
    max_page_size = MAX_PAGE_SIZE
