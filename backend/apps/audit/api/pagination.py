from typing import Any

from django.utils import timezone
from django.utils.dateparse import parse_datetime
from rest_framework.exceptions import NotFound
from rest_framework.pagination import Cursor, CursorPagination

DEFAULT_PAGE_SIZE = 50
MAX_PAGE_SIZE = 100


class AuditCursorPagination(CursorPagination):
    """Newest first, with the id as a tie-breaker, so pages are stable under concurrent inserts.

    ``?cursor=`` is opaque; ``?page_size=`` is capped at 100. A malformed cursor is a 404,
    including a well-formed cursor whose position is not a timezone-aware timestamp (a client can
    decode and re-encode the cursor; an invalid position previously reached the database query and
    could end in a 500, AEMS-020).
    """

    ordering = ("-created_at", "-id")
    page_size = DEFAULT_PAGE_SIZE
    page_size_query_param = "page_size"
    max_page_size = MAX_PAGE_SIZE

    def decode_cursor(self, request: Any) -> Cursor | None:
        cursor = super().decode_cursor(request)
        if cursor is None or cursor.position is None:
            return cursor
        try:
            position = parse_datetime(str(cursor.position))
        except ValueError:
            position = None
        if position is None or timezone.is_naive(position):
            raise NotFound(self.invalid_cursor_message)
        return cursor
