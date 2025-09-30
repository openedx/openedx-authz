"""Pagination classes for the REST API."""

from rest_framework.pagination import PageNumberPagination


class AuthZAPIViewPagination(PageNumberPagination):
    """Pagination class for the AuthZ API views."""

    page_size = 10
    page_size_query_param = "page_size"
    max_page_size = 100
