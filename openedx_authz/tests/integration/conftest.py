"""Pytest configuration for openedx-authz tests."""

import pytest


@pytest.fixture(scope="session")
def django_db_setup():
    """Override django_db_setup to use existing database instead of creating a new one.

    This is necessary when running tests in an edx-platform environment where:
    1. The database already exists
    2. The database user doesn't have CREATE DATABASE permissions

    By providing this fixture, we tell pytest-django to skip database creation
    and use the existing database directly.
    """
    # Do nothing - use the existing database


@pytest.fixture(scope="session")
def django_db_modify_db_settings():
    """Configure database settings to use existing database for tests."""
